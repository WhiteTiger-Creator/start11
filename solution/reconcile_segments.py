#!/usr/bin/env python3
"""Reconcile the interrupted compaction into /app/data/compacted_base.jsonl.

The rules implemented here are the ones active in the engine version the
manifest pins (1.9), which is not the newest version the release notes carry.
"""
import hashlib
import json
from pathlib import Path

DATA = Path("/app/data")
MANIFEST_PATH = DATA / "manifest.json"
SEGMENT_DIR = DATA / "segments"
PENDING_DIR = DATA / "pending"
BASE_PATH = DATA / "compacted_base.jsonl"
REPAIRED_PATH = DATA / "manifest_repaired.json"

MAX_KEY_BYTES = 64  # v1.4


def read_segment(path: Path) -> tuple[list[dict], dict | None]:
    """Split a segment file into its body records and its trailer, if any."""
    body: list[dict] = []
    trailer: dict | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("trailer"):
            trailer = record
            continue
        body.append(record)
    return body, trailer


def body_checksum(body: list[dict]) -> str:
    """The trailer checksum covers the serialised body lines, in order."""
    digest = hashlib.sha256()
    for record in body:
        digest.update(json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()[:32]


def admit_pending(checkpoint_seq: int) -> tuple[list[dict], list[str]]:
    """v1.7: a pending segment is admitted whole or discarded whole.

    v1.3 truncated a torn segment at its last valid record; 1.7 replaced that
    with an all-or-nothing admission, so a body that disagrees with its trailer
    on either the record count or the checksum takes the whole segment out.
    v1.9 then admits what survives at level 0, numbered from the checkpoint in
    ascending segment id order.
    """
    admitted, discarded = [], []
    for path in sorted(PENDING_DIR.glob("*.jsonl")):
        body, trailer = read_segment(path)
        intact = (
            trailer is not None
            and trailer.get("records") == len(body)
            and trailer.get("checksum") == body_checksum(body)
        )
        if not intact:
            discarded.append(path.stem)
            continue
        # A discarded segment takes no rank, so the numbering closes over it
        # instead of leaving a hole at the checkpoint.
        admitted.append(
            {
                "id": path.stem,
                "level": 0,
                "seq": checkpoint_seq + 1 + len(admitted),
                "body": body,
            }
        )
    return admitted, discarded


def key_is_admissible(key: object) -> bool:
    """v1.4: empty, over-long and control-bearing keys never reach the base."""
    if not isinstance(key, str) or not key:
        return False
    if len(key.encode("utf-8")) > MAX_KEY_BYTES:
        return False
    return all(ord(ch) >= 0x20 for ch in key)


def build_base() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    checkpoint_seq = manifest["checkpoint_seq"]

    sources: list[dict] = []
    for level, entries in manifest["levels"].items():
        for entry in entries:
            body, _ = read_segment(SEGMENT_DIR / f"{entry['id']}.jsonl")
            sources.append(
                {"id": entry["id"], "level": int(level), "seq": entry["seq"], "body": body}
            )
    admitted, discarded = admit_pending(checkpoint_seq)
    sources.extend(admitted)

    # The repaired manifest carries the level-0 set the planner has to work
    # from: the linked segments plus whatever survived admission, each with the
    # metadata the unlinked segments never had written for them.
    level_zero = [dict(entry) for entry in manifest["levels"]["0"]]
    for source in admitted:
        keys = [r["k"] for r in source["body"]]
        level_zero.append(
            {
                "id": source["id"],
                "level": 0,
                "seq": source["seq"],
                "min_key": min(keys, key=lambda k: k.encode("utf-8")),
                "max_key": max(keys, key=lambda k: k.encode("utf-8")),
                "records": len(source["body"]),
                "bytes": sum(int(r.get("vb", 0)) for r in source["body"]),
            }
        )
    repaired = {
        "checkpoint_seq": checkpoint_seq,
        "discarded_segments": sorted(discarded),
        "engine_version": manifest["engine_version"],
        "levels": {
            "0": sorted(level_zero, key=lambda e: e["id"]),
            "1": manifest["levels"]["1"],
            "2": manifest["levels"]["2"],
        },
        "shard_count": manifest["shard_count"],
    }
    REPAIRED_PATH.write_text(
        json.dumps(repaired, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # v1.5: the winner is the record from the lowest level; within a level the
    # highest seq; on a further tie the lexicographically greatest segment id.
    # v2.1's global-highest-seq rule belongs to a version this engine is not on.
    winners: dict[str, dict] = {}
    versions: dict[str, int] = {}
    for source in sources:
        rank = (-source["level"], source["seq"], source["id"])
        for record in source["body"]:
            key = record.get("k")
            if not key_is_admissible(key):
                continue
            versions[key] = versions.get(key, 0) + 1
            held = winners.get(key)
            if held is None or rank > held["rank"]:
                winners[key] = {
                    "rank": rank,
                    "seq": record["seq"],
                    "level": source["level"],
                    "segment": source["id"],
                    "op": record.get("op", "put"),
                    "value_bytes": int(record.get("vb", 0)),
                }

    # v1.8: a winning tombstone suppresses the key outright. v2.0 keeps it as a
    # deleted marker, which is a later version's behaviour.
    rows = []
    for key in sorted(winners, key=lambda k: k.encode("utf-8")):  # v1.6 byte collation
        won = winners[key]
        if won["op"] == "del":
            continue
        rows.append(
            {
                "key": key,
                "level": won["level"],
                "seq": won["seq"],
                "segment": won["segment"],
                "value_bytes": won["value_bytes"],
                "version_count": versions[key],
            }
        )

    with BASE_PATH.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    return {"keys": len(rows), "sources": len(sources), "discarded": discarded}


if __name__ == "__main__":
    print(json.dumps(build_base()))
