#!/usr/bin/env python3
"""Rebuild the shard index and the level-0 compaction plan.

Carried forward from the 2.x branch during the migration trial. It has not been
reconciled against the release the manifest pins.
"""
import argparse
import json
import math
from pathlib import Path

DATA = Path("/app/data")
REPAIRED_MANIFEST_PATH = DATA / "manifest_repaired.json"
POLICY_PATH = DATA / "index_policy.json"
DEFAULT_BASE = DATA / "compacted_base.jsonl"
DEFAULT_OUTPUT_DIR = Path("/app/output")

SCHEMA_VERSION = "segment-index-v1"
MIB = 1048576


def load_base(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def fold_key(value: str) -> tuple:
    return (value.lower(), value.encode("utf-8"))


def shard_boundaries(rows: list[dict], shard_count: int) -> list[dict]:
    """Divide the base into shards holding an equal number of keys."""
    rows = sorted(rows, key=lambda row: fold_key(row["key"]))
    shards = []
    per_shard = math.ceil(len(rows) / shard_count) if rows else 0
    for shard in range(shard_count):
        window = rows[shard * per_shard: (shard + 1) * per_shard]
        if not window:
            continue
        shards.append(
            {
                "shard": len(shards),
                "first_key": window[0]["key"],
                "last_key": window[-1]["key"],
                "key_count": len(window),
                "value_bytes": sum(int(row["value_bytes"]) for row in window),
                "max_version_count": max(int(row["version_count"]) for row in window),
            }
        )
    return shards


def overlap_scores(segments: list[dict]) -> dict[str, int]:
    spans = [(fold_key(s["min_key"]), fold_key(s["max_key"]), s["id"]) for s in segments]
    scores = {seg_id: 0 for _, _, seg_id in spans}
    for i, (lo_a, hi_a, id_a) in enumerate(spans):
        for lo_b, hi_b, id_b in spans[i + 1:]:
            if lo_a <= hi_b and lo_b <= hi_a:
                scores[id_a] += 1
                scores[id_b] += 1
    return scores


def compaction_plan(segments: list[dict], budget_mib: int) -> dict:
    """Fill the budget in descending overlap-per-mebibyte order."""
    scores = overlap_scores(segments)
    items = [
        {
            "id": s["id"],
            "weight": max(1, int(int(s["bytes"]) // MIB)),
            "value": scores[s["id"]],
        }
        for s in segments
    ]
    items.sort(key=lambda item: (-item["value"] / item["weight"], item["id"]))

    chosen, remaining = [], budget_mib
    for item in items:
        if item["weight"] <= remaining:
            chosen.append(item)
            remaining -= item["weight"]
    chosen.sort(key=lambda item: item["id"])
    return {
        "segments": [item["id"] for item in chosen],
        "charged": {item["id"]: item["weight"] for item in chosen},
        "eliminated_overlap": sum(item["value"] for item in chosen),
        "charged_mib": sum(item["weight"] for item in chosen),
        "budget_mib": budget_mib,
        "candidate_count": len(items),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="rebuild the shard index")
    parser.add_argument("--input", default=str(DEFAULT_BASE))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    manifest = json.loads(REPAIRED_MANIFEST_PATH.read_text(encoding="utf-8"))
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    rows = load_base(Path(args.input))

    shards = shard_boundaries(rows, int(policy["shard_count"]))
    candidates = manifest["levels"]["0"] + manifest["levels"]["1"]
    plan = compaction_plan(candidates, int(policy["merge_budget_mib"]))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "shard_index.json").write_text(
        json.dumps(shards, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_dir / "compaction_plan.jsonl").open("w", encoding="utf-8") as handle:
        for seg_id in plan["segments"]:
            handle.write(
                json.dumps(
                    {"segment": seg_id, "charged_mib": plan["charged"][seg_id]},
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "engine_version": manifest["engine_version"],
        "base_key_count": len(rows),
        "base_value_bytes": sum(int(row["value_bytes"]) for row in rows),
        "discarded_segment_count": len(manifest.get("discarded_segments", [])),
        "level0_candidate_count": plan["candidate_count"],
        "shard_count": len(shards),
        "max_shard_value_bytes": max(s["value_bytes"] for s in shards),
        "min_shard_value_bytes": min(s["value_bytes"] for s in shards),
        "max_shard_key_count": max(s["key_count"] for s in shards),
        "deepest_version_count": max(s["max_version_count"] for s in shards),
        "plan_segment_count": len(plan["segments"]),
        "plan_eliminated_overlap": plan["eliminated_overlap"],
        "plan_charged_mib": plan["charged_mib"],
        "plan_budget_mib": plan["budget_mib"],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
