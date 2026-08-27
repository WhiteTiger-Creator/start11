#!/usr/bin/env python3
"""Rebuild the shard index and the level-0 compaction plan for a 1.9 engine."""
import argparse
import json
from pathlib import Path

DATA = Path("/app/data")
REPAIRED_MANIFEST_PATH = DATA / "manifest_repaired.json"
POLICY_PATH = DATA / "index_policy.json"
DEFAULT_BASE = DATA / "compacted_base.jsonl"
DEFAULT_OUTPUT_DIR = Path("/app/output")

SCHEMA_VERSION = "segment-index-v1"
MIB = 1048576
RECORD_UNIT = 1000  # v1.9 charges records in whole thousands


def load_base(path: Path) -> list[dict]:
    """Read the reconciled base in the order it was written."""
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def byte_key(value: str) -> bytes:
    """v1.6 collation: raw UTF-8 bytes, not the case-folded form 2.2 moved to."""
    return value.encode("utf-8")


def shard_boundaries(rows: list[dict], shard_count: int) -> list[dict]:
    """Split the base into shards carrying an equal share of stored bytes.

    Shard k closes at the first key whose running total of stored bytes reaches
    k/shard_count of the whole, so the split follows the bytes rather than the
    key count, and a shard holding one enormous value stays a shard of one.
    """
    total = sum(int(row["value_bytes"]) for row in rows)
    shards: list[dict] = []
    running = 0
    index = 0
    start = 0
    for shard in range(1, shard_count + 1):
        target = -(-(shard * total) // shard_count)
        if shard == shard_count:
            index = len(rows)
        else:
            while index < len(rows) and running < target:
                running += int(rows[index]["value_bytes"])
                index += 1
        if index <= start:
            continue
        window = rows[start:index]
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
        start = index
    return shards


def overlap_scores(segments: list[dict]) -> dict[str, int]:
    """#IDX-4291: how many other level-0 segments a segment's key range meets.

    Ranges are compared under the deployed collation, and a shared endpoint
    counts as an overlap.
    """
    spans = [(byte_key(s["min_key"]), byte_key(s["max_key"]), s["id"]) for s in segments]
    scores = {seg_id: 0 for _, _, seg_id in spans}
    for i, (lo_a, hi_a, id_a) in enumerate(spans):
        for lo_b, hi_b, id_b in spans[i + 1:]:
            if lo_a <= hi_b and lo_b <= hi_a:
                scores[id_a] += 1
                scores[id_b] += 1
    return scores


def compaction_plan(segments: list[dict], budget_mib: int, budget_records: int) -> dict:
    """Choose the level-0 merge set that eliminates the most overlap.

    The selection is an exact optimum over the whole candidate set, not a greedy
    pass: 1.9 requires the planner to return the best achievable score, and a
    density-ordered walk regularly leaves a better packing on the table. The
    merge is bounded twice, in bytes and in records, and the two do not track
    each other, so the search runs over both at once -- the best selection under
    the byte budget alone overruns the record budget on this tree. Bytes are
    charged in whole mebibytes and records in whole thousands, both rounded up.
    Among selections of equal score the plan takes the fewest segments, then the
    smallest charged size, then the smallest charged records, then the
    lexicographically smallest id list.
    """
    scores = overlap_scores(segments)
    items = sorted(
        (
            {
                "id": s["id"],
                "weight": max(1, -(-int(s["bytes"]) // MIB)),
                "records": max(1, -(-int(s["records"]) // RECORD_UNIT)),
                "value": scores[s["id"]],
            }
            for s in segments
        ),
        key=lambda item: item["id"],
    )
    record_cap = budget_records // RECORD_UNIT

    # Forward search over the loads both budgets allow. A state is the pair of
    # charges reached; each keeps the best ordering key that reaches it, so the
    # tie-break chain never has to be applied after the fact.
    best: dict[tuple[int, int], tuple] = {(0, 0): (0, 0, 0, 0, ())}
    for item in items:
        nxt = dict(best)
        for (mib, recs), state in best.items():
            load_mib, load_recs = mib + item["weight"], recs + item["records"]
            if load_mib > budget_mib or load_recs > record_cap:
                continue
            candidate = (
                state[0] + item["value"],
                state[1] - 1,
                -load_mib,
                -load_recs,
                state[4] + (item["id"],),
            )
            held = nxt.get((load_mib, load_recs))
            if held is None or candidate[:4] > held[:4] or (
                candidate[:4] == held[:4] and candidate[4] < held[4]
            ):
                nxt[(load_mib, load_recs)] = candidate
        best = nxt

    winner = max(best.values(), key=lambda state: state[:4])
    tied = [state for state in best.values() if state[:4] == winner[:4]]
    chosen = sorted(min(tied, key=lambda state: state[4])[4])

    picked = {item["id"]: item for item in items}
    return {
        "segments": chosen,
        "eliminated_overlap": sum(picked[i]["value"] for i in chosen),
        "charged_mib": sum(picked[i]["weight"] for i in chosen),
        "charged_records": sum(picked[i]["records"] for i in chosen) * RECORD_UNIT,
        "budget_mib": budget_mib,
        "budget_records": budget_records,
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
    plan = compaction_plan(
        manifest["levels"]["0"],
        int(policy["merge_budget_mib"]),
        int(policy["merge_record_budget"]),
    )
    charged = {
        s["id"]: (
            max(1, -(-int(s["bytes"]) // MIB)),
            max(1, -(-int(s["records"]) // RECORD_UNIT)) * RECORD_UNIT,
        )
        for s in manifest["levels"]["0"]
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "shard_index.json").write_text(
        json.dumps(shards, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_dir / "compaction_plan.jsonl").open("w", encoding="utf-8") as handle:
        for seg_id in plan["segments"]:
            mib, records = charged[seg_id]
            handle.write(
                json.dumps(
                    {"segment": seg_id, "charged_mib": mib, "charged_records": records},
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
        "discarded_segment_count": len(manifest["discarded_segments"]),
        "level0_candidate_count": plan["candidate_count"],
        "shard_count": len(shards),
        "max_shard_value_bytes": max(s["value_bytes"] for s in shards),
        "min_shard_value_bytes": min(s["value_bytes"] for s in shards),
        "max_shard_key_count": max(s["key_count"] for s in shards),
        "deepest_version_count": max(s["max_version_count"] for s in shards),
        "plan_segment_count": len(plan["segments"]),
        "plan_eliminated_overlap": plan["eliminated_overlap"],
        "plan_charged_mib": plan["charged_mib"],
        "plan_charged_records": plan["charged_records"],
        "plan_budget_mib": plan["budget_mib"],
        "plan_record_budget": plan["budget_records"],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
