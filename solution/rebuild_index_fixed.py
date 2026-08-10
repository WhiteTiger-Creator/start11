#!/usr/bin/env python3
"""Rebuild the shard index and the level-0 compaction plan for a 1.9 engine."""
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
        target = math.ceil(shard * total / shard_count)
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


def compaction_plan(segments: list[dict], budget_mib: int) -> dict:
    """Choose the level-0 merge set that eliminates the most overlap.

    The selection is an exact optimum over the whole candidate set, not a
    greedy pass: 1.9 requires the planner to return the best achievable score
    for the budget, and a density-ordered walk regularly leaves a better
    packing on the table. Sizes are charged in whole mebibytes, rounded up.
    Among selections of equal score the plan takes the fewest segments, then
    the smallest charged size, then the lexicographically smallest id list.
    """
    scores = overlap_scores(segments)
    items = sorted(
        (
            {
                "id": s["id"],
                "weight": max(1, math.ceil(int(s["bytes"]) / MIB)),
                "value": scores[s["id"]],
            }
            for s in segments
        ),
        key=lambda item: item["id"],
    )

    # All four keys are packed into a single integer so the search never has to
    # break a tie after the fact: overlap dominates, then the segment count,
    # then the charged size, and last a per-candidate bit that is worth more the
    # earlier the id sorts, which is exactly "lexicographically smallest list".
    count = len(items)
    bit = 1 << count
    weight_unit = bit
    count_unit = (max(item["weight"] for item in items) * count + 1) * weight_unit
    value_unit = (count + 1) * count_unit

    rows = [[0] * (budget_mib + 1) for _ in range(count + 1)]
    for i in range(count - 1, -1, -1):
        item, here, nxt = items[i], rows[i], rows[i + 1]
        gain = (
            item["value"] * value_unit
            - count_unit
            - item["weight"] * weight_unit
            + (1 << (count - 1 - i))
        )
        for capacity in range(budget_mib + 1):
            skip = nxt[capacity]
            here[capacity] = (
                max(skip, nxt[capacity - item["weight"]] + gain)
                if item["weight"] <= capacity
                else skip
            )

    chosen: list[str] = []
    capacity = budget_mib
    for i, item in enumerate(items):
        if item["weight"] <= capacity and rows[i][capacity] != rows[i + 1][capacity]:
            chosen.append(item["id"])
            capacity -= item["weight"]

    picked = {item["id"]: item for item in items}
    return {
        "segments": chosen,
        "eliminated_overlap": sum(picked[i]["value"] for i in chosen),
        "charged_mib": sum(picked[i]["weight"] for i in chosen),
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
    plan = compaction_plan(manifest["levels"]["0"], int(policy["merge_budget_mib"]))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "shard_index.json").write_text(
        json.dumps(shards, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_dir / "compaction_plan.jsonl").open("w", encoding="utf-8") as handle:
        for seg_id in plan["segments"]:
            handle.write(
                json.dumps(
                    {
                        "segment": seg_id,
                        "charged_mib": max(
                            1,
                            math.ceil(
                                int(
                                    next(
                                        s["bytes"]
                                        for s in manifest["levels"]["0"]
                                        if s["id"] == seg_id
                                    )
                                )
                                / MIB
                            ),
                        ),
                    },
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
        "plan_budget_mib": plan["budget_mib"],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
