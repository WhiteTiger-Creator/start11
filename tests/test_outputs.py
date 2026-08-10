"""Grade the segment-index reconciliation and the rebuilt index.

The agent's program is never imported: it is executed as a subprocess under an
unprivileged uid with a scrubbed environment, and only its files are read.
"""
import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path

import pytest

APP = Path("/app")
DATA = APP / "data"
WORKFLOW_PATH = APP / "workflow" / "rebuild_index.py"
ORIGINAL_WORKFLOW_PATH = APP / "workflow" / ".rebuild_index.original"
CONTRACT_PATH = APP / "docs" / "index_contract.json"
MANIFEST_PATH = DATA / "manifest.json"
POLICY_PATH = DATA / "index_policy.json"
SEGMENT_DIR = DATA / "segments"
PENDING_DIR = DATA / "pending"
BASE_PATH = DATA / "compacted_base.jsonl"
REPAIRED_PATH = DATA / "manifest_repaired.json"

EXPECTED_FIXTURE = Path("/tests/fixtures/expected_report.json")
ALT_INPUT = Path("/tests/fixtures/alt_base.jsonl")
SHIPPED_BASE_REFERENCE = Path("/tests/fixtures/shipped_base.json")

FIXTURE = json.loads(EXPECTED_FIXTURE.read_text())
CONTRACT = json.loads(CONTRACT_PATH.read_text())

RUNTIME_BUDGET_SEC = 120.0
MIB = 1048576
WORK_DIR = Path("/candidate-work")
CANDIDATE_UID = 65534
CANDIDATE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/candidate-work",
    "LANG": "C.UTF-8",
}

SUMMARY_FIELDS = CONTRACT["outputs"]["summary"]["required_fields"]
SHARD_FIELDS = CONTRACT["outputs"]["shard_index"]["element_fields"]
PLAN_FIELDS = CONTRACT["outputs"]["compaction_plan"]["element_fields"]
BASE_FIELDS = CONTRACT["reconciled_inputs"]["compacted_base"]["element_fields"]
MANIFEST_ENTRY_FIELDS = CONTRACT["reconciled_inputs"]["manifest_repaired"]["level_entry_fields"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _digest(value) -> str:
    """Canonical digest of a decoded document, insensitive to formatting."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_json(path: Path):
    """Read a JSON document."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list:
    """Read a JSON-lines document, ignoring blank lines."""
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _publish_inputs() -> None:
    """Open read access on the agent-produced inputs before privileges drop.

    A correct solution may write its reconciled base atomically, leaving the
    file mode 0600 and owned by root; the candidate subprocess runs as uid
    65534 and would then fail to read its own output for reasons that have
    nothing to do with correctness.
    """
    for path in sorted(APP.rglob("*")):
        try:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        except OSError:
            pass


def _run_pipeline(script_path: Path = WORKFLOW_PATH, input_path: Path | None = None,
                  output_dir: Path | None = None):
    """Execute the agent's rebuild as an unprivileged subprocess.

    Returns the elapsed process, the summary, the shard index and the plan.
    """
    _publish_inputs()
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK_DIR, 0o1777)
    target = Path(output_dir) if output_dir else WORK_DIR / "out"
    if target.exists():
        for stale in target.rglob("*"):
            if stale.is_file():
                stale.unlink()
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, 0o1777)

    command = [
        "setpriv",
        f"--reuid={CANDIDATE_UID}",
        f"--regid={CANDIDATE_UID}",
        "--clear-groups",
        "--no-new-privs",
        sys.executable,
        str(script_path),
        "--output-dir",
        str(target),
    ]
    if input_path is not None:
        command.extend(["--input", str(input_path)])

    completed = subprocess.run(
        command,
        cwd=str(WORK_DIR),
        env=CANDIDATE_ENV,
        capture_output=True,
        text=True,
        check=False,
        # The contract's own budget, enforced rather than documented: a run
        # that takes the obvious route does not come back inside it, and a
        # timeout here is a failure exactly as the contract says.
        timeout=RUNTIME_BUDGET_SEC,
    )
    assert completed.returncode == 0, (
        f"the rebuild exited {completed.returncode}\n"
        f"stdout: {completed.stdout[-2000:]}\nstderr: {completed.stderr[-2000:]}"
    )
    return (
        completed,
        _load_json(target / "summary.json"),
        _load_json(target / "shard_index.json"),
        _load_jsonl(target / "compaction_plan.jsonl"),
    )


@pytest.fixture(scope="module")
def primary_outputs():
    """One run over the agent's own reconciled base, shared by most tests."""
    return _run_pipeline()


# --------------------------------------------------------------------------
# Independent recomputation of the plan, written differently from any
# reference so that agreeing with it is evidence rather than a tautology.
# --------------------------------------------------------------------------
def _byte_key(value: str) -> bytes:
    """Raw UTF-8 collation."""
    return value.encode("utf-8")


def _overlap_scores(segments: list[dict]) -> dict[str, int]:
    """Count, per segment, the other segments its key range meets."""
    spans = [(_byte_key(s["min_key"]), _byte_key(s["max_key"]), s["id"]) for s in segments]
    scores = {seg_id: 0 for _, _, seg_id in spans}
    for i, (lo_a, hi_a, id_a) in enumerate(spans):
        for lo_b, hi_b, id_b in spans[i + 1:]:
            if lo_a <= hi_b and lo_b <= hi_a:
                scores[id_a] += 1
                scores[id_b] += 1
    return scores


def _plan_items(segments: list[dict]) -> list[dict]:
    """Charged size and overlap score per candidate, in id order."""
    scores = _overlap_scores(segments)
    return sorted(
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


def _optimal_plan(items: list[dict], budget: int) -> tuple[int, list[str]]:
    """Best attainable score and the plan that the tie-breaks single out.

    A forward search over reachable loads carrying the full ordering key, which
    is a different formulation from the reference's backward table; the two
    agreeing is a real cross-check rather than the same code twice.
    """
    # state: charged load -> (value, -count, -load, chosen ids)
    reachable = {0: (0, 0, 0, [])}
    for item in items:
        nxt = dict(reachable)
        for load, (value, negc, negl, ids) in reachable.items():
            new_load = load + item["weight"]
            if new_load > budget:
                continue
            candidate = (value + item["value"], negc - 1, -new_load, [*ids, item["id"]])
            held = nxt.get(new_load)
            if held is None or candidate[:3] > held[:3] or (
                candidate[:3] == held[:3] and candidate[3] < held[3]
            ):
                nxt[new_load] = candidate
        reachable = nxt
    best = max(reachable.values(), key=lambda state: (state[0], state[1], state[2]))
    tied = [
        state
        for state in reachable.values()
        if (state[0], state[1], state[2]) == (best[0], best[1], best[2])
    ]
    return best[0], sorted(min(tied, key=lambda state: state[3])[3])


def _greedy_scores(items: list[dict], budget: int) -> dict[str, int]:
    """What the plausible heuristics achieve on the same candidate set."""
    orders = {
        "density": lambda item: (-item["value"] / item["weight"], item["id"]),
        "value": lambda item: (-item["value"], item["weight"], item["id"]),
        "smallest": lambda item: (item["weight"], -item["value"], item["id"]),
    }
    results = {}
    for label, order in orders.items():
        remaining, score = budget, 0
        for item in sorted(items, key=order):
            if item["weight"] <= remaining:
                remaining -= item["weight"]
                score += item["value"]
        results[label] = score
    return results


# --------------------------------------------------------------------------
# Step one: the reconciliation itself
# --------------------------------------------------------------------------
def test_reconciled_base_exists_and_is_jsonl():
    """The base has to be rebuilt at the path the contract names."""
    assert BASE_PATH.is_file(), "the compacted base was not rebuilt"
    rows = _load_jsonl(BASE_PATH)
    assert rows, "the compacted base is empty"
    assert all(isinstance(row, dict) for row in rows)


def test_reconciled_base_matches_expected():
    """The rebuilt base must equal the reconciliation the release defines."""
    assert _digest(_load_jsonl(BASE_PATH)) == FIXTURE["expected_base_digest"]


def test_reconciled_base_carries_only_declared_fields():
    """No extra bookkeeping may leak into the base rows."""
    for row in _load_jsonl(BASE_PATH)[:5000]:
        assert sorted(row) == sorted(BASE_FIELDS)


def test_reconciled_base_is_sorted_by_byte_collation():
    """Ordering follows the deployed collation, not the case-folded one."""
    keys = [row["key"] for row in _load_jsonl(BASE_PATH)]
    assert keys == sorted(keys, key=_byte_key)
    assert len(keys) == len(set(keys)), "a key appears twice in the base"


def test_repaired_manifest_matches_expected():
    """The repaired manifest must equal the sealed reconciliation."""
    assert REPAIRED_PATH.is_file(), "the repaired manifest was not written"
    assert _digest(_load_json(REPAIRED_PATH)) == FIXTURE["expected_manifest_digest"]


def test_repaired_manifest_level_entries_are_complete():
    """Every level-0 entry carries the metadata the planner needs."""
    repaired = _load_json(REPAIRED_PATH)
    for entry in repaired["levels"]["0"]:
        assert sorted(entry) == sorted(MANIFEST_ENTRY_FIELDS)
        assert entry["level"] == 0
        assert entry["records"] > 0
        assert entry["bytes"] > 0
        assert _byte_key(entry["min_key"]) <= _byte_key(entry["max_key"])
    ids = [entry["id"] for entry in repaired["levels"]["0"]]
    assert ids == sorted(ids), "level 0 is not ordered by segment id"


def test_torn_segment_is_discarded_whole():
    """The torn flush is dropped entirely, not truncated at its last record."""
    repaired = _load_json(REPAIRED_PATH)
    assert repaired["discarded_segments"] == FIXTURE["expected_discarded"]
    admitted = {entry["id"] for entry in repaired["levels"]["0"]}
    for discarded in FIXTURE["expected_discarded"]:
        assert discarded not in admitted


def test_admitted_segments_are_numbered_from_the_checkpoint():
    """Recovered segments are placed and numbered as the release states."""
    repaired = _load_json(REPAIRED_PATH)
    checkpoint = _load_json(MANIFEST_PATH)["checkpoint_seq"]
    linked = {entry["id"] for entry in _load_json(MANIFEST_PATH)["levels"]["0"]}
    recovered = [e for e in repaired["levels"]["0"] if e["id"] not in linked]
    assert recovered, "no unlinked segment was admitted"
    for rank, entry in enumerate(sorted(recovered, key=lambda e: e["id"])):
        assert entry["seq"] == checkpoint + 1 + rank
        assert entry["level"] == 0


def test_source_segments_are_left_untouched():
    """Reconciliation reads the segment files; it never rewrites them."""
    live = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(SEGMENT_DIR.glob("*.jsonl"))
    }
    live.update(
        {
            f"pending/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(PENDING_DIR.glob("*.jsonl"))
        }
    )
    assert _digest(live) == FIXTURE["segment_tree_digest"]


def test_shipped_base_was_actually_incomplete():
    """The base that shipped covered only part of the tree.

    Without this the dependency claim would rest on an assumption; the shipped
    row count is sealed so a task that quietly shipped a finished base would
    fail here rather than pass everything.
    """
    shipped = _load_json(SHIPPED_BASE_REFERENCE)
    assert shipped["row_count"] < FIXTURE["expected_base_row_count"]
    assert _digest(_load_jsonl(BASE_PATH)) != shipped["digest"]


# --------------------------------------------------------------------------
# Step one drives step two: wrong reconciliations must move the outputs
# --------------------------------------------------------------------------
def _variant_bases() -> dict[str, list]:
    """Plausible misreadings of the release notes, as perturbed bases.

    Each is a transformation of the agent's own reconciled base rather than a
    second implementation of it, so these stay honest if the reference changes.
    """
    rows = _load_jsonl(BASE_PATH)
    variants: dict[str, list] = {}

    # 2.2 collation: order the same rows case-insensitively.
    variants["case_folded_order"] = sorted(
        rows, key=lambda row: (row["key"].lower(), _byte_key(row["key"]))
    )
    # 2.0 tombstones: keys the deployed release suppressed come back as rows.
    revived = [dict(row) for row in rows]
    for row in revived[::37]:
        row["value_bytes"] = 0
    variants["tombstones_retained"] = revived
    # 2.1 precedence: a sequence-only winner picks a different version, which
    # shows up as different stored sizes and depths for the affected keys.
    reprecedenced = [dict(row) for row in rows]
    for row in reprecedenced[::23]:
        row["level"] = 2
        row["value_bytes"] = max(1, row["value_bytes"] // 2)
    variants["sequence_only_precedence"] = reprecedenced
    # 1.3 recovery: the torn segment truncated instead of discarded, so its
    # surviving head contributes extra keys.
    truncated = [dict(row) for row in rows]
    truncated.extend(
        {
            "key": f"zzrecovered:{i:07d}",
            "level": 0,
            "seq": row["seq"] + 1,
            "segment": FIXTURE["expected_discarded"][0],
            "value_bytes": 512,
            "version_count": 1,
        }
        for i, row in enumerate(rows[:400])
    )
    variants["torn_segment_truncated"] = sorted(truncated, key=lambda r: _byte_key(r["key"]))
    return variants


def test_wrong_reconciliations_change_the_index(primary_outputs):
    """Each misreading of the release notes must move the graded outputs.

    The agent's own engine is re-run over every wrong base; if the outputs did
    not move, the reconciliation step would not be graded at all.
    """
    _, summary, shards, _plan = primary_outputs
    for label, rows in _variant_bases().items():
        staged = WORK_DIR / f"variant_{label}.jsonl"
        staged.write_text(
            "".join(
                json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows
            ),
            encoding="utf-8",
        )
        os.chmod(staged, 0o644)
        _, other_summary, other_shards, _ = _run_pipeline(
            input_path=staged, output_dir=WORK_DIR / f"out_{label}"
        )
        assert (other_summary, other_shards) != (summary, shards), label
        assert _digest(other_shards) != FIXTURE["primary"]["shard_digest"], label


# --------------------------------------------------------------------------
# Step two: the graded artifacts
# --------------------------------------------------------------------------
def test_primary_summary_matches_fixture(primary_outputs):
    """The summary must equal the sealed reference summary exactly."""
    _, summary, _, _ = primary_outputs
    assert summary == FIXTURE["primary"]["summary"]


def test_primary_shard_index_matches_fixture(primary_outputs):
    """The shard index must equal the sealed reference index."""
    _, _, shards, _ = primary_outputs
    assert _digest(shards) == FIXTURE["primary"]["shard_digest"]


def test_primary_plan_matches_fixture(primary_outputs):
    """The compaction plan must equal the sealed reference plan."""
    _, _, _, plan = primary_outputs
    assert _digest(plan) == FIXTURE["primary"]["plan_digest"]


def test_summary_required_fields_and_types(primary_outputs):
    """Every contract field is present with the declared type."""
    _, summary, _, _ = primary_outputs
    assert sorted(summary) == sorted(SUMMARY_FIELDS)
    for field, kind in CONTRACT["outputs"]["summary"]["field_types"].items():
        value = summary[field]
        if kind == "integer":
            assert isinstance(value, int) and not isinstance(value, bool), field
        else:
            assert isinstance(value, str), field
    assert summary["schema_version"] == CONTRACT["outputs"]["summary"]["schema_version_value"]


def test_shard_rows_carry_declared_fields_and_types(primary_outputs):
    """Shard rows match the contract shape."""
    _, _, shards, _ = primary_outputs
    for row in shards:
        assert sorted(row) == sorted(SHARD_FIELDS)
        for field, kind in CONTRACT["outputs"]["shard_index"]["field_types"].items():
            value = row[field]
            if kind == "integer":
                assert isinstance(value, int) and not isinstance(value, bool), field
            else:
                assert isinstance(value, str), field


def test_plan_rows_carry_declared_fields_and_are_sorted(primary_outputs):
    """Plan rows match the contract shape and its stated order."""
    _, _, _, plan = primary_outputs
    for row in plan:
        assert sorted(row) == sorted(PLAN_FIELDS)
    ids = [row["segment"] for row in plan]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_shards_are_contiguous_and_cover_the_base(primary_outputs):
    """The shards partition the base: numbered from zero, no key lost."""
    _, summary, shards, _ = primary_outputs
    assert [row["shard"] for row in shards] == list(range(len(shards)))
    rows = _load_jsonl(BASE_PATH)
    assert sum(row["key_count"] for row in shards) == len(rows)
    assert sum(row["value_bytes"] for row in shards) == sum(
        int(row["value_bytes"]) for row in rows
    )
    assert summary["base_key_count"] == len(rows)
    boundaries = [row["first_key"] for row in shards] + [shards[-1]["last_key"]]
    assert boundaries == sorted(boundaries, key=_byte_key)


def test_shards_balance_stored_bytes_not_key_counts(primary_outputs):
    """The split follows stored bytes, which is not the key-count split.

    Byte balance is tight and key balance is not; asserting both directions
    keeps a key-count implementation from passing.
    """
    _, _, shards, _ = primary_outputs
    byte_spread = max(r["value_bytes"] for r in shards) / min(
        r["value_bytes"] for r in shards
    )
    key_spread = max(r["key_count"] for r in shards) / min(r["key_count"] for r in shards)
    assert byte_spread < 1.05, f"stored bytes are not balanced: {byte_spread}"
    assert key_spread > 1.2, f"the split looks like a key-count split: {key_spread}"


def test_summary_agrees_with_its_own_artifacts(primary_outputs):
    """Summary aggregates are recomputed from the artifacts they describe."""
    _, summary, shards, plan = primary_outputs
    assert summary["shard_count"] == len(shards)
    assert summary["max_shard_value_bytes"] == max(r["value_bytes"] for r in shards)
    assert summary["min_shard_value_bytes"] == min(r["value_bytes"] for r in shards)
    assert summary["max_shard_key_count"] == max(r["key_count"] for r in shards)
    assert summary["deepest_version_count"] == max(r["max_version_count"] for r in shards)
    assert summary["plan_segment_count"] == len(plan)
    assert summary["plan_charged_mib"] == sum(row["charged_mib"] for row in plan)
    assert summary["plan_budget_mib"] == _load_json(POLICY_PATH)["merge_budget_mib"]
    assert summary["engine_version"] == _load_json(MANIFEST_PATH)["engine_version"]


def test_shard_count_follows_the_policy(primary_outputs):
    """The configured shard count is honoured."""
    _, summary, _, _ = primary_outputs
    assert summary["shard_count"] == _load_json(POLICY_PATH)["shard_count"]


# --------------------------------------------------------------------------
# The plan has to be an optimum, not a heuristic
# --------------------------------------------------------------------------
def test_plan_is_within_budget_and_charged_upward(primary_outputs):
    """Sizes are charged in whole mebibytes, rounded up, inside the budget."""
    _, _, _, plan = primary_outputs
    entries = {e["id"]: e for e in _load_json(REPAIRED_PATH)["levels"]["0"]}
    for row in plan:
        assert row["segment"] in entries, f"{row['segment']} is not a level-0 candidate"
        expected = max(1, math.ceil(int(entries[row["segment"]]["bytes"]) / MIB))
        assert row["charged_mib"] == expected, row["segment"]
    budget = _load_json(POLICY_PATH)["merge_budget_mib"]
    assert sum(row["charged_mib"] for row in plan) <= budget


def test_plan_attains_the_optimum(primary_outputs):
    """The plan's score must equal the optimum recomputed independently."""
    _, summary, _, plan = primary_outputs
    candidates = _load_json(REPAIRED_PATH)["levels"]["0"]
    items = _plan_items(candidates)
    budget = _load_json(POLICY_PATH)["merge_budget_mib"]
    best_score, best_ids = _optimal_plan(items, budget)

    scores = {item["id"]: item["value"] for item in items}
    achieved = sum(scores[row["segment"]] for row in plan)
    assert achieved == best_score, (
        f"the plan scores {achieved} against an attainable {best_score}"
    )
    assert summary["plan_eliminated_overlap"] == best_score
    assert [row["segment"] for row in plan] == best_ids


def test_greedy_planners_score_strictly_below_the_optimum(primary_outputs):
    """A heuristic planner cannot reach this optimum by luck.

    If every greedy order happened to tie the optimum the optimality test above
    would prove nothing, so the gap itself is asserted.
    """
    _, summary, _, _ = primary_outputs
    items = _plan_items(_load_json(REPAIRED_PATH)["levels"]["0"])
    budget = _load_json(POLICY_PATH)["merge_budget_mib"]
    for label, score in _greedy_scores(items, budget).items():
        assert score < summary["plan_eliminated_overlap"], (
            f"the {label} heuristic already reaches the optimum"
        )


def test_plan_covers_level_zero_only(primary_outputs):
    """Level-1 and level-2 segments are not candidates for this plan."""
    _, summary, _, plan = primary_outputs
    repaired = _load_json(REPAIRED_PATH)
    level_zero = {entry["id"] for entry in repaired["levels"]["0"]}
    higher = {entry["id"] for level in ("1", "2") for entry in repaired["levels"][level]}
    for row in plan:
        assert row["segment"] in level_zero
        assert row["segment"] not in higher
    assert summary["level0_candidate_count"] == len(level_zero)


# --------------------------------------------------------------------------
# Generalisation, idempotency, the command line
# --------------------------------------------------------------------------
def test_rebuild_is_idempotent():
    """Two runs over the same base produce the same three artifacts."""
    _, summary_a, shards_a, plan_a = _run_pipeline(output_dir=WORK_DIR / "idem_a")
    _, summary_b, shards_b, plan_b = _run_pipeline(output_dir=WORK_DIR / "idem_b")
    assert (summary_a, shards_a, plan_a) == (summary_b, shards_b, plan_b)


def test_rebuild_generalises_to_a_held_out_base():
    """A base the agent never saw must produce the sealed alternate outputs."""
    # /tests stays unreadable to the candidate uid, so the held-out base is
    # staged into the shared scratch area before the run.
    staged = WORK_DIR / "alt_base.jsonl"
    staged.write_bytes(ALT_INPUT.read_bytes())
    os.chmod(staged, 0o644)
    _, summary, shards, plan = _run_pipeline(
        input_path=staged, output_dir=WORK_DIR / "alt"
    )
    assert summary == FIXTURE["alternate"]["summary"]
    assert _digest(shards) == FIXTURE["alternate"]["shard_digest"]
    assert _digest(plan) == FIXTURE["alternate"]["plan_digest"]


def test_cli_defaults_match_an_explicit_run(primary_outputs):
    """Running with no arguments is the documented default run."""
    _, explicit_summary, explicit_shards, explicit_plan = primary_outputs
    default_dir = APP / "output"
    # solve.sh leaves its own run behind as root; the candidate uid has to be
    # able to overwrite it for the default-path run to mean anything.
    _publish_inputs()
    default_dir.mkdir(parents=True, exist_ok=True)
    for stale in default_dir.iterdir():
        if stale.is_file():
            stale.unlink()
    os.chmod(default_dir, 0o1777)
    completed = subprocess.run(
        [
            "setpriv",
            f"--reuid={CANDIDATE_UID}",
            f"--regid={CANDIDATE_UID}",
            "--clear-groups",
            "--no-new-privs",
            sys.executable,
            str(WORKFLOW_PATH),
        ],
        cwd=str(WORK_DIR),
        env=CANDIDATE_ENV,
        capture_output=True,
        text=True,
        check=False,
        # The contract's own budget, enforced rather than documented: a run
        # that takes the obvious route does not come back inside it, and a
        # timeout here is a failure exactly as the contract says.
        timeout=RUNTIME_BUDGET_SEC,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert _load_json(default_dir / "summary.json") == explicit_summary
    assert _digest(_load_json(default_dir / "shard_index.json")) == _digest(explicit_shards)
    assert _digest(_load_jsonl(default_dir / "compaction_plan.jsonl")) == _digest(explicit_plan)


def test_policy_path_actually_influences_the_output():
    """The policy is read from its fixed path, not inlined as a constant."""
    original = POLICY_PATH.read_text(encoding="utf-8")
    policy = json.loads(original)
    policy["shard_count"] = int(policy["shard_count"]) // 2
    policy["merge_budget_mib"] = int(policy["merge_budget_mib"]) // 3
    try:
        POLICY_PATH.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _, summary, shards, plan = _run_pipeline(output_dir=WORK_DIR / "policy")
        assert summary["shard_count"] == policy["shard_count"]
        assert len(shards) == policy["shard_count"]
        assert summary["plan_budget_mib"] == policy["merge_budget_mib"]
        assert sum(row["charged_mib"] for row in plan) <= policy["merge_budget_mib"]
        assert summary != FIXTURE["primary"]["summary"]
    finally:
        POLICY_PATH.write_text(original, encoding="utf-8")


def test_run_finishes_inside_the_contract_budget(primary_outputs):
    """The contract states one budget and the tests hold the same number."""
    assert CONTRACT["runtime_budget_seconds"] == RUNTIME_BUDGET_SEC
    _, summary, _, _ = primary_outputs
    assert summary["base_key_count"] > 100_000, "the graded base is not at scale"


# --------------------------------------------------------------------------
# The frozen snapshot
# --------------------------------------------------------------------------
def test_original_snapshot_preserved():
    """The migration-branch engine must still be on disk, unmodified."""
    assert ORIGINAL_WORKFLOW_PATH.exists()
    digest = hashlib.sha256(ORIGINAL_WORKFLOW_PATH.read_bytes()).hexdigest()
    assert digest == FIXTURE["broken_engine_sha256"]


def test_original_snapshot_is_wrong():
    """The shipped engine must not already produce the graded outputs."""
    _, summary, shards, plan = _run_pipeline(
        script_path=ORIGINAL_WORKFLOW_PATH, output_dir=WORK_DIR / "orig"
    )
    assert summary != FIXTURE["primary"]["summary"]
    assert _digest(shards) != FIXTURE["primary"]["shard_digest"]
    assert _digest(plan) != FIXTURE["primary"]["plan_digest"]


def test_release_notes_were_not_edited():
    """The rule source is read, not rewritten to suit the implementation."""
    live = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((APP / "docs" / "release_notes").glob("*.md"))
    }
    assert _digest(live) == FIXTURE["release_notes_digest"]
