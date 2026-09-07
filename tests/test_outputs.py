"""Grade the segment-index reconciliation and the rebuilt index.

The agent's program is never imported: it is executed as a subprocess under an
unprivileged uid with a scrubbed environment, and only its files are read.
"""
import ast
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

APP = Path("/app")
DATA = APP / "data"
WORKFLOW_PATH = APP / "workflow" / "rebuild_index.py"
ORIGINAL_WORKFLOW_PATH = APP / "workflow" / ".rebuild_index.original"
CONTRACT_PATH = APP / "docs" / "index_contract.json"
# The contract is golden metadata: the verifier reads it from its own image,
# never from the agent-writable copy under /app.
GOLDEN_CONTRACT_PATH = Path("/tests/fixtures/contract_golden.json")
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
CONTRACT = json.loads(GOLDEN_CONTRACT_PATH.read_text())

RUNTIME_BUDGET_SEC = 120.0
MIB = 1048576
RECORD_UNIT = 1000  # v1.9 charges records in whole thousands
WORK_DIR = Path("/candidate-work")
CANDIDATE_UID = 65534


def _setpriv_prefix(base: list) -> list:
    """The strictest setpriv invocation this image actually supports.

    Dropping the uid is not the whole of it: a candidate that kept inheritable
    or bounding-set capabilities could regain privilege across an exec. The two
    flags are probed rather than assumed, because a util-linux without them
    would make every run fail on the flag rather than on the task.
    """
    strict = base + ["--inh-caps=-all", "--bounding-set=-all"]
    try:
        probe = subprocess.run(strict + ["/bin/true"], capture_output=True, timeout=30)
        if probe.returncode == 0:
            return strict
    except (OSError, subprocess.SubprocessError):
        pass
    return base


# Resource ceilings for anything run as the candidate. Deliberately not
# RLIMIT_AS or RLIMIT_DATA: a language runtime that reserves a large virtual
# arena at start-up dies under those, so they would kill a correct program
# rather than a runaway one. These bound the failure modes that actually escape
# a process group -- forking without end, filling the disk, dumping core.
_CANDIDATE_NPROC = 512
_CANDIDATE_FSIZE = 512 * 1024 * 1024
_CANDIDATE_NOFILE = 1024


def _apply_rlimits() -> None:
    """Run in the child between fork and exec: own session, plus ceilings."""
    import resource

    for what, limit in (
        (resource.RLIMIT_NPROC, _CANDIDATE_NPROC),
        (resource.RLIMIT_FSIZE, _CANDIDATE_FSIZE),
        (resource.RLIMIT_NOFILE, _CANDIDATE_NOFILE),
        (resource.RLIMIT_CORE, 0),
    ):
        try:
            _soft, hard = resource.getrlimit(what)
            ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            resource.setrlimit(what, (ceiling, ceiling))
        except (ValueError, OSError):
            continue
    os.setsid()


def _pids_owned_by(uid: int) -> list:
    """Every live pid whose owner is `uid`, read from /proc."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat("/proc/" + entry).st_uid == uid:
                pids.append(int(entry))
        except OSError:
            continue
    return pids


def reap_candidate_uid(uid: int = CANDIDATE_UID) -> None:
    """Kill everything still running as the candidate, whatever group it is in.

    Killing the process group is not enough on its own: a submitted program can
    call setsid and leave its own group, and would then survive into later tests
    -- holding the staged inputs of the next run, or still writing into an
    output directory being read. Ownership is the property that cannot be
    escaped, so the sweep is by owner.
    """
    import signal as _signal
    import time as _time

    for _ in range(50):
        pids = _pids_owned_by(uid)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                continue
        for pid in pids:
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                continue
        _time.sleep(0.02)


_SETPRIV = _setpriv_prefix([
    "setpriv", f"--reuid={CANDIDATE_UID}", f"--regid={CANDIDATE_UID}",
    "--clear-groups", "--no-new-privs",
])


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
    """Read a contracted JSONL artifact, taking every line as written.

    Skipping blank lines here softened a contract that says one compact object
    per line: a run that padded its output with empty lines read back the same
    as a clean one and scored full marks. A blank line is a malformed line and
    is read as one.
    """
    text = Path(path).read_text(encoding="utf-8")
    if not text:
        return []
    assert text.endswith("\n"), f"{Path(path).name} has no trailing newline"
    lines = text.split("\n")[:-1]
    for number, line in enumerate(lines, start=1):
        assert line.strip(), f"{Path(path).name} line {number} is blank"
    return [json.loads(line) for line in lines]


def _publish_inputs() -> None:
    """Open read access on the agent-produced inputs before privileges drop.

    A correct solution may write its reconciled base atomically, leaving the
    file mode 0600 and owned by root; the candidate subprocess runs as uid
    65534 and would then fail to read its own output for reasons that have
    nothing to do with correctness.
    """
    for path in sorted(APP.rglob("*")):
        # Never chmod through a link. This walks a tree the agent controls, so a
        # link planted in it would otherwise have root widen its TARGET -- and a
        # link pointing into /tests would reopen the sealed fixtures to the uid the
        # graded program runs as. is_symlink() stats the link itself; os.chmod's
        # follow_symlinks=False is unavailable on Linux, which has no lchmod, and
        # raises NotImplementedError rather than doing nothing.
        if path.is_symlink():
            continue
        try:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        except OSError:
            pass


def test_publishing_inputs_does_not_chmod_through_a_planted_link():
    """A link under /app cannot make root widen what it points at.

    _publish_inputs runs as root over a tree the agent controls, so a link planted
    there and aimed at /tests would otherwise open the sealed fixtures to the uid
    the graded program runs as. Written as a live attempt, so it keeps holding if
    the loop is rewritten.
    """
    target = EXPECTED_FIXTURE
    target_dir = target.parent
    before_file, before_dir = target.stat().st_mode, target_dir.stat().st_mode
    planted_file = DATA / "planted-link.json"
    planted_dir = DATA / "planted-dir-link"
    for link in (planted_file, planted_dir):
        if link.is_symlink() or link.exists():
            link.unlink()
    planted_file.symlink_to(target)
    planted_dir.symlink_to(target_dir)
    try:
        _publish_inputs()
        assert target.stat().st_mode == before_file, (
            "root chmod followed a planted link and widened a sealed fixture")
        assert target_dir.stat().st_mode == before_dir, (
            "root chmod followed a planted link and widened the fixture directory")
        assert planted_file.is_symlink() and planted_dir.is_symlink()
    finally:
        for link in (planted_file, planted_dir):
            if link.is_symlink() or link.exists():
                link.unlink()


def _reap_group(pgid: int) -> None:
    """Kill and reap whatever the candidate left behind in its process group.

    The id is captured before the run rather than after: once the direct child
    has been waited on its process group can no longer be looked up, and a
    grandchild it double-forked would survive the run and outlive grading.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return
    for _ in range(50):
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(0.02)


def _run_candidate(command: list, cwd: Path) -> subprocess.CompletedProcess:
    """Run the graded program in its own session and collect what it wrote.

    Output goes to temporary files rather than pipes: a double-forked grandchild
    inherits the write end of a pipe and can hold it open long after its parent
    exits, which would stall the read instead of ending the run at the budget.
    The whole process group is killed once the direct child is done, so nothing
    the run spawned is still executing while its files are graded.
    """
    with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as out, \
            tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as err:
        proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=dict(CANDIDATE_ENV),
            stdout=out,
            stderr=err,
            preexec_fn=_apply_rlimits,
        )
        # Session leader, so the group id equals the pid; read it before the wait.
        pgid = proc.pid
        try:
            # The contract's own budget, enforced rather than documented: a run
            # that takes the obvious route does not come back inside it, and a
            # timeout here is a failure exactly as the contract says.
            proc.wait(timeout=RUNTIME_BUDGET_SEC)
        except subprocess.TimeoutExpired:
            _reap_group(pgid)
            reap_candidate_uid()
            proc.wait()
            raise
        finally:
            _reap_group(pgid)
            reap_candidate_uid()
        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(command, proc.returncode, out.read(), err.read())


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

    command = _SETPRIV + [
        sys.executable,
        str(script_path),
        "--output-dir",
        str(target),
    ]
    if input_path is not None:
        command.extend(["--input", str(input_path)])

    completed = _run_candidate(command, WORK_DIR)
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
    """Charged size, charged records and overlap score per candidate, in id order."""
    scores = _overlap_scores(segments)
    return sorted(
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


def _optimal_plan(items: list[dict], budget: int, record_budget: int) -> tuple[int, list[str]]:
    """Best attainable score and the plan that the tie-breaks single out.

    A backward table over both budgets, with the whole ordering key packed into
    one integer so a state costs a machine word rather than a list of ids: score
    dominates, then fewer segments, then smaller charged size, then smaller
    charged records, then a per-candidate bit worth more the earlier its id
    sorts, which is exactly "lexicographically smallest list". The reference
    searches forward over reachable loads instead, so the two agreeing is a real
    cross-check rather than the same code run twice.
    """
    cap = record_budget // RECORD_UNIT
    count = len(items)
    id_bits = 1 << count
    recs_unit = id_bits
    mib_unit = recs_unit * (sum(i["records"] for i in items) + 1)
    count_unit = mib_unit * (sum(i["weight"] for i in items) + 1)
    value_unit = count_unit * (count + 1)
    gains = [
        item["value"] * value_unit
        - count_unit
        - item["weight"] * mib_unit
        - item["records"] * recs_unit
        + (1 << (count - 1 - index))
        for index, item in enumerate(items)
    ]

    width = cap + 1
    table = [[0] * ((budget + 1) * width) for _ in range(count + 1)]
    for index in range(count - 1, -1, -1):
        item, here, nxt, gain = items[index], table[index], table[index + 1], gains[index]
        weight, records = item["weight"], item["records"]
        for mib in range(budget + 1):
            row = mib * width
            for recs in range(cap + 1):
                skip = nxt[row + recs]
                if weight <= mib and records <= recs:
                    take = nxt[(mib - weight) * width + (recs - records)] + gain
                    here[row + recs] = take if take > skip else skip
                else:
                    here[row + recs] = skip

    chosen: list[str] = []
    mib, recs = budget, cap
    for index, item in enumerate(items):
        if item["weight"] <= mib and item["records"] <= recs:
            here = table[index][mib * width + recs]
            if here != table[index + 1][mib * width + recs]:
                chosen.append(item["id"])
                mib -= item["weight"]
                recs -= item["records"]
    score = sum(item["value"] for item in items if item["id"] in set(chosen))
    return score, sorted(chosen)


def _greedy_scores(items: list[dict], budget: int, record_budget: int) -> dict[str, int]:
    """What the plausible heuristics achieve on the same candidate set."""
    orders = {
        "density": lambda item: (-item["value"] / item["weight"], item["id"]),
        "value": lambda item: (-item["value"], item["weight"], item["id"]),
        "smallest": lambda item: (item["weight"], -item["value"], item["id"]),
    }
    results = {}
    for label, order in orders.items():
        remaining, left, score = budget, record_budget // RECORD_UNIT, 0
        for item in sorted(items, key=order):
            if item["weight"] <= remaining and item["records"] <= left:
                remaining -= item["weight"]
                left -= item["records"]
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
    """No extra bookkeeping may leak into the base rows.

    The sort here is over FIELD NAMES, comparing the set of keys a row carries
    against the set the contract declares. A JSON object has no order to soften,
    and the row's own serialisation is graded byte for byte elsewhere.
    """
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


def test_a_segment_whose_count_agrees_but_whose_checksum_does_not_is_discarded():
    """The other half of v1.7's admission rule, which nothing used to reach.

    Only one pending segment used to fail admission and it failed on its trailer
    record count, so an engine that compared counts and never recomputed the
    checksum was graded identical to one that did both. seg-0093 carries a body
    whose length matches its trailer exactly and a checksum that does not.
    """
    raw = (PENDING_DIR / "seg-0093.jsonl").read_text(encoding="utf-8")
    assert raw.endswith("\n"), "seg-0093 has no trailing newline"
    body, trailer = [], None
    # every line is parsed as it stands: a segment file carries one record per
    # line and nothing else, so a blank line is a fault to report, not to skip
    for number, line in enumerate(raw.split("\n")[:-1], start=1):
        assert line.strip(), f"seg-0093 line {number} is blank"
        record = json.loads(line)
        if record.get("trailer"):
            trailer = record
        else:
            body.append(record)
    assert trailer is not None, "seg-0093 lost its trailer"
    assert trailer["records"] == len(body), (
        "seg-0093 must fail on its checksum alone, so its count has to agree")
    running = hashlib.sha256()
    for record in body:
        running.update(
            json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        running.update(b"\n")
    assert running.hexdigest()[:32] != trailer["checksum"], (
        "seg-0093's checksum agrees, so it no longer tests the rule")

    repaired = _load_json(REPAIRED_PATH)
    assert "seg-0093" in repaired["discarded_segments"]
    assert "seg-0093" not in {entry["id"] for entry in repaired["levels"]["0"]}
    keys = {row["key"] for row in _load_jsonl(BASE_PATH)}
    assert not (keys & {record["k"] for record in body}), (
        "keys from the discarded segment reached the base")


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


def test_repaired_manifest_carries_exactly_the_contracted_keys():
    """The repaired manifest's top-level key set is the contracted one, exactly.

    The sealed-digest check would also catch an extra key, but only as an opaque
    mismatch. index_contract.json states this key set is exhaustive, so a manifest
    that carried the shipped note and unlinked_dir forward fails here saying which
    keys were wrong.
    """
    repaired = _load_json(REPAIRED_PATH)
    wanted = set(CONTRACT["reconciled_inputs"]["manifest_repaired"]["required_fields"])
    extra, missing = set(repaired) - wanted, wanted - set(repaired)
    assert not extra, f"repaired manifest carries keys the contract does not: {sorted(extra)}"
    assert not missing, f"repaired manifest is missing contracted keys: {sorted(missing)}"


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
def _a_segment_entry_at_level(level: int) -> dict:
    """A segment entry the repaired manifest really carries at that level.

    The perturbed bases below have to stay consistent with the manifest the
    engine reads beside them, so a submission that validates one against the
    other is not failed for a rule the instruction never states. Consistent
    means the level and the segment id, and it also means the key range the
    entry records: a row attributed to a segment whose min_key/max_key do not
    cover it contradicts the manifest just as plainly as a wrong level does.
    """
    entries = _load_json(REPAIRED_PATH)["levels"][str(level)]
    assert entries, f"the repaired manifest has no level-{level} segment"
    return sorted(entries, key=lambda entry: entry["id"])[0]


def _a_segment_at_level(level: int) -> str:
    """The id of that segment."""
    return _a_segment_entry_at_level(level)["id"]


def _keys_inside(entry: dict, count: int, taken: set) -> list[str]:
    """Fresh keys that sort inside the entry's recorded range.

    Suffixing min_key keeps every one of them above min_key and below max_key,
    since max_key differs from min_key before the suffix begins.
    """
    low, high = entry["min_key"], entry["max_key"]
    minted = [f"{low}~{i:05d}" for i in range(count)]
    for key in minted:
        assert low < key < high, f"{key} falls outside {low}..{high}"
        assert key not in taken, f"{key} is already in the base"
    return minted


def _variant_bases() -> dict[str, list]:
    """Plausible misreadings of the release notes, as perturbed bases.

    Each is a transformation of the agent's own reconciled base rather than a
    second implementation of it, so these stay honest if the reference changes.
    """
    rows = _load_jsonl(BASE_PATH)
    variants: dict[str, list] = {}

    # A collation variant belongs here in spirit, but a pure reordering of the
    # same rows is recovered by any engine that defensively re-sorts its input --
    # which the shipped engine does and a minimal repair may well keep -- so it
    # would fail a correct solution. Byte collation is asserted directly on the
    # recovered base instead, by test_reconciled_base_is_sorted_by_byte_collation.
    # 2.0 tombstones: keys the deployed release suppressed come back as rows.
    revived = [dict(row) for row in rows]
    for row in revived[::37]:
        row["value_bytes"] = 0
    variants["tombstones_retained"] = revived
    # 2.1 precedence: a sequence-only winner picks a different version, which
    # shows up as different stored sizes and depths for the affected keys.
    reprecedenced = [dict(row) for row in rows]
    deeper = _a_segment_at_level(2)
    for row in reprecedenced[::23]:
        # the row moves to a level the manifest really has, and to a segment
        # that level really holds: an engine that sanity-checks its input
        # against the repaired manifest must not be failed for doing so, which
        # naming a level-2 row against a level-0 segment would have done.
        row["level"] = 2
        row["segment"] = deeper
        row["value_bytes"] = max(1, row["value_bytes"] // 2)
    variants["sequence_only_precedence"] = reprecedenced
    # 1.3 recovery: the torn segment truncated instead of discarded, so its
    # surviving head contributes extra keys.
    truncated = [dict(row) for row in rows]
    # The keys are what this variant is about: a torn segment truncated rather
    # than discarded contributes extra keys. They are attributed to a segment
    # the manifest admitted, so the base stays consistent with it and an engine
    # that checks the two against each other is not failed for the check.
    admitted = _a_segment_entry_at_level(0)
    minted = _keys_inside(admitted, 400, {row["key"] for row in rows})
    truncated.extend(
        {
            "key": key,
            "level": 0,
            "seq": row["seq"] + 1,
            "segment": admitted["id"],
            "value_bytes": 512,
            "version_count": 1,
        }
        for key, row in zip(minted, rows[:400])
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
        try:
            _, other_summary, other_shards, _ = _run_pipeline(
                input_path=staged, output_dir=WORK_DIR / f"out_{label}"
            )
        except AssertionError:
            # refusing a base that contradicts the manifest is a defensible
            # reading no document forbids, and it is not the graded result either
            continue
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
    """Shard rows match the contract shape.

    As above, the sort is over field NAMES against the contract's declared set;
    the rows' own order is asserted separately and is not softened here.
    """
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
    """Plan rows match the contract shape and its stated order.

    The first sort is over field NAMES. The second is the contract's own stated
    order for the plan -- ascending by segment id -- so comparing against
    sorted() is asserting the requirement rather than relaxing it.
    """
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
    # index_policy.json states min_shard_keys as the fewest keys a shard may
    # carry, so a window below it is dropped rather than written out
    floor = int(_load_json(POLICY_PATH)["min_shard_keys"])
    thin = [row["shard"] for row in shards if row["key_count"] < floor]
    assert not thin, f"shards below the policy floor of {floor} keys: {thin}"
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

    The boundaries are recomputed here straight from the release's rule -- shard
    k closes at the first key whose running total of stored bytes reaches
    k/shard_count of the whole -- and compared exactly, so the check carries no
    tuned tolerance to justify. The closing assertion shows the two splits really
    do differ on this base, which is what makes the comparison discriminating:
    an equal-key split would land on different boundaries and fail above.
    """
    _, _, shards, _ = primary_outputs
    rows = _load_jsonl(BASE_PATH)
    shard_count = int(_load_json(POLICY_PATH)["shard_count"])
    total = sum(int(row["value_bytes"]) for row in rows)

    expected = []
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
        expected.append(
            (
                window[0]["key"],
                window[-1]["key"],
                len(window),
                sum(int(row["value_bytes"]) for row in window),
            )
        )
        start = index

    observed = [
        (r["first_key"], r["last_key"], r["key_count"], r["value_bytes"]) for r in shards
    ]
    assert observed == expected, "the shard boundaries do not follow the stored bytes"

    equal_key_counts = [
        len(rows) // shard_count + (1 if position < len(rows) % shard_count else 0)
        for position in range(shard_count)
    ]
    assert [row[2] for row in expected] != equal_key_counts, (
        "on this base a key-count split coincides with the byte split, so the "
        "comparison above cannot tell the two apart"
    )


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
def test_plan_is_within_both_budgets_and_charged_upward(primary_outputs):
    """Bytes are charged in whole mebibytes and records in whole thousands, both up.

    #v1.9 bounds the merge twice over, and the two budgets do not track each
    other: a plan that fits the bytes and overruns the records is not a plan.
    """
    _, summary, _, plan = primary_outputs
    policy = _load_json(POLICY_PATH)
    entries = {e["id"]: e for e in _load_json(REPAIRED_PATH)["levels"]["0"]}
    for row in plan:
        assert row["segment"] in entries, f"{row['segment']} is not a level-0 candidate"
        entry = entries[row["segment"]]
        assert row["charged_mib"] == max(1, -(-int(entry["bytes"]) // MIB)), row["segment"]
        assert row["charged_records"] == (
            max(1, -(-int(entry["records"]) // RECORD_UNIT)) * RECORD_UNIT
        ), row["segment"]
    assert sum(row["charged_mib"] for row in plan) <= policy["merge_budget_mib"]
    assert sum(row["charged_records"] for row in plan) <= policy["merge_record_budget"]
    assert summary["plan_charged_records"] == sum(row["charged_records"] for row in plan)
    assert summary["plan_record_budget"] == policy["merge_record_budget"]


def test_the_record_budget_binds_and_is_not_slack(primary_outputs):
    """The second budget changes the answer rather than decorating it.

    Were the record budget loose enough to ignore, an engine that planned on
    bytes alone would still be right and the rule would grade nothing. The best
    selection under the byte budget alone is recomputed here and required to
    overrun the record budget.
    """
    items = _plan_items(_load_json(REPAIRED_PATH)["levels"]["0"])
    policy = _load_json(POLICY_PATH)
    # "no record budget at all" is the sum of every candidate's charge, which
    # bounds the table instead of blowing it up the way a huge literal would
    unbounded = sum(item["records"] for item in items) * RECORD_UNIT
    bytes_only, ids = _optimal_plan(items, policy["merge_budget_mib"], unbounded)
    charged = {item["id"]: item for item in items}
    spent = sum(charged[i]["records"] for i in ids) * RECORD_UNIT
    assert spent > policy["merge_record_budget"], (
        "the byte-optimal plan already fits the record budget, so the second "
        "budget decides nothing"
    )
    _, summary, _, _ = primary_outputs
    assert summary["plan_eliminated_overlap"] < bytes_only, (
        "planning on bytes alone reaches the same score, so the record budget "
        "costs nothing"
    )


def test_plan_attains_the_optimum(primary_outputs):
    """The plan's score must equal the optimum recomputed independently."""
    _, summary, _, plan = primary_outputs
    candidates = _load_json(REPAIRED_PATH)["levels"]["0"]
    items = _plan_items(candidates)
    policy = _load_json(POLICY_PATH)
    best_score, best_ids = _optimal_plan(
        items, policy["merge_budget_mib"], policy["merge_record_budget"]
    )

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
    policy = _load_json(POLICY_PATH)
    for label, score in _greedy_scores(
        items, policy["merge_budget_mib"], policy["merge_record_budget"]
    ).items():
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
    assert summary["candidate_count"] == len(level_zero)


# --------------------------------------------------------------------------
# Generalisation, idempotency, the command line
# --------------------------------------------------------------------------
def test_output_dir_holds_exactly_the_three_contracted_files():
    """instruction.md says a run writes exactly three artifacts.

    _run_pipeline reads those three by name, so a run that also dropped a scratch
    file beside them satisfied every other check here. This resolves into a fresh
    directory and then names everything in it.
    """
    _publish_inputs()
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK_DIR, 0o1777)
    target = WORK_DIR / "exact-out"
    if target.exists():
        for stale in sorted(target.rglob("*"), reverse=True):
            if stale.is_file() or stale.is_symlink():
                stale.unlink()
            else:
                stale.rmdir()
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, 0o1777)
    completed = _run_candidate(
        _SETPRIV + [
        sys.executable, str(WORKFLOW_PATH),
         "--output-dir", str(target)],
        WORK_DIR)
    # the exit code is a precondition; the verdict is the directory listing below
    assert completed.returncode == 0, (
        f"the run exited {completed.returncode}\n"
        f"stdout: {completed.stdout[-2000:]}\nstderr: {completed.stderr[-2000:]}")
    names = sorted(q.name for q in target.iterdir())
    assert names == ["compaction_plan.jsonl", "shard_index.json", "summary.json"], names
    # and the three are this run's real artifacts rather than three empty files
    # that happen to carry the contracted names
    assert _load_json(target / "summary.json") == FIXTURE["primary"]["summary"]
    assert _digest(_load_json(target / "shard_index.json")) == (
        FIXTURE["primary"]["shard_digest"])
    assert _digest(_load_jsonl(target / "compaction_plan.jsonl")) == (
        FIXTURE["primary"]["plan_digest"])


def test_artifacts_use_the_serialisation_the_contract_states():
    """Serialisation is contracted, and the digests cannot see it.

    _digest decodes before hashing, so an artifact with the right content and the
    wrong layout matches every sealed fixture. index_contract.json names two-space
    indent with sorted keys and a trailing newline for the JSON artifacts and one
    compact object per line for the plan, so those are read off the raw bytes.
    """
    target = WORK_DIR / "serialisation-out"
    _run_pipeline(output_dir=target)
    for name in ("summary.json", "shard_index.json"):
        raw = (target / name).read_text(encoding="utf-8")
        assert raw.endswith("\n"), f"{name} has no trailing newline"
        assert raw == json.dumps(json.loads(raw), indent=2, sort_keys=True) + "\n", (
            f"{name} is not two-space-indented JSON with sorted keys")

    raw = (target / "compaction_plan.jsonl").read_text(encoding="utf-8")
    assert raw.endswith("\n"), "compaction_plan.jsonl has no trailing newline"
    lines = raw.splitlines()
    assert lines and all(line.strip() for line in lines)
    for number, line in enumerate(lines, start=1):
        assert json.dumps(json.loads(line), separators=(",", ":"), sort_keys=True) == line, (
            f"plan line {number} is not the compact, key-sorted serialisation of its content")


_DYNAMIC_LOADERS = {"__import__", "import_module", "load_module", "exec_module",
                    "find_module", "module_from_spec", "spec_from_file_location",
                    "SourceFileLoader", "ExtensionFileLoader", "eval", "exec"}


def _imported_roots(source: str) -> set:
    """Top-level module names the source imports, read from the parse tree.

    Static import nodes are only half of it. A submission can reach an installed
    package through __import__("pandas") or importlib.import_module(name) and a
    scan that walks Import and ImportFrom alone sees nothing, so the standard
    library rule was enforced against the honest spelling only. Every name a
    dynamic loader is handed as a literal is taken as an import too.
    """
    roots = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            name = (target.id if isinstance(target, ast.Name)
                    else target.attr if isinstance(target, ast.Attribute) else None)
            if name not in _DYNAMIC_LOADERS:
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    roots.add(arg.value.split(".")[0])
    return roots


def _dynamic_loads_with_a_computed_name(source: str) -> list:
    """Dynamic loads whose argument is not a literal, which no scan can follow."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name = (target.id if isinstance(target, ast.Name)
                else target.attr if isinstance(target, ast.Attribute) else None)
        if name not in _DYNAMIC_LOADERS:
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        if not args or not all(
                isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args):
            out.append((name, node.lineno))
    return out


def test_rebuild_imports_only_the_standard_library():
    """instruction.md says standard library only, and nothing was checking it.

    Relying on the verifier image simply not carrying third-party packages is not
    the same as enforcing the rule: it makes the constraint an accident of the
    image rather than something the task states and grades. Modules the
    submission ships beside the rebuild are its own code, not a dependency.
    """
    # Every module the submission ships under /app/workflow, not just the entry
    # point: reading rebuild_index.py alone let a helper beside it import a
    # third-party package unnoticed.
    sources = sorted(WORKFLOW_PATH.parent.rglob("*.py"))
    assert WORKFLOW_PATH in sources, "the rebuild is not where the contract puts it"
    local = {path.stem for path in sources}
    local |= {path.name for path in WORKFLOW_PATH.parent.iterdir() if path.is_dir()}
    for source in sources:
        found = _imported_roots(source.read_text(encoding="utf-8"))
        outside = {name for name in found
                   if name not in sys.stdlib_module_names and name not in local}
        assert not outside, (
            f"{source.name} imports outside the standard library: {sorted(outside)}")
        # A dynamic load whose module name is computed cannot be resolved here
        # at all, so it is refused outright rather than waved through: the rule
        # is standard library only, and a name assembled at run time is a way of
        # not saying which library.
        computed = _dynamic_loads_with_a_computed_name(
            source.read_text(encoding="utf-8"))
        assert not computed, (
            f"{source.name} loads a module through a computed name, which no "
            f"import check can follow: {computed}")


def test_the_import_check_reads_dynamic_loads_as_well_as_static_ones():
    """The scan above is only worth running if it cannot be spelled around.

    Four ways to reach an installed package -- the plain import, the from-import,
    __import__ and importlib.import_module -- must all be seen, and a module the
    submission ships beside the rebuild must not be mistaken for one of them.
    """
    assert _imported_roots("import pandas") == {"pandas"}
    assert _imported_roots("from pandas import read_csv") == {"pandas"}
    assert _imported_roots("__import__('pandas')") == {"pandas"}
    assert _imported_roots(
        "import importlib\nimportlib.import_module('pandas.io')") == {
        "importlib", "pandas"}
    assert _imported_roots("import json\nimport collections") == {
        "json", "collections"}
    assert _dynamic_loads_with_a_computed_name("__import__(name)")
    assert not _dynamic_loads_with_a_computed_name("__import__('json')")


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
    completed = _run_candidate(
        _SETPRIV + [
        sys.executable,
            str(WORKFLOW_PATH),
        ],
        WORK_DIR,
    )
    # the exit code is a precondition; the verdict is the three artifacts below
    assert completed.returncode == 0, (
        f"the run exited {completed.returncode}\n"
        f"stdout: {completed.stdout[-2000:]}\nstderr: {completed.stderr[-2000:]}")
    assert _load_json(default_dir / "summary.json") == explicit_summary
    assert _digest(_load_json(default_dir / "shard_index.json")) == _digest(explicit_shards)
    assert _digest(_load_jsonl(default_dir / "compaction_plan.jsonl")) == _digest(explicit_plan)


_MIB = 1048576


def _tie_world(segments: list[tuple]) -> list[dict]:
    """Level-0 entries in the manifest's own shape, from a compact description.

    Every field the contract's level_entry_fields names is written, `level` and
    `seq` included. Neither reaches the planner, but an engine that validates
    the manifest it is handed against the contract is entitled to refuse a
    level entry missing them, and refusing a crafted world is not the failure
    this test is looking for.
    """
    entries = []
    for offset, (seg_id, lo, hi, mib, krecs) in enumerate(segments):
        entries.append({"id": seg_id, "level": 0, "seq": 900 + offset,
                        "min_key": lo, "max_key": hi,
                        "bytes": mib * _MIB, "records": krecs * 1000})
    return entries


# Three candidate sets where the optimal score is reached more than once. On the
# graded tree the optimum is unique, so a planner that returned any optimal
# subset matched every sealed fixture and the ordering 1.9 states went ungraded.
_TIES = {
    # fewest segments first: the lone wide segment ties with three pairs, and it
    # is NOT the lexicographically smallest of them, so id order lands elsewhere
    "fewest_segments": (
        [("seg-t280", "a", "e", 6, 6),
         ("seg-t281", "a", "a", 8, 8), ("seg-t282", "b", "b", 8, 8),
         ("seg-t283", "c", "c", 8, 8), ("seg-t284", "d", "d", 8, 8),
         ("seg-t205", "m", "o", 4, 4), ("seg-t206", "n", "p", 4, 4),
         ("seg-t207", "o", "q", 4, 4)],
        8, 8000, ["seg-t280"],
    ),
    # then smallest charged size: two single segments score alike, and the
    # cheaper one sorts second, so id order would take the dearer
    "smallest_charged_size": (
        [("seg-t300", "a", "f", 5, 5),
         ("seg-t301", "a", "a", 8, 8), ("seg-t302", "c", "c", 8, 8),
         ("seg-t303", "e", "e", 8, 8),
         ("seg-t310", "m", "r", 3, 5),
         ("seg-t311", "m", "m", 8, 8), ("seg-t312", "o", "o", 8, 8),
         ("seg-t313", "q", "q", 8, 8)],
        5, 5000, ["seg-t310"],
    ),
    # then smallest charged record count: two single segments alike on score and
    # on charged size, differing only in records, and the cheaper one sorts
    # second, so the id link would take the dearer
    "smallest_charged_records": (
        [("seg-t400", "a", "f", 4, 7),
         ("seg-t401", "a", "a", 8, 8), ("seg-t402", "c", "c", 8, 8),
         ("seg-t403", "e", "e", 8, 8),
         ("seg-t410", "m", "r", 4, 5),
         ("seg-t411", "m", "m", 8, 8), ("seg-t412", "o", "o", 8, 8),
         ("seg-t413", "q", "q", 8, 8)],
        4, 7000, ["seg-t410"],
    ),
    # and last the id list: six pairs of equal score, count and charge
    "smallest_id_list": (
        [("seg-t001", "a", "m", 10, 10), ("seg-t002", "b", "n", 10, 10),
         ("seg-t003", "c", "o", 10, 10), ("seg-t004", "d", "p", 10, 10)],
        20, 20000, ["seg-t001", "seg-t002"],
    ),
}


def test_the_plan_breaks_a_tie_the_way_the_release_states():
    """v1.9 orders equal-scoring plans; the graded tree never puts it to work.

    Each world below has several selections reaching the optimal score, and in
    each the link under test picks a different one from the links after it, so a
    planner that stops at "an optimum" or applies the chain out of order fails.
    """
    original_policy = POLICY_PATH.read_text(encoding="utf-8")
    original_manifest = REPAIRED_PATH.read_text(encoding="utf-8")
    manifest = json.loads(original_manifest)
    try:
        for label, (segments, mib, records, expected) in _TIES.items():
            staged = json.loads(original_manifest)
            staged["levels"]["0"] = _tie_world(segments)
            REPAIRED_PATH.write_text(
                json.dumps(staged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            policy = json.loads(original_policy)
            policy["merge_budget_mib"] = mib
            policy["merge_record_budget"] = records
            POLICY_PATH.write_text(
                json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            _, summary, _, plan = _run_pipeline(output_dir=WORK_DIR / f"tie_{label}")
            chosen = [row["segment"] for row in plan]
            assert chosen == expected, (
                f"{label}: the plan took {chosen}, not the {expected} that 1.9's "
                f"ordering names among the equally-scoring selections")
            assert summary["plan_charged_mib"] <= mib
            assert summary["plan_charged_records"] <= records
    finally:
        POLICY_PATH.write_text(original_policy, encoding="utf-8")
        REPAIRED_PATH.write_text(original_manifest, encoding="utf-8")
    assert json.loads(REPAIRED_PATH.read_text(encoding="utf-8")) == manifest


def test_the_shard_floor_and_the_plan_level_are_read_from_the_policy():
    """Both fields the contract names, at values that actually bind.

    The shipped policy sets the floor to one and the level to zero, where the
    smallest shard already carries over sixteen hundred keys, so neither field
    changes anything on the graded run and an engine ignoring both matched every
    fixture. These values make them bind: a floor above the natural window has
    to fold shards together without losing a key, and a different level has to
    plan over that level's segments instead of level zero's.
    """
    original = POLICY_PATH.read_text(encoding="utf-8")
    manifest = _load_json(REPAIRED_PATH)
    base_rows = _load_jsonl(BASE_PATH)
    try:
        # a floor well above the byte-balanced window size: 96 shards over this
        # base average under two thousand keys each, so 20,000 forces folding
        policy = json.loads(original)
        policy["min_shard_keys"] = 20_000
        POLICY_PATH.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _, summary, shards, _ = _run_pipeline(output_dir=WORK_DIR / "floor")
        assert shards, "the run emitted no shards at all"
        assert len(shards) < policy["shard_count"], (
            "the floor bound on this base but the shard count did not fall, so "
            "min_shard_keys was ignored")
        thin = [row["shard"] for row in shards if row["key_count"] < 20_000]
        assert not thin, f"shards below the raised floor: {thin}"
        # folding must not lose a key or a byte
        assert sum(row["key_count"] for row in shards) == len(base_rows)
        assert sum(row["value_bytes"] for row in shards) == sum(
            int(row["value_bytes"]) for row in base_rows)
        assert [row["shard"] for row in shards] == list(range(len(shards)))
        assert shards[0]["first_key"] == base_rows[0]["key"]
        assert shards[-1]["last_key"] == base_rows[-1]["key"]

        # a level the plan has never been asked for
        other = next(lvl for lvl in sorted(manifest["levels"]) if lvl != "0")
        policy = json.loads(original)
        policy["plan_level"] = int(other)
        POLICY_PATH.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _, summary, _, plan = _run_pipeline(output_dir=WORK_DIR / "level")
        available = {s["id"] for s in manifest["levels"][other]}
        assert available, f"level {other} carries no segments to plan over"
        chosen = {row["segment"] for row in plan}
        assert chosen <= available, (
            f"the plan names segments outside level {other}, so plan_level was ignored")
        assert _digest(plan) != FIXTURE["primary"]["plan_digest"]
        # candidate_count is the set the planner chose from, so it follows
        # plan_level. Every other run here plans over level 0, where the planned
        # level's count and level 0's are the same number, so nothing separated
        # the two.
        assert summary["candidate_count"] == len(manifest["levels"][other]), (
            f"candidate_count stayed on level 0 with plan_level at {other}, "
            "though the contract counts the entries at the level plan_level names")
    finally:
        POLICY_PATH.write_text(original, encoding="utf-8")


def test_the_shard_floor_holds_where_one_value_dominates_the_base():
    """The floor's hard case: a first value that meets every later target at once.

    Six keys, the first carrying a hundred bytes against one byte each for the
    rest, split four ways under a floor of two. Shard one closes on the first
    key alone and falls below the floor, so its key carries forward -- and every
    later target is already met by those hundred bytes. A window that measures
    what it has taken from the last CLOSED boundary then takes no further key at
    all and folds the whole base into a single shard, which is a shard split in
    name only. Each shard closes at a key, so shard two reaches the second key,
    the carried window makes the floor and closes, and the base is really split.
    """
    original_policy = POLICY_PATH.read_text(encoding="utf-8")
    rows = [{"key": f"kk-{i:04d}", "value_bytes": 100 if i == 0 else 1,
             "version_count": 1, "level": 0, "segment": "seg-0000", "seq": 1 + i}
            for i in range(6)]
    staged = WORK_DIR / "dominant_base.jsonl"
    staged.write_text("".join(
        json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")
    os.chmod(staged, 0o644)
    try:
        policy = json.loads(original_policy)
        policy["shard_count"] = 4
        policy["min_shard_keys"] = 2
        POLICY_PATH.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _, summary, shards, _ = _run_pipeline(
            input_path=staged, output_dir=WORK_DIR / "dominant")
    finally:
        POLICY_PATH.write_text(original_policy, encoding="utf-8")

    assert len(shards) > 1, (
        "the whole base landed in one shard: a window that cannot make the floor "
        "carried forward and then took nothing more")
    assert all(row["key_count"] >= 2 for row in shards), (
        f"a shard fell below the floor: {[row['key_count'] for row in shards]}")
    assert sum(row["key_count"] for row in shards) == len(rows)
    assert sum(row["value_bytes"] for row in shards) == 105
    assert [row["shard"] for row in shards] == list(range(len(shards)))
    assert shards[0]["first_key"] == rows[0]["key"]
    assert shards[-1]["last_key"] == rows[-1]["key"]
    assert summary["shard_count"] == len(shards)


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
    # the run happened over the reconciled base rather than some smaller stand-in
    assert summary["base_key_count"] == len(_load_jsonl(BASE_PATH))


# --------------------------------------------------------------------------
# The frozen snapshot
# --------------------------------------------------------------------------
# Everything the verifier keeps to itself: the reward channel, the sealed
# expectations, the held-out corpus and the suite that reads them. The probe
# below has to be refused every one of them.
PROBED_VERIFIER_ASSETS = [
    Path("/logs/verifier/reward.txt"),
    EXPECTED_FIXTURE,
    GOLDEN_CONTRACT_PATH,
    ALT_INPUT,
    Path("/tests/fixtures/shipped_base.json"),
    Path("/tests/test_outputs.py"),
    Path("/tests/fixtures"),
]


def test_submitted_program_runs_unprivileged_and_cannot_reach_verifier_assets():
    """The graded program runs as nobody and reaches nothing the verifier holds.

    Writing the reward was the only thing this ever probed, so it proved the
    score could not be forged and nothing about whether the answers could be
    read. A run that cannot write the reward but can read the sealed fixtures,
    the held-out corpus or this file has no need to solve anything.
    """
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK_DIR, 0o1777)
    # The probe lives in the shared work directory rather than a pytest tmp dir:
    # those sit under a root-only parent that uid 65534 cannot traverse.
    probe = WORK_DIR / "probe.py"
    probe.write_text(
        "import os\n"
        "print(os.getuid())\n"
        "try:\n"
        "    open('/logs/verifier/reward.txt', 'w').write('1')\n"
        "    print('writable')\n"
        "except OSError:\n"
        "    print('unwritable')\n"
        "for path in " + repr([str(q) for q in PROBED_VERIFIER_ASSETS]) + ":\n"
        "    try:\n"
        "        open(path, 'rb').read(1)\n"
        "        print('read ' + path)\n"
        "    except OSError:\n"
        "        print('denied ' + path)\n",
        encoding="utf-8",
    )
    os.chmod(probe, 0o644)
    result = _run_candidate(
        _SETPRIV + [
        sys.executable,
            str(probe),
        ],
        WORK_DIR,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    # exact line count, no blank-line filtering: a probe whose output is trimmed
    # into shape can be made to look like a pass it did not earn
    lines = result.stdout.split("\n")
    assert lines and lines[-1] == "", "the probe's output does not end in a newline"
    lines = lines[:-1]
    assert len(lines) == 2 + len(PROBED_VERIFIER_ASSETS), lines
    assert lines[0] == str(CANDIDATE_UID), lines[0]
    assert lines[1] == "unwritable", lines[1]
    for path, line in zip(PROBED_VERIFIER_ASSETS, lines[2:]):
        assert line == f"denied {path}", (
            f"code run as the graded program reached {path}")


def test_original_snapshot_preserved():
    """The migration-branch engine must still be on disk, unmodified."""
    assert ORIGINAL_WORKFLOW_PATH.exists()
    digest = hashlib.sha256(ORIGINAL_WORKFLOW_PATH.read_bytes()).hexdigest()
    assert digest == FIXTURE["broken_engine_sha256"]


def test_original_snapshot_is_wrong():
    """The shipped engine must not already produce the graded outputs.

    What is being shown here is that the migration branch is wrong, not that it
    works: if it cannot even run to completion over the reconciled inputs it has
    certainly not produced the graded artifacts, so a non-zero exit settles the
    question rather than failing the submission for it.
    """
    target = WORK_DIR / "orig"
    try:
        _, summary, shards, plan = _run_pipeline(
            script_path=ORIGINAL_WORKFLOW_PATH, output_dir=target
        )
    except AssertionError:
        return
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


def test_shipped_contract_matches_the_golden_copy():
    """The output contract in the environment is unmodified.

    Field lists, container shapes and sort orders are golden metadata and are read
    from the verifier's own image; this proves the agent's copy still agrees with
    it, so the contract cannot be trimmed to weaken a schema check.
    """
    # instruction.md asks for the contract byte for byte, so the bytes are what
    # is compared: parsing both sides first accepted a re-indent or a key
    # reordering, which is not the file coming back unchanged.
    assert CONTRACT_PATH.read_bytes() == GOLDEN_CONTRACT_PATH.read_bytes(), (
        "the shipped contract differs from the golden copy; it must come back "
        "byte for byte, not merely parse to the same document")
    # kept as a second, narrower reading of the same requirement
    assert json.loads(CONTRACT_PATH.read_text(encoding="utf-8")) == json.loads(
        GOLDEN_CONTRACT_PATH.read_text(encoding="utf-8"))


def _utf16_key(value: str) -> bytes:
    """The order the 1.5 client library reported: UTF-16 code units."""
    return value.encode("utf-16-be", "surrogatepass")


def test_a_pending_segment_with_no_trailer_at_all_is_discarded():
    """v1.7 names three admission conditions and only two were ever reached.

    Every pending segment used to carry a trailer, so an engine that checked the
    record count and the checksum but never asked whether a trailer was there
    graded identical to one that did. seg-0094 is a body and nothing else.
    """
    raw = (PENDING_DIR / "seg-0094.jsonl").read_text(encoding="utf-8")
    assert raw.endswith("\n") and not raw.endswith("\n\n"), (
        "seg-0094 does not end in a single newline")
    lines = raw.split("\n")[:-1]
    assert lines, "seg-0094 is empty"
    # every line is taken as it stands: a segment file carries one record per
    # line and nothing else, so a blank line is a fault to report rather than
    # something to skip past
    for number, line in enumerate(lines, start=1):
        assert line.strip(), f"seg-0094 line {number} is blank"
        record = json.loads(line)
        assert not record.get("trailer"), f"seg-0094 line {number} is a trailer"
    repaired = _load_json(REPAIRED_PATH)
    assert "seg-0094" in repaired["discarded_segments"], (
        "a pending segment carrying no trailer was admitted")
    assert "seg-0094" not in {e["id"] for e in repaired["levels"]["0"]}
    keys = {row["key"] for row in _load_jsonl(BASE_PATH)}
    for record in (json.loads(line) for line in lines):
        assert record["k"] not in keys, (
            f"{record['k']} reached the base from a segment with no trailer")


def test_an_inadmissible_key_is_dropped_and_its_segment_still_admitted():
    """v1.4 drops three kinds of key at merge time, and none was in the corpus.

    The shipped bodies carried no empty key, none over 64 bytes encoded and none
    with a character below U+0020, so an engine that never validated a key at all
    produced the same base. seg-0095 carries one of each beside ordinary keys,
    and v1.4 is explicit that this is not an error: the records go, the segment
    stays.
    """
    raw = (PENDING_DIR / "seg-0095.jsonl").read_text(encoding="utf-8")
    assert raw.endswith("\n") and not raw.endswith("\n\n"), (
        "seg-0095 does not end in a single newline")
    lines = raw.split("\n")[:-1]
    for number, line in enumerate(lines, start=1):
        assert line.strip(), f"seg-0095 line {number} is blank"
    body = [json.loads(line) for line in lines]
    trailer = body.pop()
    assert trailer.get("trailer"), "seg-0095 has no trailer"

    # v1.4 names three ways a key fails admission. They are separated here so
    # each one is asserted present in the segment on its own, and so nothing in
    # this test reads as a filter that quietly drops a record: every body record
    # is placed in exactly one of the two lists below.
    empty, overlong, control, admissible = [], [], [], []
    for record in body:
        key = record["k"]
        if len(key) == 0:
            empty.append(key)
        elif len(key.encode("utf-8")) > 64:
            overlong.append(key)
        elif min((ord(ch) for ch in key), default=0x20) < 0x20:
            control.append(key)
        else:
            admissible.append(key)
    assert empty, "seg-0095 carries no empty key"
    assert overlong, "seg-0095 carries no key over 64 bytes encoded"
    assert control, "seg-0095 carries no key below U+0020"
    assert admissible, "seg-0095 carries no ordinary key to survive beside them"
    inadmissible = empty + overlong + control
    assert len(inadmissible) + len(admissible) == len(body)

    repaired = _load_json(REPAIRED_PATH)
    assert "seg-0095" in {e["id"] for e in repaired["levels"]["0"]}, (
        "the segment was discarded, though v1.4 says an inadmissible key is not "
        "an error and takes only itself out")
    keys = {row["key"] for row in _load_jsonl(BASE_PATH)}
    for key in inadmissible:
        assert key not in keys, f"the inadmissible key {key!r} reached the base"
    for key in admissible:
        assert key in keys, f"the admissible key {key!r} was dropped with the rest"


def test_the_base_follows_byte_order_where_the_two_collations_disagree():
    """v1.6 replaced the client library's UTF-16 order with raw UTF-8 byte order.

    The two agree across the whole basic multilingual plane, and every key the
    corpus used to carry was ASCII, so the rule could not be told from its
    predecessor anywhere in the graded data. seg-0095 carries a pair that
    reverses between them: U+FF3A encodes as EF BC BA and U+10000 as F0 90 80 80,
    so byte order puts the first ahead while UTF-16 puts the second ahead through
    its D800 lead surrogate.
    """
    keys = [row["key"] for row in _load_jsonl(BASE_PATH)]
    disagreeing = [(a, b) for a, b in zip(keys, keys[1:])
                   if (_byte_key(a) < _byte_key(b)) != (_utf16_key(a) < _utf16_key(b))]
    assert disagreeing, (
        "no two neighbouring keys order differently under the two collations, so "
        "this base cannot tell byte order from the UTF-16 order 1.6 withdrew")
    assert keys == sorted(keys, key=_byte_key), (
        "the base is not in byte order")
    assert keys != sorted(keys, key=_utf16_key), (
        "the base is also in UTF-16 order, so the two are not being separated")


def test_the_merge_breaks_a_seq_tie_on_the_greatest_segment_id():
    """v1.5's last link, which the shipped tree never put to work.

    No two level-0 segments shared a sequence number, so an engine that stopped
    at the level and the seq took the same winner as one that went on to the id.
    seg-0200 and seg-0201 sit at level 0 on the same seq and both carry
    dup:0000001; the greatest id wins it.
    """
    manifest = _load_json(MANIFEST_PATH)
    level0 = manifest["levels"]["0"]
    shared = [e for e in level0 if e["id"] in {"seg-0200", "seg-0201"}]
    assert len(shared) == 2, "the crafted pair is not in the shipped manifest"
    assert shared[0]["seq"] == shared[1]["seq"], "the pair does not share a seq"

    rows = {row["key"]: row for row in _load_jsonl(BASE_PATH)}
    assert "dup:0000001" in rows, "the contested key did not reach the base"
    assert rows["dup:0000001"]["segment"] == "seg-0201", (
        "the seq tie went to " + rows["dup:0000001"]["segment"] + ", not to the "
        "lexicographically greatest segment id v1.5 names")
    # both segments' own keys survive; only the contested one has a loser
    assert rows["only:seg-0200"]["segment"] == "seg-0200"
    assert rows["only:seg-0201"]["segment"] == "seg-0201"
