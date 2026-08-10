#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Step 1: reconcile the interrupted compaction ---------------------------
# The compactor died after merging the cold level, leaving nine segments on disk
# that the manifest never learned about and one of them torn. Rebuild
# /app/data/compacted_base.jsonl and /app/data/manifest_repaired.json under the
# rules the deployed release defines; the planner and the shard split are both
# wrong until this is done.

python3 "${SCRIPT_DIR}/reconcile_segments.py"

# --- Step 2: restore the index rebuild -------------------------------------

cp "${SCRIPT_DIR}/rebuild_index_fixed.py" /app/workflow/rebuild_index.py
python3 /app/workflow/rebuild_index.py --output-dir /app/output
