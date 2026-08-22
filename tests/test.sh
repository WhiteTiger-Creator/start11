#!/bin/bash
set -uo pipefail

mkdir -p /logs/verifier
# The reward channel is root-only: the graded program runs as an unprivileged
# uid and must not be able to read it, let alone write it.
chmod 700 /logs/verifier
echo 0 > /logs/verifier/reward.txt
chmod 600 /logs/verifier/reward.txt

TEST_DIR="${TEST_DIR:-/tests}"

python -m pytest -o cache_dir=/tmp/pytest_cache \
  --ctrf /logs/verifier/ctrf.json "$TEST_DIR/test_outputs.py" -rA
rc=$?

if [ "$rc" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
