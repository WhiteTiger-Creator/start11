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

# Nothing the graded programs left running is alive when the reward is written.
# A submitted child that called setsid escapes its process group, and the suite
# reaps by owner after every run, but the reward channel is the one place where
# a survivor would matter most -- so the sweep is repeated here, as root, before
# the value is written. Done through python rather than pkill, which lives in
# procps and is not in this slim image.
python - <<'SWEEP' || true
import os, signal, time
UID = 65534
def owned():
    out = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if os.stat("/proc/" + entry).st_uid == UID:
                    out.append(int(entry))
            except OSError:
                pass
    return out
for _ in range(50):
    pids = owned()
    if not pids:
        break
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    time.sleep(0.1)
SWEEP

if [ "$rc" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
