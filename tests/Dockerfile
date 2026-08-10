FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

# Verifier dependencies, baked in (no network at trial time). Grading uses the
# stdlib only (json/hashlib/ast/subprocess/fractions) plus pytest.
RUN pip install --no-cache-dir \
        pytest==8.4.1 \
        pytest-json-ctrf==0.3.5

# Landing directory for the declared artifact (/app) collected from the agent's
# environment. Its parent must exist in the verifier image before the copy.
RUN mkdir -p /app

# Verifier-execution isolation: the submitted program runs under the unprivileged uid 65534
# (nobody). setpriv already ships in this base image; a world-writable scratch area lets the
# candidate write only there. /tests (held-out fixtures) and the reward path stay root-owned
# and unreadable/unwritable to the candidate.
RUN mkdir -p /candidate-work \
    && chmod 1777 /candidate-work

WORKDIR /tests
COPY test_outputs.py /tests/test_outputs.py
COPY test.sh /tests/test.sh
COPY fixtures/ /tests/fixtures/

# Keep the held-out fixtures readable only by root, so the unprivileged candidate cannot read
# expected outputs even though it can be handed staged inputs.
RUN chmod -R go-rwx /tests
