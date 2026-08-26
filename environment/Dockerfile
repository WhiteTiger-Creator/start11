FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV DEBIAN_FRONTEND=noninteractive

# Least-volatile layers first: fix the working directory before the apt layer so
# a change there never invalidates the WORKDIR layer.
WORKDIR /app

# The only step in this build that reaches the network, and a single transient
# mirror failure was enough to fail an image build and void a grading trial, so
# the fetch is retried rather than attempted once.
RUN set -eu; \
    delay=5; \
    for attempt in 1 2 3 4; do \
        if apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 \
                -o Acquire::https::Timeout=20 update \
            && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 \
                -o Acquire::https::Timeout=20 install -y --no-install-recommends \
                tmux asciinema; then \
            rm -rf /var/lib/apt/lists/*; \
            exit 0; \
        fi; \
        echo "apt attempt ${attempt} failed, retrying in ${delay}s" >&2; \
        rm -rf /var/lib/apt/lists/*; \
        sleep "${delay}"; \
        delay=$((delay * 2)); \
    done; \
    exit 1

# /app/data ships exactly as the interrupted compactor left it: a base carrying
# only the cold level it had finished, a repaired manifest that predates the
# nine segments sitting unlinked under /app/data/pending, and the segment files
# themselves.
COPY app/ /app/
RUN cp /app/workflow/rebuild_index.py /app/workflow/.rebuild_index.original \
    && chmod a-w /app/workflow/.rebuild_index.original
