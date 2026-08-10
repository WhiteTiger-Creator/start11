FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV DEBIAN_FRONTEND=noninteractive

# Least-volatile layers first: fix the working directory before the apt layer so
# a change there never invalidates the WORKDIR layer.
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tmux \
        asciinema \
    && rm -rf /var/lib/apt/lists/*

# /app/data ships exactly as the interrupted compactor left it: a base carrying
# only the cold level it had finished, a repaired manifest that predates the
# nine segments sitting unlinked under /app/data/pending, and the segment files
# themselves.
COPY app/ /app/
RUN cp /app/workflow/rebuild_index.py /app/workflow/.rebuild_index.original \
    && chmod a-w /app/workflow/.rebuild_index.original
