# syntax=docker/dockerfile:1.7

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS runtime

ARG OCI_CREATED="1970-01-01T00:00:00Z"
ARG OCI_REVISION="local"
ARG OCI_SOURCE="local"
ARG OCI_VERSION="0.1.0"

LABEL org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="Local-first webhook receiver conformance harness" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="webhook-receiver-conformance" \
      org.opencontainers.image.version="${OCI_VERSION}"

ENV HOME=/home/webhook \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEBHOOK_CONFORMANCE_ARTIFACT_ROOT=/artifacts

RUN groupadd --gid 65532 webhook \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/webhook webhook \
    && install -d -o 65532 -g 65532 /artifacts /project

COPY --from=build /wheels /wheels
RUN python -m pip install --no-deps /wheels/*.whl \
    && rm -rf /wheels /root/.cache

USER 65532:65532
WORKDIR /project

ENTRYPOINT ["webhook-conformance"]
CMD ["version"]
