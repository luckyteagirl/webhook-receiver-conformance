# syntax=docker/dockerfile:1.7

FROM python:3.12.13-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12.13-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d AS runtime

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

RUN addgroup -g 65532 -S webhook \
    && adduser -u 65532 -S -D -H -h /home/webhook -G webhook webhook \
    && install -d -o 65532 -g 65532 /artifacts /project

COPY --from=build /wheels /wheels
RUN python -m pip install --no-deps /wheels/*.whl \
    && rm -rf /wheels /root/.cache

USER 65532:65532
WORKDIR /project

ENTRYPOINT ["webhook-conformance"]
CMD ["version"]
