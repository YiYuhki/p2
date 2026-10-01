# syntax=docker/dockerfile:1
#
# Build context must be the directory that holds BOTH repos side by side
# (so the `replace ../../p1` in go.mod resolves), e.g.:
#
#   docker build -f p2/analyzer/Dockerfile -t secmail-analyzer .
#
# run from the parent of p1/ and p2/ (…/program).
#
# Unlike secmail's core image this one links libyara via cgo (CGO_ENABLED=1),
# which is exactly why the worker is its own module.

FROM golang:1.24-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends libyara-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# malengine (p1) is imported via the module replace directive.
COPY p1/ ./p1/
COPY p2/analyzer/ ./p2/analyzer/
WORKDIR /src/p2/analyzer
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/analyzer .

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libyara9 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 65532 nonroot
COPY --from=build /out/analyzer /usr/local/bin/analyzer
# Bundled YARA rules (optional): enable with -yara-dir /rules/yara.
COPY p1/rules/ /rules/
USER nonroot
ENTRYPOINT ["/usr/local/bin/analyzer"]
