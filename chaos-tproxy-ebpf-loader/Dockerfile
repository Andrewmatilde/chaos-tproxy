# syntax=docker/dockerfile:1.6
#
# Multi-stage build for chaos-tproxy-ebpf-loader.
#
# Stages:
#   1. bpf-build    compile redirect.bpf.c -> redirect.bpf.o + bpf2go bindings
#   2. proxy-build  build the existing Rust chaos-tproxy binary
#   3. runtime      slim image with the Go loader + chaos-tproxy binary

ARG GO_VERSION=1.22
ARG DEBIAN=bookworm

############################################################
# Stage 1: bpf-build  (clang + libbpf + bpftool + go for bpf2go)
############################################################
FROM golang:${GO_VERSION}-${DEBIAN} AS bpf-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        libelf-dev \
        bpftool \
        ca-certificates \
        pkg-config \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY chaos-tproxy-ebpf-loader/ chaos-tproxy-ebpf-loader/

WORKDIR /src/chaos-tproxy-ebpf-loader
# Resolve dep tree (we ship go.mod only; lockfile materialized here).
RUN go mod tidy
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.15.0

# Generate the bpf2go bindings + compile the .o (bpf2go shells out to clang).
ENV BPF_CFLAGS="-O2 -g -Wall -Werror -nostdinc -I/usr/include -I/usr/include/$(uname -m)-linux-gnu -I/usr/include/bpf"
RUN cd internal/bpfload && \
    PATH=$PATH:$(go env GOPATH)/bin go generate ./...

# Build the loader binary.
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' \
    -o /out/chaos-tproxy-ebpf-loader ./cmd/loader

############################################################
# Stage 2: proxy-build (Rust nightly-2021-12-23 — same toolchain as the
# existing top-level Dockerfile; bullseye base because buster repos are EOL)
############################################################
FROM debian:bullseye-slim AS proxy-build

ENV DEBIAN_FRONTEND=noninteractive
ARG HTTPS_PROXY
ARG HTTP_PROXY
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY

RUN apt-get update && apt-get install -y \
        build-essential gcc curl git pkg-config ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain none -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /src
WORKDIR /src
# rustup auto-installs the toolchain pinned in rust-toolchain.toml.
RUN cargo build --release --bin chaos-tproxy

############################################################
# Stage 3: runtime
############################################################
FROM debian:${DEBIAN}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=proxy-build /src/target/release/chaos-tproxy /usr/local/bin/chaos-tproxy
COPY --from=bpf-build  /out/chaos-tproxy-ebpf-loader     /usr/local/bin/chaos-tproxy-ebpf-loader

ENTRYPOINT ["/usr/local/bin/chaos-tproxy-ebpf-loader"]
