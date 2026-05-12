# syntax=docker/dockerfile:1.6
#
# chaos-tproxy iptables-redirect loader (istio-style).

ARG GO_VERSION=1.22
ARG DEBIAN=bookworm

############################################################
# go-build
############################################################
FROM golang:${GO_VERSION}-${DEBIAN} AS go-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY chaos-tproxy-iptables-loader/ chaos-tproxy-iptables-loader/

WORKDIR /src/chaos-tproxy-iptables-loader
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' \
    -o /out/chaos-tproxy-iptables-loader ./cmd/loader

############################################################
# proxy-build (Rust nightly-2021-12-23 on bullseye)
############################################################
FROM debian:bullseye-slim AS proxy-build

ENV DEBIAN_FRONTEND=noninteractive
ARG HTTPS_PROXY
ARG HTTP_PROXY
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY

RUN apt-get update && apt-get install -y \
        build-essential gcc curl git pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain nightly-2021-12-23 -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /src
WORKDIR /src
RUN cargo build --release --bin chaos-tproxy

############################################################
# runtime
############################################################
FROM debian:${DEBIAN}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=proxy-build /src/target/release/chaos-tproxy /usr/local/bin/chaos-tproxy
COPY --from=go-build /out/chaos-tproxy-iptables-loader /usr/local/bin/chaos-tproxy-iptables-loader

ENTRYPOINT ["/usr/local/bin/chaos-tproxy-iptables-loader"]
