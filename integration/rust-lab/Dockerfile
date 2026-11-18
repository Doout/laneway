# Disposable test toolchain. Do not publish or deploy as a Laneway service.
FROM golang:1.26-bookworm AS go
FROM rust:1.91-bookworm
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" GOPATH=/go GOCACHE=/gobuild
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 nftables iputils-ping jq procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --chmod=0755 ip /opt/rootless-lab/ip
