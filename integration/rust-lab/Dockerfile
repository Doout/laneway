# Disposable test toolchain. Do not publish or deploy as a Laneway service.
FROM rust:1.91-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 nftables iputils-ping jq procps wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --chmod=0755 ip /opt/rootless-lab/ip
