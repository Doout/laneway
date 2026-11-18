# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28
FROM docker.io/library/rust:1.91.1-alpine3.22@sha256:8efbfb788786eeb127adc581394349c5fb567712156e0f8c2e499acadbc23756 AS build
ARG VERSION=dev
WORKDIR /src
COPY rust/ ./rust/
COPY api/proto/ ./api/proto/
ENV CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_STRIP=symbols RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=/src=."
RUN cargo fetch --locked --manifest-path rust/Cargo.toml
RUN --network=none set -eu; \
    case "$VERSION" in ""|*[!0-9A-Za-z._+-]*) exit 1;; esac; \
    test "${#VERSION}" -le 64; \
    target="$(rustc -vV | sed -n 's/^host: //p')"; \
    case "$target" in aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;; *) exit 1;; esac; \
    LANEWAY_PRODUCT_VERSION="$VERSION" cargo build --offline --locked --release \
      --manifest-path rust/Cargo.toml --target "$target" -p laneway-docker-plugin; \
    install -m 0755 "rust/target/$target/release/laneway-docker-plugin" /usr/local/bin/laneway-docker-plugin

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache iproute2 nftables ca-certificates
COPY --from=build /usr/local/bin/laneway-docker-plugin /usr/bin/laneway-docker-plugin
