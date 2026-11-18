# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS console
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@10.14.0 --activate && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build:live

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build-base
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway-healthcheck ./cmd/laneway-healthcheck
RUN mkdir -p /out/controller-state /out/relay-state /out/relay-public && chown 65532:65532 /out/controller-state /out/relay-state /out/relay-public

FROM build-base AS build-controller
ARG BINARY=laneway-controller
RUN test "${BINARY}" = laneway-controller && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway ./cmd/laneway-controller

FROM build-base AS build-admin
ARG BINARY=laneway
RUN test "${BINARY}" = laneway && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway ./cmd/laneway

FROM build-base AS build-relay
ARG BINARY=laneway-relay
RUN test "${BINARY}" = laneway-relay && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway ./cmd/laneway-relay

FROM scratch AS runtime
COPY --from=build-base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-base /out/laneway-healthcheck /usr/local/bin/laneway-healthcheck
COPY --from=build-base --chown=65532:65532 /out/controller-state /var/lib/laneway-controller
COPY --from=build-base --chown=65532:65532 /out/relay-state /var/lib/laneway-relay
COPY --from=build-base --chown=65532:65532 /out/relay-public /var/lib/laneway-public
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/laneway"]

FROM runtime AS controller
COPY --from=build-controller /out/laneway /usr/local/bin/laneway
COPY --from=console /src/web/dist /usr/share/laneway-console

FROM runtime AS relay
COPY --from=build-relay /out/laneway /usr/local/bin/laneway

# The operator CLI is the default; Go service images are explicit fixtures.
FROM runtime AS admin
COPY --from=build-admin /out/laneway /usr/local/bin/laneway
