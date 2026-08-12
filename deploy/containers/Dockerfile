# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS console
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@10.14.0 --activate && pnpm install --frozen-lockfile
COPY web/ ./
RUN VITE_LANEWAY_LIVE=true pnpm build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
ARG BINARY=laneway-relay
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X laneway.dev/laneway/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway ./cmd/${BINARY}
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X laneway.dev/laneway/internal/buildinfo.Version=${VERSION}" \
    -o /out/laneway-healthcheck ./cmd/laneway-healthcheck
RUN mkdir -p /out/controller-state /out/relay-state /out/relay-public && chown 65532:65532 /out/controller-state /out/relay-state /out/relay-public

FROM scratch
ARG BINARY=laneway-relay
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/laneway /usr/local/bin/laneway
COPY --from=build /out/laneway-healthcheck /usr/local/bin/laneway-healthcheck
COPY --from=console /src/web/dist /usr/share/laneway-console
COPY --from=build --chown=65532:65532 /out/controller-state /var/lib/laneway-controller
COPY --from=build --chown=65532:65532 /out/relay-state /var/lib/laneway-relay
COPY --from=build --chown=65532:65532 /out/relay-public /var/lib/laneway-public
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/laneway"]
