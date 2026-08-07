# syntax=docker/dockerfile:1.9
FROM golang:1.26-alpine AS build
ARG BINARY=laneway-relay
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/laneway ./cmd/${BINARY}
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/laneway-healthcheck ./cmd/laneway-healthcheck
RUN mkdir -p /out/controller-state /out/relay-state && chown 65532:65532 /out/controller-state /out/relay-state

FROM scratch
ARG BINARY=laneway-relay
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/laneway /usr/local/bin/laneway
COPY --from=build /out/laneway-healthcheck /usr/local/bin/laneway-healthcheck
COPY --from=build --chown=65532:65532 /out/controller-state /var/lib/laneway-controller
COPY --from=build --chown=65532:65532 /out/relay-state /var/lib/laneway-relay
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/laneway"]
