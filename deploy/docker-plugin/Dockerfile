# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src/go
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=${VERSION}" -o /out/laneway-docker-plugin ./cmd/laneway-docker-plugin

FROM alpine:3.22
RUN apk add --no-cache iproute2 nftables ca-certificates
COPY --from=build /out/laneway-docker-plugin /usr/bin/laneway-docker-plugin
