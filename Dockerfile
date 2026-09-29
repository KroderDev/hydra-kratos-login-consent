# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS dependencies

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

FROM dependencies AS test

COPY . .
ARG RUN_INTEGRATION_TESTS=true
RUN if [ "$RUN_INTEGRATION_TESTS" = "true" ]; then go test -tags=integration -count=1 ./...; fi

FROM test AS builder
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags='-s -w' \
    -o /out/server \
    ./cmd/server

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime

RUN apk upgrade --no-cache \
    && addgroup -S app \
    && adduser -S -G app -h /nonexistent -s /sbin/nologin app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=app:app /out/server /server

USER app:app
WORKDIR /nonexistent

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --output-document=- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/server"]
