# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS dependencies

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

FROM alpine:3.24.1 AS runtime

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
