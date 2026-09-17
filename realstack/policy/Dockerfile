# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build

WORKDIR /src
COPY main.go .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags='-s -w' \
    -o /out/realstack-policy \
    ./main.go

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -S app \
    && adduser -S -G app -h /nonexistent -s /sbin/nologin app

COPY --from=build --chown=app:app /out/realstack-policy /realstack-policy

USER app:app
WORKDIR /nonexistent
EXPOSE 8090
ENTRYPOINT ["/realstack-policy"]
