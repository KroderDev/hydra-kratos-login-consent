FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/realstack-policy ./main.go

FROM alpine:3.24.1
RUN apk upgrade --no-cache \
    && addgroup -S app \
    && adduser -S -G app -h /nonexistent -s /sbin/nologin app
COPY --from=build --chown=app:app /out/realstack-policy /realstack-policy
USER app:app
EXPOSE 8090
ENTRYPOINT ["/realstack-policy"]
