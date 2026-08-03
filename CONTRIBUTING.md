# Contributing

## Requirements

- Go 1.26 or newer.
- `golangci-lint` for linting.
- `govulncheck` for dependency checks.

## Validation

Run the following before opening a change:

```text
gofmt -w .
go test -shuffle=on ./...
go test -race -shuffle=on ./...
go vet ./...
golangci-lint run ./...
govulncheck ./...
```

Do not add Docker or Kubernetes packaging until the runtime contract and
production state adapter are approved.

## Design Rules

- Keep application flows independent of HTTP and Ory SDK types.
- Add external integrations behind small interfaces.
- Keep Hydra and Kratos administrative credentials server-side.
- Add tests for rejected paths as well as successful flows.
- Do not commit secrets, tokens, or generated local configuration.
