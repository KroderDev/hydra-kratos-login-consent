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

Keep deployment packaging and platform examples aligned with
`docs/deployment.md`; do not add platform-specific resources that contradict
the documented runtime contract.

## Design Rules

- Keep application flows independent of HTTP and Ory SDK types.
- Add external integrations behind small interfaces.
- Keep Hydra and Kratos administrative credentials server-side.
- Add tests for rejected paths as well as successful flows.
- Do not commit secrets, tokens, or generated local configuration.
