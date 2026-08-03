.PHONY: fmt test e2e e2e-docker race vet lint security check

fmt:
	gofmt -w .

test:
	go test -shuffle=on ./...

e2e:
	go test -tags=integration -count=1 -shuffle=on ./...

e2e-docker:
	trap 'docker compose -f docker-compose.e2e.yml down -v' EXIT; docker compose -f docker-compose.e2e.yml up -d --wait && E2E_REDIS_URL=redis://127.0.0.1:6379/0 go test -tags=integration -count=1 -shuffle=on ./...

race:
	go test -race -shuffle=on ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

security:
	govulncheck ./...

check: fmt test race vet lint
