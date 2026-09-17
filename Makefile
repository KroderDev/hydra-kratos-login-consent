GOLANGCI_LINT_VERSION ?= v2.13.2

.PHONY: fmt test e2e e2e-docker e2e-realstack race vet lint security check

fmt:
	gofmt -w .

test:
	go test -shuffle=on ./...

e2e:
	go test -tags=integration -count=1 -shuffle=on ./...

e2e-docker:
	trap 'docker compose -f docker-compose.e2e.yml down -v' EXIT; docker compose -f docker-compose.e2e.yml up -d --wait && E2E_REDIS_URL=redis://127.0.0.1:6379/0 go test -tags=integration -count=1 -shuffle=on ./...

e2e-realstack:
	@set -eu; \
	project="$${COMPOSE_PROJECT_NAME:-hydra-realstack}"; \
	export REALSTACK_HYDRA_SYSTEM_SECRET="$${REALSTACK_HYDRA_SYSTEM_SECRET:-$$(openssl rand -hex 32)}"; \
	export REALSTACK_HYDRA_PAIRWISE_SALT="$${REALSTACK_HYDRA_PAIRWISE_SALT:-$$(openssl rand -hex 32)}"; \
	export REALSTACK_CLIENT_SECRET="$${REALSTACK_CLIENT_SECRET:-$$(openssl rand -hex 32)}"; \
	export REALSTACK_KRATOS_COOKIE_SECRET="$${REALSTACK_KRATOS_COOKIE_SECRET:-$$(openssl rand -hex 16)}"; \
	export REALSTACK_KRATOS_CIPHER_SECRET="$${REALSTACK_KRATOS_CIPHER_SECRET:-$$(openssl rand -hex 16)}"; \
	export REALSTACK_PASSWORD="$${REALSTACK_PASSWORD:-$$(openssl rand -hex 16)}"; \
	export REALSTACK_BASIC_PASSWORD="$${REALSTACK_BASIC_PASSWORD:-$$(openssl rand -hex 16)}"; \
	export REALSTACK_POLICY_TOKEN="$${REALSTACK_POLICY_TOKEN:-$$(openssl rand -hex 32)}"; \
	export REALSTACK_PROVIDER_PORT="$${REALSTACK_PROVIDER_PORT:-18080}"; \
	compose="docker compose -p $$project -f docker-compose.realstack.yml"; \
	$$compose down -v --remove-orphans >/dev/null 2>&1 || true; \
	trap 'status=$$?; $$compose down -v --remove-orphans >/dev/null 2>&1 || true; exit $$status' EXIT; \
	$$compose up -d --build --wait; \
	go test -tags=integration,realstack -count=1 -shuffle=on ./internal/e2e

race:
	go test -race -shuffle=on ./...

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

security:
	govulncheck ./...

check: fmt test race vet lint security
