GOLANGCI_LINT_VERSION ?= v2.12.2

REALSTACK_COMPOSE ?= docker-compose.realstack.yml
REALSTACK_CLIENT_SECRET ?= realstack-client-secret
REALSTACK_PASSWORD ?= realstack-operator-password
REALSTACK_BASIC_PASSWORD ?= realstack-basic-password
REALSTACK_POLICY_TOKEN ?= realstack-policy-token

.PHONY: fmt test e2e e2e-docker integration-real oidc-smoke race vet lint security check

fmt:
	gofmt -w .

test:
	go test -shuffle=on ./...

e2e:
	go test -tags=integration -count=1 -shuffle=on ./...

e2e-docker:
	trap 'docker compose -f docker-compose.e2e.yml down -v' EXIT; docker compose -f docker-compose.e2e.yml up -d --wait && E2E_REDIS_URL=redis://127.0.0.1:6379/0 go test -tags=integration -count=1 -shuffle=on ./...

integration-real oidc-smoke:
	set -eu; trap 'docker compose -f $(REALSTACK_COMPOSE) down -v --remove-orphans' EXIT; export REALSTACK_CLIENT_SECRET='$(REALSTACK_CLIENT_SECRET)' REALSTACK_PASSWORD='$(REALSTACK_PASSWORD)' REALSTACK_BASIC_PASSWORD='$(REALSTACK_BASIC_PASSWORD)' REALSTACK_POLICY_TOKEN='$(REALSTACK_POLICY_TOKEN)'; docker compose -f $(REALSTACK_COMPOSE) down -v --remove-orphans; docker compose -f $(REALSTACK_COMPOSE) up --build --wait; go test -tags=integration,realstack -count=1 -shuffle=on ./internal/e2e

race:
	go test -race -shuffle=on ./...

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

security:
	govulncheck ./...

check: fmt test race vet lint
