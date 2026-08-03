// Command server runs the Hydra login and consent provider.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	inboundhttp "github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/inbound/http"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/hydra"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/kratos"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/policy"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/application"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger := newLogger(os.Getenv("LOG_LEVEL"))
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if err := validateStateConfiguration(cfg); err != nil {
		return err
	}
	adminToken := strings.TrimSpace(os.Getenv("HYDRA_ADMIN_TOKEN"))
	if secureEnvironment(cfg.Environment) && adminToken == "" {
		return fmt.Errorf("HYDRA_ADMIN_TOKEN is required outside development and test")
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			MaxConnsPerHost:       64,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	hydraClient, err := hydra.New(cfg.HydraAdminURL, httpClient, adminToken)
	if err != nil {
		return fmt.Errorf("create hydra client: %w", err)
	}
	kratosClient, err := kratos.New(cfg.KratosPublicURL, httpClient)
	if err != nil {
		return fmt.Errorf("create kratos client: %w", err)
	}
	transactionStore, closeState, err := newTransactionStore(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeState(); err != nil {
			slog.Error("close state store", "error", err)
		}
	}()
	readiness := []ports.Readiness{hydraClient, kratosClient}
	if checker, ok := transactionStore.(ports.Readiness); ok {
		readiness = append(readiness, checker)
	}
	subjectScopes, err := subjectScopeRules(os.Getenv("ALLOWED_SUBJECT_SCOPES"))
	if err != nil {
		return err
	}
	if secureEnvironment(cfg.Environment) && len(subjectScopes) == 0 {
		return fmt.Errorf("ALLOWED_SUBJECT_SCOPES is required outside development and test")
	}
	providerPolicy := policy.NewStaticWithScopes(
		csvValues(os.Getenv("ALLOWED_SUBJECTS")),
		clientIDs(cfg),
		subjectScopes,
		secureEnvironment(cfg.Environment),
	)
	service, err := application.NewService(cfg, application.Dependencies{
		Login:     hydraClient,
		Consent:   hydraClient,
		Logout:    hydraClient,
		Kratos:    kratosClient,
		State:     transactionStore,
		Policy:    providerPolicy,
		Readiness: readiness,
	})
	if err != nil {
		return fmt.Errorf("create provider service: %w", err)
	}
	api, err := inboundhttp.New(service, cfg, logger)
	if err != nil {
		return fmt.Errorf("create http api: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Info("starting provider", "address", cfg.ListenAddress)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
		return nil
	}
}

func newLogger(value string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func validateStateConfiguration(cfg config.Config) error {
	store := strings.ToLower(strings.TrimSpace(os.Getenv("STATE_STORE")))
	if store == "" {
		store = "memory"
	}
	if store != "memory" && store != "redis" {
		return fmt.Errorf("unsupported state_store %q: want memory or redis", store)
	}
	if store == "memory" && secureEnvironment(cfg.Environment) {
		return fmt.Errorf("memory state store cannot be used outside development and test")
	}
	if store == "redis" && strings.TrimSpace(os.Getenv("REDIS_URL")) == "" {
		return fmt.Errorf("REDIS_URL is required for redis state store")
	}
	if store == "redis" {
		if err := state.ValidateRedisURL(os.Getenv("REDIS_URL"), secureEnvironment(cfg.Environment)); err != nil {
			return err
		}
		if secureEnvironment(cfg.Environment) && strings.TrimSpace(os.Getenv("REDIS_KEY_PREFIX")) == "" {
			return fmt.Errorf("REDIS_KEY_PREFIX is required outside development and test")
		}
	}
	return nil
}

func newTransactionStore(cfg config.Config) (ports.TransactionStore, func() error, error) {
	store := strings.ToLower(strings.TrimSpace(os.Getenv("STATE_STORE")))
	if store == "" || store == "memory" {
		return state.NewMemoryStore(time.Now), func() error { return nil }, nil
	}
	keyPrefix := strings.TrimSpace(os.Getenv("REDIS_KEY_PREFIX"))
	if keyPrefix == "" {
		keyPrefix = "hydra-kratos-login-consent:" + strings.ToLower(strings.TrimSpace(cfg.Environment)) + ":transaction:"
	}
	redisStore, err := state.NewRedisStore(os.Getenv("REDIS_URL"), keyPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("create redis state store: %w", err)
	}
	return redisStore, redisStore.Close, nil
}

func secureEnvironment(environment string) bool {
	environment = strings.ToLower(strings.TrimSpace(environment))
	return environment != "" && environment != "development" && environment != "test"
}

func csvValues(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func subjectScopeRules(value string) (map[string]map[string][]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var rules map[string]map[string][]string
	if err := json.Unmarshal([]byte(value), &rules); err != nil {
		return nil, fmt.Errorf("parse allowed_subject_scopes: %w", err)
	}
	return rules, nil
}

func clientIDs(cfg config.Config) []string {
	ids := make([]string, 0, len(cfg.Clients))
	for id := range cfg.Clients {
		ids = append(ids, id)
	}
	return ids
}
