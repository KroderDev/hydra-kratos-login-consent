package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

type request struct {
	Version            string   `json:"version"`
	Operation          string   `json:"operation"`
	Subject            string   `json:"subject"`
	ClientID           string   `json:"client_id"`
	RequestedScopes    []string `json:"requested_scopes"`
	GrantedScopes      []string `json:"granted_scopes"`
	RequestedAudiences []string `json:"requested_audiences"`
	AAL                string   `json:"aal"`
	AMR                []string `json:"amr"`
}

func main() {
	token := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_TOKEN"))
	clientID := envOrDefault("REALSTACK_POLICY_CLIENT_ID", "realstack-client")
	deniedSubject := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_DENY_SUBJECT"))
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		if token == "" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		defer r.Body.Close()
		var input request
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		allowed := input.Version == "v1" && input.Subject != "" && input.ClientID == clientID && input.Subject != deniedSubject && (input.Operation == "login" || input.Operation == "consent") && input.AAL == "aal1" && contains(input.AMR, "password")
		if !allowed {
			writeDecision(w, false, nil, nil, nil)
			return
		}
		if input.Operation == "login" {
			writeDecision(w, true, nil, nil, map[string]any{})
			return
		}
		writeDecision(w, true, append([]string(nil), input.GrantedScopes...), append([]string(nil), input.RequestedAudiences...), map[string]any{
			"id_token": map[string]any{
				"email":     "policy@example.com",
				"role":      "operator",
				"sensitive": "not-allowlisted",
			},
			"access_token": map[string]any{
				"tenant": "tenant-realstack",
			},
		})
	})
	log.Fatal(http.ListenAndServe(":8090", mux)) // #nosec G114 -- test-only local policy.
}

func writeDecision(w http.ResponseWriter, allowed bool, scopes, audiences []string, claims map[string]any) {
	if scopes == nil {
		scopes = []string{}
	}
	if audiences == nil {
		audiences = []string{}
	}
	if claims == nil {
		claims = map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":           "v1",
		"allowed":           allowed,
		"granted_scopes":    scopes,
		"granted_audiences": audiences,
		"claims":            claims,
	})
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
