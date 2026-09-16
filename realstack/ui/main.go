package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type server struct {
	client         *http.Client
	kratosURL      string
	kratosBrowser  string
	kratosLoginAAL string
	providerURL    string
}

func main() {
	s := &server{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		kratosURL:      envOrDefault("KRATOS_INTERNAL_URL", "http://kratos:4433"),
		kratosBrowser:  envOrDefault("KRATOS_BROWSER_URL", "http://localhost:4433"),
		kratosLoginAAL: envOrDefault("KRATOS_LOGIN_AAL", "aal1"),
		providerURL:    envOrDefault("PROVIDER_BROWSER_URL", "http://localhost:8080"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/settings", s.settings)
	mux.HandleFunc("/error", s.errorPage)
	log.Fatal(http.ListenAndServe(":3000", mux)) // #nosec G114 -- test-only local UI.
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	flow := strings.TrimSpace(r.URL.Query().Get("flow"))
	switch flow {
	case "":
		s.redirectToKratosLogin(w, r)
	case "login":
		s.redirectToKratosLogin(w, r)
	case "consent":
		s.renderConsent(w, r)
	case "logout":
		s.renderLogout(w, r)
	default:
		s.renderKratosFlow(w, r, "login", flow)
	}
}

func (s *server) settings(w http.ResponseWriter, r *http.Request) {
	flow := strings.TrimSpace(r.URL.Query().Get("flow"))
	if flow == "" {
		returnTo := r.URL.Query().Get("return_to")
		if returnTo == "" {
			returnTo = "http://localhost:3000/settings"
		}
		target := strings.TrimRight(s.kratosBrowser, "/") + "/self-service/settings/browser?" + url.Values{
			"return_to": {returnTo},
		}.Encode()
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	s.renderKratosFlow(w, r, "settings", flow)
}

func (s *server) redirectToKratosLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !s.allowedReturnTo(returnTo) {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	query := url.Values{"return_to": {returnTo}, "aal": {s.kratosLoginAAL}}
	target := strings.TrimRight(s.kratosBrowser, "/") + "/self-service/login/browser?" + query.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *server) renderKratosFlow(w http.ResponseWriter, r *http.Request, kind, flowID string) {
	flow, err := s.getKratosFlow(r, kind, flowID)
	if err != nil {
		http.Error(w, "unable to load flow", http.StatusBadGateway)
		return
	}
	ui, _ := flow["ui"].(map[string]any)
	action := stringValue(ui["action"])
	if action == "" {
		action = strings.TrimRight(s.kratosBrowser, "/") + "/self-service/" + kind + "?flow=" + url.QueryEscape(flowID)
	}
	action = strings.Replace(action, s.kratosURL, s.kratosBrowser, 1)
	method := strings.ToUpper(stringValue(ui["method"]))
	if method == "" {
		method = http.MethodPost
	}
	nodes, _ := ui["nodes"].([]any)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><html><head><meta name=\"kratos-flow\" content=\"%s\">", html.EscapeString(flowID))
	fmt.Fprint(w, "</head><body><form method=\""+html.EscapeString(method)+"\" action=\""+html.EscapeString(action)+"\">")
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			continue
		}
		attributes, _ := node["attributes"].(map[string]any)
		name := stringValue(attributes["name"])
		if name == "" {
			name = stringValue(attributes["id"])
		}
		if name == "" {
			continue
		}
		if sensitiveFlowField(name) {
			continue
		}
		inputType := stringValue(attributes["type"])
		value := stringValue(attributes["value"])
		if inputType == "submit" {
			label := value
			if label == "" {
				label = name
			}
			fmt.Fprintf(w, "<button type=\"submit\" name=\"%s\" value=\"%s\">%s</button>", html.EscapeString(name), html.EscapeString(value), html.EscapeString(label))
			continue
		}
		if inputType == "" {
			inputType = "text"
		}
		checked := ""
		if boolValue(attributes["checked"]) {
			checked = " checked"
		}
		required := ""
		if boolValue(attributes["required"]) {
			required = " required"
		}
		fmt.Fprintf(w, "<input type=\"%s\" name=\"%s\" value=\"%s\"%s%s>", html.EscapeString(inputType), html.EscapeString(name), html.EscapeString(value), checked, required)
	}
	fmt.Fprint(w, "<button type=\"submit\">submit</button></form></body></html>")
}

func (s *server) renderConsent(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	scopes := strings.Fields(query.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	formAction := strings.TrimRight(s.providerURL, "/") + "/consent"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><html><body><form method=\"post\" action=\""+html.EscapeString(formAction)+"\">")
	fmt.Fprintf(w, "<input type=\"hidden\" name=\"transaction\" value=\"%s\"><input type=\"hidden\" name=\"csrf\" value=\"%s\"><input type=\"hidden\" name=\"decision\" value=\"accept\">", html.EscapeString(query.Get("transaction")), html.EscapeString(query.Get("csrf")))
	if query.Get("skip_consent") == "true" {
		fmt.Fprint(w, "<input type=\"hidden\" name=\"skip_consent\" value=\"true\">")
	}
	for _, scope := range scopes {
		fmt.Fprintf(w, "<input type=\"hidden\" name=\"grant_scope\" value=\"%s\">", html.EscapeString(scope))
	}
	fmt.Fprint(w, "<button type=\"submit\">approve</button></form></body></html>")
}

func (s *server) renderLogout(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	formAction := strings.TrimRight(s.providerURL, "/") + "/logout"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><html><body><form method=\"post\" action=\""+html.EscapeString(formAction)+"\">")
	fmt.Fprintf(w, "<input type=\"hidden\" name=\"transaction\" value=\"%s\"><input type=\"hidden\" name=\"csrf\" value=\"%s\"><button type=\"submit\">logout</button></form></body></html>", html.EscapeString(query.Get("transaction")), html.EscapeString(query.Get("csrf")))
}

func (s *server) errorPage(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "kratos flow failed", http.StatusBadRequest)
}

func (s *server) getKratosFlow(r *http.Request, kind, flowID string) (map[string]any, error) {
	endpoint := strings.TrimRight(s.kratosURL, "/") + "/self-service/" + kind + "/flows?id=" + url.QueryEscape(flowID)
	// The host and path come from the fixed Kratos configuration; flowID is only
	// placed in the query string, so this cannot redirect the UI's upstream.
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil) // #nosec G704 -- fixed configured upstream; flowID is query-escaped.
	if err != nil {
		return nil, err
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	response, err := s.client.Do(request) // #nosec G704 -- request targets the fixed configured Kratos upstream.
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil, fmt.Errorf("kratos flow status %d", response.StatusCode)
	}
	var flow map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&flow); err != nil {
		return nil, err
	}
	return flow, nil
}

func (s *server) allowedReturnTo(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	provider, err := url.Parse(s.providerURL)
	return err == nil && parsed.Scheme == provider.Scheme && parsed.Host == provider.Host
}

func stringValue(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case float64:
		return fmt.Sprintf("%v", value)
	case bool:
		if value {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func sensitiveFlowField(name string) bool {
	switch strings.ToLower(name) {
	case "totp_secret", "totp_url", "recovery_codes":
		return true
	default:
		return false
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
