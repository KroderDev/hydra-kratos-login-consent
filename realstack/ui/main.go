package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxFlowResponseBytes = 1 << 20
	maxFlowIDLength      = 128
	maxHandoffValue      = 256
)

type uiServer struct {
	client         *http.Client
	kratosInternal *url.URL
	kratosBrowser  *url.URL
	provider       *url.URL
	uiBrowser      *url.URL
	loginAAL       string
}

type flowPage struct {
	Title  string
	Action string
	Method string
	FlowID string
	Fields []formField
}

type consentPage struct {
	Action string
	Fields []formField
}

type formField struct {
	Name     string
	Type     string
	Value    string
	Label    string
	Hidden   bool
	Submit   bool
	Checked  bool
	Required bool
}

var flowPageTemplate = template.Must(template.New("flow").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title></head>
<body>
<main>
<h1>{{.Title}}</h1>
<form method="{{.Method}}" action="{{.Action}}">
{{range .Fields}}
{{if .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{else if .Submit}}<button type="submit" name="{{.Name}}" value="{{.Value}}">{{.Label}}</button>
{{else}}<label>{{.Label}}<input type="{{.Type}}" name="{{.Name}}" value="{{.Value}}"{{if .Checked}} checked{{end}}{{if .Required}} required{{end}}></label>
{{end}}
{{end}}
</form>
</main>
</body>
</html>`))

var consentPageTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Consent</title></head>
<body>
<main>
<h1>Consent</h1>
<form method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<input type="hidden" name="decision" value="accept"><button type="submit">approve</button>
</form>
<form method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<input type="hidden" name="decision" value="deny"><button type="submit">deny</button>
</form>
</main>
</body>
</html>`))

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	server, err := newUIServer()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.root)
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc("/login", server.login)
	mux.HandleFunc("/registration", server.registration)
	mux.HandleFunc("/settings", server.settings)
	mux.HandleFunc("/logout/complete", server.logoutComplete)
	mux.HandleFunc("/error", server.errorPage)
	httpServer := &http.Server{
		Addr:              ":3000",
		Handler:           server.securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return err
		}
	}
	return nil
}

func newUIServer() (*uiServer, error) {
	kratosInternal, err := requiredURL("KRATOS_INTERNAL_URL", "http://kratos:4433")
	if err != nil {
		return nil, err
	}
	kratosBrowser, err := requiredURL("KRATOS_BROWSER_URL", "http://127.0.0.1:4433")
	if err != nil {
		return nil, err
	}
	provider, err := requiredURL("PROVIDER_BROWSER_URL", "http://127.0.0.1:8080")
	if err != nil {
		return nil, err
	}
	uiBrowser, err := requiredURL("UI_BROWSER_URL", "http://127.0.0.1:3000")
	if err != nil {
		return nil, err
	}
	loginAAL := strings.ToLower(strings.TrimSpace(envOrDefault("KRATOS_LOGIN_AAL", "aal1")))
	if loginAAL != "aal1" && loginAAL != "aal2" {
		return nil, fmt.Errorf("KRATOS_LOGIN_AAL must be aal1 or aal2")
	}
	return &uiServer{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		kratosInternal: kratosInternal,
		kratosBrowser:  kratosBrowser,
		provider:       provider,
		uiBrowser:      uiBrowser,
		loginAAL:       loginAAL,
	}, nil
}

func (s *uiServer) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.redirect(w, r, s.browserEndpoint(s.uiBrowser, "/login", nil))
}

func (s *uiServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *uiServer) login(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	flow := strings.TrimSpace(query.Get("flow"))
	switch flow {
	case "login":
		s.startLogin(w, r)
	case "consent":
		s.renderConsent(w, r)
	case "logout":
		s.startLogout(w, r)
	case "":
		s.startStandaloneLogin(w, r)
	default:
		s.renderKratosFlow(w, r, "login", flow)
	}
}

func (s *uiServer) registration(w http.ResponseWriter, r *http.Request) {
	flowID := strings.TrimSpace(r.URL.Query().Get("flow"))
	if flowID == "" {
		s.redirect(w, r, s.browserEndpoint(s.kratosBrowser, "/self-service/registration/browser", url.Values{
			"return_to": {s.browserEndpoint(s.uiBrowser, "/login", nil)},
		}))
		return
	}
	s.renderKratosFlow(w, r, "registration", flowID)
}

func (s *uiServer) settings(w http.ResponseWriter, r *http.Request) {
	flowID := strings.TrimSpace(r.URL.Query().Get("flow"))
	if flowID == "" {
		returnTo := s.browserEndpoint(s.uiBrowser, "/settings", nil)
		s.redirect(w, r, s.browserEndpoint(s.kratosBrowser, "/self-service/settings/browser", url.Values{
			"return_to": {returnTo},
		}))
		return
	}
	s.renderKratosFlow(w, r, "settings", flowID)
}

func (s *uiServer) startStandaloneLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := s.browserEndpoint(s.uiBrowser, "/settings", nil)
	if value := strings.TrimSpace(r.URL.Query().Get("return_to")); value != "" {
		parsed, err := s.validateUIReturnTo(value)
		if err != nil {
			http.Error(w, "invalid return_to", http.StatusBadRequest)
			return
		}
		returnTo = parsed
	}
	s.redirect(w, r, s.browserEndpoint(s.kratosBrowser, "/self-service/login/browser", url.Values{
		"aal":       {s.loginAAL},
		"return_to": {returnTo},
	}))
}

func (s *uiServer) startLogin(w http.ResponseWriter, r *http.Request) {
	transaction, csrf, ok := handoffValues(r.URL.Query())
	if !ok {
		http.Error(w, "invalid login handoff", http.StatusBadRequest)
		return
	}
	loginAAL := s.loginAAL
	if value := strings.TrimSpace(r.URL.Query().Get("aal")); value != "" {
		loginAAL = strings.ToLower(value)
		if loginAAL != "aal1" && loginAAL != "aal2" {
			http.Error(w, "invalid login handoff", http.StatusBadRequest)
			return
		}
	}
	callback := s.providerCallback("/login/callback", transaction, csrf)
	query := url.Values{
		"aal":       {loginAAL},
		"return_to": {callback},
	}
	forceReauth, err := booleanQuery(r.URL.Query(), "force_reauth")
	if err != nil {
		http.Error(w, "invalid login handoff", http.StatusBadRequest)
		return
	}
	maxAge, hasMaxAge, err := maxAgeQuery(r.URL.Query())
	if err != nil {
		http.Error(w, "invalid login handoff", http.StatusBadRequest)
		return
	}
	// Kratos refreshes the browser session instead of accepting a stale one.
	if forceReauth || (hasMaxAge && maxAge >= 0) {
		query.Set("refresh", "true")
	}
	s.redirect(w, r, s.browserEndpoint(s.kratosBrowser, "/self-service/login/browser", query))
}

func (s *uiServer) startLogout(w http.ResponseWriter, r *http.Request) {
	transaction, csrf, ok := handoffValues(r.URL.Query())
	if !ok {
		http.Error(w, "invalid logout handoff", http.StatusBadRequest)
		return
	}
	returnTo := s.browserEndpoint(s.uiBrowser, "/logout/complete", url.Values{
		"transaction": {transaction},
		"csrf":        {csrf},
	})
	// The browser, rather than the UI server, owns the Kratos session cookie.
	s.redirect(w, r, s.browserEndpoint(s.kratosBrowser, "/self-service/logout/browser", url.Values{
		"return_to": {returnTo},
	}))
}

func (s *uiServer) logoutComplete(w http.ResponseWriter, r *http.Request) {
	transaction, csrf, ok := handoffValues(r.URL.Query())
	if !ok {
		http.Error(w, "invalid logout handoff", http.StatusBadRequest)
		return
	}
	action := s.providerEndpoint("/logout", nil)
	view := flowPage{
		Title:  "Logout",
		Action: action,
		Method: http.MethodPost,
		Fields: []formField{
			{Hidden: true, Name: "transaction", Value: transaction},
			{Hidden: true, Name: "csrf", Value: csrf},
		},
	}
	if err := flowPageTemplate.Execute(w, view); err != nil {
		return
	}
}

func (s *uiServer) renderConsent(w http.ResponseWriter, r *http.Request) {
	transaction, csrf, ok := handoffValues(r.URL.Query())
	if !ok {
		http.Error(w, "invalid consent handoff", http.StatusBadRequest)
		return
	}
	scopes, ok := safeScopes(r.URL.Query().Get("scope"))
	if !ok {
		http.Error(w, "invalid consent handoff", http.StatusBadRequest)
		return
	}
	audiences, ok := safeList(r.URL.Query().Get("audience"))
	if !ok {
		http.Error(w, "invalid consent handoff", http.StatusBadRequest)
		return
	}
	fields := []formField{
		{Hidden: true, Name: "transaction", Value: transaction},
		{Hidden: true, Name: "csrf", Value: csrf},
	}
	if r.URL.Query().Get("skip_consent") == "true" {
		fields = append(fields, formField{Hidden: true, Name: "skip_consent", Value: "true"})
	}
	for _, scope := range scopes {
		fields = append(fields, formField{Hidden: true, Name: "grant_scope", Value: scope})
	}
	for _, audience := range audiences {
		fields = append(fields, formField{Hidden: true, Name: "grant_audience", Value: audience})
	}
	if err := consentPageTemplate.Execute(w, consentPage{
		Action: s.providerEndpoint("/consent", nil),
		Fields: fields,
	}); err != nil {
		return
	}
}

func (s *uiServer) renderKratosFlow(w http.ResponseWriter, r *http.Request, kind, flowID string) {
	if !validFlowID(flowID) {
		http.Error(w, "invalid flow", http.StatusBadRequest)
		return
	}
	flow, err := s.getKratosFlow(r, kind, flowID, w)
	if err != nil {
		http.Error(w, "unable to load flow", http.StatusBadGateway)
		return
	}
	ui, ok := flow["ui"].(map[string]any)
	if !ok {
		http.Error(w, "invalid flow", http.StatusBadGateway)
		return
	}
	action, ok := s.flowAction(ui["action"], kind, flowID)
	if !ok {
		http.Error(w, "invalid flow action", http.StatusBadGateway)
		return
	}
	fields := safeFlowFields(ui["nodes"])
	if len(fields) == 0 {
		http.Error(w, "flow has no usable fields", http.StatusBadGateway)
		return
	}
	if err := flowPageTemplate.Execute(w, flowPage{
		Title:  flowTitle(kind),
		Action: action,
		Method: http.MethodPost,
		FlowID: flowID,
		Fields: fields,
	}); err != nil {
		return
	}
}

func (s *uiServer) getKratosFlow(r *http.Request, kind, flowID string, w http.ResponseWriter) (map[string]any, error) {
	if kind != "login" && kind != "registration" && kind != "settings" {
		return nil, errors.New("unsupported flow")
	}
	endpoint := s.browserEndpoint(s.kratosInternal, "/self-service/"+kind+"/flows", url.Values{"id": {flowID}})
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if cookie := kratosCookieHeader(r); cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	for _, value := range response.Header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", value)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("kratos flow returned status %d", response.StatusCode)
	}
	var flow map[string]any
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxFlowResponseBytes))
	if err := decoder.Decode(&flow); err != nil {
		return nil, err
	}
	return flow, nil
}

// flowAction accepts only a matching Kratos self-service action and rewrites its
// internal origin to the browser-visible Kratos origin.
func (s *uiServer) flowAction(value any, kind, flowID string) (string, bool) {
	raw, ok := value.(string)
	if !ok || strings.TrimSpace(raw) == "" {
		raw = s.browserEndpoint(s.kratosInternal, "/self-service/"+kind, url.Values{"flow": {flowID}})
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if !sameOrigin(parsed, s.kratosInternal) && !sameOrigin(parsed, s.kratosBrowser) {
		return "", false
	}
	if !strings.HasPrefix(parsed.Path, "/self-service/"+kind+"/") && parsed.Path != "/self-service/"+kind {
		return "", false
	}
	parsed.Scheme = s.kratosBrowser.Scheme
	parsed.Host = s.kratosBrowser.Host
	parsed.User = nil
	parsed.Fragment = ""
	if parsed.RawQuery == "" {
		parsed.RawQuery = url.Values{"flow": {flowID}}.Encode()
	} else if values, err := url.ParseQuery(parsed.RawQuery); err != nil || len(values["flow"]) != 1 || values.Get("flow") != flowID {
		return "", false
	}
	return parsed.String(), true
}

// safeFlowFields converts Kratos UI nodes through an explicit field allowlist;
// unknown and sensitive nodes are omitted.
func safeFlowFields(value any) []formField {
	nodes, ok := value.([]any)
	if !ok {
		return nil
	}
	fields := make([]formField, 0, len(nodes))
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			continue
		}
		attributes, ok := node["attributes"].(map[string]any)
		if !ok {
			continue
		}
		name := strings.TrimSpace(stringValue(attributes["name"]))
		inputType := strings.ToLower(strings.TrimSpace(stringValue(attributes["type"])))
		field, ok := safeFlowField(name, inputType, attributes)
		if ok {
			fields = append(fields, field)
		}
	}
	return fields
}

func safeFlowField(name, inputType string, attributes map[string]any) (formField, bool) {
	if sensitiveFlowField(name) {
		return formField{}, false
	}
	if name == "csrf_token" {
		return formField{
			Hidden: true,
			Name:   name,
			Value:  stringValue(attributes["value"]),
		}, true
	}
	switch name {
	case "identifier":
		if inputType != "email" && inputType != "text" {
			return formField{}, false
		}
		return formField{
			Name:     name,
			Type:     inputType,
			Value:    stringValue(attributes["value"]),
			Label:    "Identifier",
			Required: boolValue(attributes["required"]),
		}, true
	case "traits.email":
		if inputType != "email" && inputType != "text" {
			return formField{}, false
		}
		return formField{
			Name:     name,
			Type:     inputType,
			Value:    stringValue(attributes["value"]),
			Label:    "Email",
			Required: boolValue(attributes["required"]),
		}, true
	case "traits.name":
		if inputType != "text" {
			return formField{}, false
		}
		return formField{
			Name:     name,
			Type:     inputType,
			Value:    stringValue(attributes["value"]),
			Label:    "Name",
			Required: boolValue(attributes["required"]),
		}, true
	case "password":
		if inputType != "password" && inputType != "text" {
			return formField{}, false
		}
		return formField{
			Name:     name,
			Type:     "password",
			Label:    "Password",
			Required: boolValue(attributes["required"]),
		}, true
	case "totp_code":
		if inputType != "text" && inputType != "number" && inputType != "password" {
			return formField{}, false
		}
		return formField{
			Name:     name,
			Type:     "text",
			Label:    "Authenticator code",
			Required: boolValue(attributes["required"]),
		}, true
	}
	if inputType != "submit" || name != "method" {
		return formField{}, false
	}
	value := stringValue(attributes["value"])
	if value != "password" && value != "profile" && value != "totp" {
		return formField{}, false
	}
	return formField{
		Name:   name,
		Value:  value,
		Label:  value,
		Submit: true,
	}, true
}

func sensitiveFlowField(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "totp_secret") ||
		strings.Contains(name, "totp_url") ||
		strings.Contains(name, "recovery_code") ||
		strings.Contains(name, "recovery_codes") ||
		strings.Contains(name, "lookup_secret")
}

func handoffValues(query url.Values) (string, string, bool) {
	transaction := strings.TrimSpace(query.Get("transaction"))
	csrf := strings.TrimSpace(query.Get("csrf"))
	return transaction, csrf, validHandoffValue(transaction) && validHandoffValue(csrf)
}

func validHandoffValue(value string) bool {
	return value != "" && len(value) <= maxHandoffValue && !strings.ContainsAny(value, "\r\n")
}

func safeScopes(value string) ([]string, bool) {
	return safeListWithDefault(value, []string{"openid"})
}

func safeList(value string) ([]string, bool) {
	return safeListWithDefault(value, nil)
}

func safeListWithDefault(value string, defaultValue []string) ([]string, bool) {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return defaultValue, true
	}
	if len(parts) > 64 {
		return nil, false
	}
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 128 || strings.ContainsAny(part, "\r\n") {
			return nil, false
		}
		scopes = append(scopes, part)
	}
	return scopes, true
}

func booleanQuery(query url.Values, name string) (bool, error) {
	value := strings.TrimSpace(query.Get(name))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	return parsed, err
}

// maxAgeQuery returns max_age and whether it was present. Duplicate, blank,
// nonnumeric, and negative values are rejected.
func maxAgeQuery(query url.Values) (int64, bool, error) {
	values, ok := query["max_age"]
	if !ok {
		return 0, false, nil
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return 0, false, errors.New("invalid max_age")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(values[0]), 10, 64)
	if err != nil || value < 0 {
		return 0, false, errors.New("invalid max_age")
	}
	return value, true, nil
}

func validFlowID(value string) bool {
	if value == "" || len(value) > maxFlowIDLength || strings.ContainsAny(value, "\r\n/?#") {
		return false
	}
	return true
}

func (s *uiServer) providerCallback(path, transaction, csrf string) string {
	return s.providerEndpoint(path, url.Values{
		"transaction": {transaction},
		"csrf":        {csrf},
	})
}

func (s *uiServer) providerEndpoint(path string, query url.Values) string {
	return s.browserEndpoint(s.provider, path, query)
}

func (s *uiServer) browserEndpoint(base *url.URL, path string, query url.Values) string {
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawQuery = query.Encode()
	endpoint.Fragment = ""
	return endpoint.String()
}

// validateUIReturnTo permits only query-free login and settings URLs on the
// configured UI origin.
func (s *uiServer) validateUIReturnTo(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || !sameOrigin(parsed, s.uiBrowser) {
		return "", errors.New("invalid UI return_to")
	}
	if parsed.Path != "/login" && parsed.Path != "/settings" {
		return "", errors.New("invalid UI return_to")
	}
	return parsed.String(), nil
}

func (s *uiServer) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *uiServer) errorPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	http.Error(w, "flow failed", http.StatusBadRequest)
}

func requiredURL(name, fallback string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP URL without query or fragment", name)
	}
	return parsed, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func sameOrigin(value, origin *url.URL) bool {
	return value.Scheme == origin.Scheme && value.Host == origin.Host
}

func stringValue(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

// kratosCookieHeader forwards only the Kratos session and CSRF cookies needed
// to retrieve a browser flow.
func kratosCookieHeader(r *http.Request) string {
	values := make([]string, 0, len(r.Cookies()))
	for _, cookie := range r.Cookies() {
		if cookie.Name != "ory_kratos_session" && cookie.Name != "csrf_token" && !strings.HasPrefix(cookie.Name, "csrf_token_") && !strings.HasSuffix(cookie.Name, "_csrf_token") {
			continue
		}
		values = append(values, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(values, "; ")
}

func flowTitle(kind string) string {
	switch kind {
	case "login":
		return "Login"
	case "registration":
		return "Registration"
	case "settings":
		return "Settings"
	default:
		return "Flow"
	}
}

func (s *uiServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		formAction := strings.Join([]string{"'self'", browserOrigin(s.kratosBrowser), browserOrigin(s.provider)}, " ")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action "+formAction)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func browserOrigin(value *url.URL) string {
	if value == nil {
		return ""
	}
	return value.Scheme + "://" + value.Host
}
