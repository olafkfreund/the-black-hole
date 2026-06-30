package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/cache"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
)

// EgressPolicy controls which downstream hosts the gateway is permitted to call.
// It is the primary defense against SSRF (e.g. cloud metadata, internal services).
type EgressPolicy struct {
	Allowlist    []string // permitted hostnames; empty = any public host allowed
	AllowPrivate bool     // permit private/loopback/link-local targets (local/demo only)
}

type GatewayClient struct {
	vault       VaultProvider
	http        *http.Client
	egress      EgressPolicy
	secretCache *cache.TTLCache[string]
	respCache   *cache.TTLCache[string]
	maxRetries  int
}

// EnableSecretCache caches vault lookups for ttl to keep them off the per-call
// hot path. Use a short TTL since secret rotation is not event-driven here.
func (gc *GatewayClient) EnableSecretCache(ttl time.Duration) {
	gc.secretCache = cache.New[string](ttl)
}

// EnableResponseCache caches idempotent GET responses for ttl. Off by default.
func (gc *GatewayClient) EnableResponseCache(ttl time.Duration) {
	gc.respCache = cache.New[string](ttl)
}

// SetMaxRetries bounds retries for idempotent requests (transport errors / 5xx).
func (gc *GatewayClient) SetMaxRetries(n int) { gc.maxRetries = n }

// getSecret resolves a secret, consulting the secret cache when enabled.
func (gc *GatewayClient) getSecret(ctx context.Context, ref string) (string, error) {
	if v, ok := gc.secretCache.Get(ref); ok {
		return v, nil
	}
	val, err := gc.vault.GetSecret(ctx, ref)
	if err != nil {
		return "", err
	}
	gc.secretCache.Set(ref, val)
	return val, nil
}

type VaultProvider interface {
	GetSecret(ctx context.Context, secretName string) (string, error)
}

func NewGatewayClient(vp vault.VaultProvider, egress EgressPolicy) *GatewayClient {
	gc := &GatewayClient{
		vault:  vp,
		egress: egress,
	}

	baseDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// Connection pooling for throughput under concurrent load.
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		// Validate the actual connected IP at dial time. This closes the
		// DNS-rebinding TOCTOU window left by a name-only pre-check.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !egress.AllowPrivate {
				if ip, err := netip.ParseAddr(host); err == nil {
					ip = ip.Unmap()
					if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
						ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
						return nil, fmt.Errorf("blocked dial to non-public address %s", ip)
					}
				}
			}
			return baseDialer.DialContext(ctx, network, addr)
		},
	}

	gc.http = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		// Do not follow redirects automatically: a 3xx to an internal host
		// would bypass the egress check performed on the original URL.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return gc
}

// validateEgress enforces scheme, allowlist, and private-range restrictions on a
// resolved downstream URL before any request is dispatched.
func (gc *GatewayClient) validateEgress(reqURL *url.URL) error {
	if reqURL.Scheme != "http" && reqURL.Scheme != "https" {
		return fmt.Errorf("blocked URL scheme %q (only http/https allowed)", reqURL.Scheme)
	}

	host := reqURL.Hostname()
	if host == "" {
		return fmt.Errorf("blocked request: empty host")
	}

	// Enforce hostname allowlist when configured.
	if len(gc.egress.Allowlist) > 0 {
		allowed := false
		for _, h := range gc.egress.Allowlist {
			if strings.EqualFold(h, host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("blocked request: host %q is not in the egress allowlist", host)
		}
	}

	if gc.egress.AllowPrivate {
		return nil
	}

	// Resolve and reject private / loopback / link-local / unspecified targets.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host %q: %w", host, err)
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("blocked request to non-public address %s (host %q)", addr, host)
		}
	}
	return nil
}

// ExecuteCall renders the templates, fetches credentials, runs the request, and formats the output.
func (gc *GatewayClient) ExecuteCall(ctx context.Context, conn *storage.APIConnection, ep *storage.APIEndpoint, params map[string]interface{}) (string, error) {
	// 1. Resolve path template
	renderedPath := ep.Path
	for k, v := range params {
		placeholder := fmt.Sprintf("{{%s}}", k)
		renderedPath = strings.ReplaceAll(renderedPath, placeholder, fmt.Sprintf("%v", v))
	}

	fullURLStr := strings.TrimSuffix(conn.BaseURL, "/") + "/" + strings.TrimPrefix(renderedPath, "/")
	reqURL, err := url.Parse(fullURLStr)
	if err != nil {
		return "", fmt.Errorf("invalid rendered URL %q: %w", fullURLStr, err)
	}

	// SSRF guard: validate the destination before doing any work or attaching secrets.
	if err := gc.validateEgress(reqURL); err != nil {
		return "", fmt.Errorf("egress denied: %w", err)
	}

	// 2. Resolve query parameters from template if needed
	// (For GET requests, we can also automatically append unused parameters to the query string)
	if ep.Method == "GET" {
		query := reqURL.Query()
		for k, v := range params {
			// If the parameter was not used in the path template, add to query
			placeholder := fmt.Sprintf("{{%s}}", k)
			if !strings.Contains(ep.Path, placeholder) {
				query.Set(k, fmt.Sprintf("%v", v))
			}
		}
		reqURL.RawQuery = query.Encode()
	}

	// Response cache (idempotent GET only): serve a fresh cached body if present.
	cacheKey := ep.Method + " " + reqURL.String()
	if ep.Method == "GET" {
		if v, ok := gc.respCache.Get(cacheKey); ok {
			return v, nil
		}
	}

	// 3. Resolve Request Body if method permits and template is set
	var bodyReader io.Reader
	if ep.Method != "GET" && ep.Method != "DELETE" {
		renderedBody := ep.Template
		if renderedBody != "" {
			for k, v := range params {
				placeholder := fmt.Sprintf("{{%s}}", k)
				// If value is a string, let's replace but keep quotes.
				// For simple JSON replacement, we can serialize the value.
				serialized, err := json.Marshal(v)
				if err == nil {
					// Remove the surrounding quotes for standard placeholder if template has them,
					// or replace directly. We support both:
					// a) {"key": "{{value}}"} -> string replacement
					// b) {"key": {{value}}} -> raw json replacement
					rawVal := string(serialized)
					// If it is a string, rawVal will contain quotes, e.g. "my-val"
					// If the template has double quotes like "{{param}}", replace including quotes to prevent double quoting
					renderedBody = strings.ReplaceAll(renderedBody, fmt.Sprintf("\"{{%s}}\"", k), rawVal)
					renderedBody = strings.ReplaceAll(renderedBody, placeholder, strings.Trim(rawVal, "\""))
				}
			}
			bodyReader = bytes.NewReader([]byte(renderedBody))
		} else {
			// Default to encoding all params as a JSON body if no template is defined
			payload, err := json.Marshal(params)
			if err != nil {
				return "", fmt.Errorf("failed to encode body payload: %w", err)
			}
			bodyReader = bytes.NewReader(payload)
		}
	}

	// 4. Create HTTP request
	req, err := http.NewRequestWithContext(ctx, ep.Method, reqURL.String(), bodyReader)
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MCP-API-Gateway/1.0")

	// 5. Inject Authorization Credentials from Vault
	if conn.AuthType != "none" && conn.AuthSecretRef != "" {
		secretVal, err := gc.getSecret(ctx, conn.AuthSecretRef)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve authorization secret from vault: %w", err)
		}

		switch conn.AuthType {
		case "bearer":
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secretVal))
		case "basic":
			// Expects secret to be formatted as "username:password"
			parts := strings.SplitN(secretVal, ":", 2)
			if len(parts) == 2 {
				req.SetBasicAuth(parts[0], parts[1])
			} else {
				return "", fmt.Errorf("basic auth secret must be in 'username:password' format")
			}
		case "custom_headers":
			// Expects secret to be a JSON string representing map[string]string
			var headers map[string]string
			if err := json.Unmarshal([]byte(secretVal), &headers); err != nil {
				return "", fmt.Errorf("custom headers secret must be a valid JSON map: %w", err)
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		default:
			return "", fmt.Errorf("unsupported auth type: %s", conn.AuthType)
		}
	}

	// 6. Perform the request with bounded retries for idempotent methods.
	resp, respBody, err := gc.doWithRetry(ctx, req, ep.Method)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("target API returned error status %d: %s", resp.StatusCode, string(respBody))
	}

	// 7. Format final response output
	// Try to format JSON beautifully if it is JSON, otherwise return raw text.
	out := string(respBody)
	var prettyJSON bytes.Buffer
	if json.Unmarshal(respBody, &struct{}{}) == nil {
		if err := json.Indent(&prettyJSON, respBody, "", "  "); err == nil {
			out = prettyJSON.String()
		}
	}

	// Cache successful idempotent GET responses.
	if ep.Method == "GET" {
		gc.respCache.Set(cacheKey, out)
	}
	return out, nil
}

// isIdempotent reports whether a method is safe to retry on transient failure.
func isIdempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// doWithRetry executes the request, retrying idempotent methods on transport
// errors and 5xx responses with exponential backoff. Non-idempotent methods are
// attempted exactly once.
func (gc *GatewayClient) doWithRetry(ctx context.Context, req *http.Request, method string) (*http.Response, []byte, error) {
	attempts := 1
	if gc.maxRetries > 0 && isIdempotent(method) {
		attempts = gc.maxRetries + 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms, ... (capped), context-aware.
			backoff := time.Duration(100*(1<<(attempt-1))) * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := gc.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http request failed: %w", err)
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", readErr)
			continue
		}

		// Retry idempotent requests on transient upstream 5xx.
		if resp.StatusCode >= 500 && isIdempotent(method) && attempt < attempts-1 {
			lastErr = fmt.Errorf("target API returned status %d", resp.StatusCode)
			continue
		}

		return resp, respBody, nil
	}
	return nil, nil, lastErr
}
