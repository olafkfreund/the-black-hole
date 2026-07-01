package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/config"
	"github.com/calitti/mcp-api-gateway/pkg/gateway"
	"github.com/calitti/mcp-api-gateway/pkg/mcp"
	"github.com/calitti/mcp-api-gateway/pkg/portal"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/telemetry"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
	"github.com/google/uuid"
)

func main() {
	// 1. Parse command line flags
	stdioMode := flag.Bool("stdio", false, "Run in stdio mode as a local MCP server")
	flag.Parse()

	// 2. Load configurations (fails closed if required secrets are missing)
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// 3. Initialize storage
	db, err := storage.NewDB(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer db.Close()

	// Performance: short-TTL topology cache (busted on writes) + connection pool tuning.
	db.EnableConfigCache(cfg.ConfigCacheTTL)
	db.TunePool(cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, 30*time.Minute)

	// Seed demo data only when explicitly enabled (SEED_DEMO_DATA=true).
	if cfg.SeedDemoData {
		seedDatabase(context.Background(), db, cfg.Port)
	}

	// 4. Initialize Vault provider. The postgres vault encrypts secrets with
	// VAULT_ENCRYPTION_KEY (falling back to JWT_SECRET) and shares them across replicas.
	vaultKey := cfg.VaultEncryptionKey
	if vaultKey == "" {
		vaultKey = cfg.JWTSecret
	}
	vaultProvider, err := vault.InitVault(cfg.VaultProvider, cfg.VaultLocalPath, db.DB, vaultKey)
	if err != nil {
		log.Fatalf("Vault initialization failed: %v", err)
	}

	// 5. Check if running in administrative CLI mode
	if len(os.Args) > 1 && os.Args[1] == "cli" {
		runCLI(db, vaultProvider)
		return
	}

	// 6. Initialize Gateway client and Auth manager
	gatewayClient := gateway.NewGatewayClient(vaultProvider, gateway.EgressPolicy{
		Allowlist:    cfg.EgressAllowlist,
		AllowPrivate: cfg.EgressAllowPrivate,
	})
	// Performance/resilience: cache secrets + idempotent GET responses, bound retries.
	gatewayClient.EnableSecretCache(cfg.SecretCacheTTL)
	gatewayClient.EnableResponseCache(cfg.ResponseCacheTTL)
	gatewayClient.SetMaxRetries(cfg.DownstreamRetries)
	authManager := auth.NewAuthManager(cfg.JWTSecret, cfg.GatewayToken)

	// 7. Initialize MCP Server with vault capabilities
	mcpServer := mcp.NewMCPServer(db, gatewayClient, vaultProvider, authManager, cfg.CORSAllowedOrigins)

	// If stdio mode flag is set, run MCP over stdin/stdout directly
	if *stdioMode {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Run in background and listen for termination signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			cancel()
		}()

		mcpServer.StartStdioMode(ctx)
		return
	}

	// 8. Initialize OpenTelemetry Tracing & Prometheus metrics exporting
	tp, err := telemetry.InitTelemetry("mcp-api-gateway")
	if err != nil {
		log.Fatalf("Telemetry initialization failed: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down TracerProvider: %v", err)
		}
	}()

	// 9. Web / Portal & SSE service mode
	portalServer := portal.NewPortalServer(db, vaultProvider, authManager, cfg, mcpServer)

	mux := http.NewServeMux()

	// Register Admin Portal and API routes
	portalServer.RegisterRoutes(mux)

	// MCP endpoints. /sse dispatches by method so both transports work on one URL:
	//   GET    -> legacy HTTP+SSE stream (Claude Code type "sse")
	//   POST   -> Streamable HTTP request/response (Antigravity; Claude Code type "http")
	//   DELETE -> Streamable HTTP session termination (no-op; stateless)
	mux.HandleFunc("/sse", logMCP("sse", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			mcpServer.ServeStreamable(w, r)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			mcpServer.ServeSSE(w, r)
		}
	}))
	// Dedicated Streamable HTTP endpoint (stateless; scales across replicas).
	mux.HandleFunc("/mcp", logMCP("mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		mcpServer.ServeStreamable(w, r)
	}))
	mux.HandleFunc("/messages", logMCP("messages", mcpServer.ServeMessages))

	// Liveness: process is up. Readiness: dependencies (DB) are reachable so the
	// load balancer / HPA only routes to pods that can actually serve.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Register Prometheus metrics endpoint (OTel), optionally token-protected.
	mux.Handle("/metrics", metricsAuth(cfg.MetricsToken, telemetry.ServeMetrics()))

	// Load TLS & mTLS certificates (Enterprise security)
	tlsConfig, err := auth.LoadTLSConfig(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.ClientCAPath)
	if err != nil {
		log.Fatalf("TLS Configuration failed: %v", err)
	}

	server := &http.Server{
		Addr: ":" + cfg.Port,
		// Wrap with body-size limiting and a basic per-IP rate limiter (DoS defense).
		Handler:           rateLimit(limitBody(mux, 1<<20)),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Graceful shutdown setup
	idleConnsClosed := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server gracefully...")
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
		close(idleConnsClosed)
	}()

	if tlsConfig != nil {
		log.Printf("Janus API Gateway starting securely on HTTPS port %s (mTLS enabled: %v)...", cfg.Port, cfg.ClientCAPath != "")
		err = server.ListenAndServeTLS("", "")
	} else {
		log.Printf("Janus API Gateway starting on HTTP port %s (Warning: Traffic unencrypted)...", cfg.Port)
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		log.Fatalf("Server listen failed: %v", err)
	}

	<-idleConnsClosed
	log.Println("Server stopped.")
}

// logMCP logs how MCP clients negotiate the transport (method, path, Accept,
// User-Agent). Low volume; useful for diagnosing client compatibility.
func logMCP(label string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("MCP[%s] %s %s?%s Accept=%q UA=%q", label, r.Method, r.URL.Path, r.URL.RawQuery,
			r.Header.Get("Accept"), r.Header.Get("User-Agent"))
		next.ServeHTTP(w, r)
	}
}

// limitBody caps request body size to defend against memory-exhaustion DoS.
func limitBody(next http.Handler, max int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}

// metricsAuth optionally protects /metrics with a bearer token. If token is
// empty the endpoint is served unauthenticated (backward compatible).
func metricsAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		presented := ""
		if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
			presented = authHeader[7:]
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipRateLimiter is a minimal per-IP token-bucket limiter for basic DoS and
// brute-force protection. It is intentionally dependency-free; for multi-replica
// deployments use a shared limiter (e.g. Redis) instead.
type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*bucket
	rate     float64 // tokens per second
	burst    float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(rate, burst float64) *ipRateLimiter {
	return &ipRateLimiter{visitors: make(map[string]*bucket), rate: rate, burst: burst}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.visitors[ip]
	if !ok {
		l.visitors[ip] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var globalLimiter = newIPRateLimiter(50, 100) // ~50 req/s/IP, burst 100

func rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		}
		if !globalLimiter.allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runCLI processes command-line subcommands for dynamic operations management
func runCLI(db *storage.DB, vp vault.VaultProvider) {
	if len(os.Args) < 3 {
		fmt.Println("Janus API Gateway Configuration CLI")
		fmt.Println("Usage: mcp-gateway cli <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  connection-add --name <name> --url <url> --auth <auth> [--secret <secret>] [--prefix <prefix>]")
		fmt.Println("  connection-list")
		fmt.Println("  endpoint-add --conn <conn_id> --name <name> --desc <desc> --path <path> --method <method>")
		fmt.Println("  endpoint-list")
		fmt.Println("  vault-set --key <key> --val <value>")
		return
	}

	cmd := os.Args[2]
	ctx := context.Background()

	switch cmd {
	case "connection-list":
		conns, err := db.GetConnections(ctx)
		if err != nil {
			log.Fatalf("Error loading connections: %v", err)
		}
		fmt.Println("ID | Name | URL | AuthType | ToolPrefix | Enabled")
		for _, c := range conns {
			fmt.Printf("%s | %s | %s | %s | %s | %v\n", c.ID, c.Name, c.BaseURL, c.AuthType, c.ToolPrefix, c.Enabled)
		}

	case "connection-add":
		fs := flag.NewFlagSet("connection-add", flag.ExitOnError)
		name := fs.String("name", "", "Connection name")
		url := fs.String("url", "", "Base URL")
		auth := fs.String("auth", "none", "Auth type (none, basic, bearer, custom_headers)")
		secret := fs.String("secret", "", "Vault secret reference path")
		prefix := fs.String("prefix", "", "Tool prefix")
		_ = fs.Parse(os.Args[3:])

		if *name == "" || *url == "" {
			log.Fatal("Error: --name and --url are required parameters")
		}

		conn := &storage.APIConnection{
			ID:            uuid.New().String(),
			Name:          *name,
			BaseURL:       *url,
			AuthType:      *auth,
			AuthSecretRef: *secret,
			ToolPrefix:    *prefix,
			Enabled:       true,
		}
		if err := db.SaveConnection(ctx, conn); err != nil {
			log.Fatalf("Error saving connection: %v", err)
		}
		fmt.Printf("API Connection %q registered successfully. ID: %s\n", conn.Name, conn.ID)

	case "endpoint-list":
		eps, err := db.GetAllEndpoints(ctx)
		if err != nil {
			log.Fatalf("Error loading endpoints: %v", err)
		}
		fmt.Println("ID | ConnectionID | ToolName | Method | Path | Description")
		for _, e := range eps {
			fmt.Printf("%s | %s | %s | %s | %s | %s\n", e.ID, e.ConnectionID, e.ToolName, e.Method, e.Path, e.ToolDescription)
		}

	case "endpoint-add":
		fs := flag.NewFlagSet("endpoint-add", flag.ExitOnError)
		connID := fs.String("conn", "", "Target Connection ID UUID")
		name := fs.String("name", "", "Exposed MCP tool name")
		desc := fs.String("desc", "", "Tool description for the LLM")
		path := fs.String("path", "", "Target route URI path")
		method := fs.String("method", "GET", "HTTP Method (GET, POST, etc.)")
		_ = fs.Parse(os.Args[3:])

		if *connID == "" || *name == "" || *desc == "" || *path == "" {
			log.Fatal("Error: --conn, --name, --desc, and --path are required parameters")
		}

		ep := &storage.APIEndpoint{
			ID:              uuid.New().String(),
			ConnectionID:    *connID,
			ToolName:        *name,
			ToolDescription: *desc,
			Path:            *path,
			Method:          *method,
		}
		if err := db.SaveEndpoint(ctx, ep); err != nil {
			log.Fatalf("Error saving endpoint: %v", err)
		}
		fmt.Printf("MCP Tool %q registered successfully. ID: %s\n", ep.ToolName, ep.ID)

	case "vault-set":
		fs := flag.NewFlagSet("vault-set", flag.ExitOnError)
		key := fs.String("key", "", "Secret lookup path reference")
		val := fs.String("val", "", "Secret token value")
		_ = fs.Parse(os.Args[3:])

		if *key == "" || *val == "" {
			log.Fatal("Error: --key and --val are required parameters")
		}

		if err := vp.SetSecret(ctx, *key, *val); err != nil {
			log.Fatalf("Error storing secret: %v", err)
		}
		fmt.Printf("Secret key reference %q stored successfully in Vault.\n", *key)

	default:
		fmt.Printf("Error: Unknown CLI subcommand %q\n", cmd)
	}
}

func seedDatabase(ctx context.Context, db *storage.DB, port string) {
	conns, err := db.GetConnections(ctx)
	if err != nil {
		log.Printf("Warning: Seeding check failed: %v", err)
		return
	}
	if len(conns) > 0 {
		return
	}

	log.Println("Database empty. Seeding default LCH DPG, US Treasury, and Coinbase configurations...")

	// 1. Seed LCH Mock Services
	connID := uuid.New().String()
	conn := &storage.APIConnection{
		ID:            connID,
		Name:          "LCH DPG & Collateral Services",
		Description:   "Simulated downstream LCH services for DPG Trade Volumes and Non-Cash Collateral",
		BaseURL:       "http://127.0.0.1:" + port + "/api/mock",
		AuthType:      "none",
		AuthSecretRef: "",
		Enabled:       true,
		ToolPrefix:    "lch_",
	}
	if err := db.SaveConnection(ctx, conn); err != nil {
		log.Printf("Warning: Failed to seed connection: %v", err)
		return
	}

	// Seed endpoint: DPG Trade Volume
	ep1 := &storage.APIEndpoint{
		ID:               uuid.New().String(),
		ConnectionID:     connID,
		ToolName:         "get_dpg_trade_volume",
		ToolDescription:  "Retrieve daily trade volumes, trade counts, and currency breakdowns for a specific LCH member. Supported parameters: member_id (string), date (string, YYYY-MM-DD).",
		Path:             "/dpg/trade-volume",
		Method:           "GET",
		ParametersSchema: `{"type":"object","properties":{"member_id":{"type":"string","description":"Clearing member ID (e.g. MEM-LCH-001)"},"date":{"type":"string","description":"ISO Date YYYY-MM-DD (e.g. 2026-06-29)"}},"required":[]}`,
		Template:         "",
	}
	if err := db.SaveEndpoint(ctx, ep1); err != nil {
		log.Printf("Warning: Failed to seed trade volume endpoint: %v", err)
	}

	// Seed endpoint: Non Cash Collateral
	ep2 := &storage.APIEndpoint{
		ID:               uuid.New().String(),
		ConnectionID:     connID,
		ToolName:         "get_non_cash_collateral",
		ToolDescription:  "Query non-cash collateral asset breakdown, market values, haircuts, and ISIN codes held for a member. Supported parameters: member_id (string).",
		Path:             "/collateral/non-cash",
		Method:           "GET",
		ParametersSchema: `{"type":"object","properties":{"member_id":{"type":"string","description":"Clearing member ID (e.g. MEM-LCH-001)"}},"required":[]}`,
		Template:         "",
	}
	if err := db.SaveEndpoint(ctx, ep2); err != nil {
		log.Printf("Warning: Failed to seed non-cash collateral endpoint: %v", err)
	}

	// 2. Seed U.S. Treasury API
	treasuryConnID := uuid.New().String()
	treasuryConn := &storage.APIConnection{
		ID:            treasuryConnID,
		Name:          "U.S. Treasury API",
		Description:   "Real-time average interest rates and currency exchange rates from the official U.S. Treasury",
		BaseURL:       "https://api.fiscaldata.treasury.gov/services/api/fiscal_service",
		AuthType:      "none",
		AuthSecretRef: "",
		Enabled:       true,
		ToolPrefix:    "ustreasury_",
	}
	if err := db.SaveConnection(ctx, treasuryConn); err != nil {
		log.Printf("Warning: Failed to seed Treasury connection: %v", err)
	} else {
		epRates := &storage.APIEndpoint{
			ID:               uuid.New().String(),
			ConnectionID:     treasuryConnID,
			ToolName:         "get_avg_interest_rates",
			ToolDescription:  "Retrieve real-time average interest rates for U.S. Treasury marketable securities (Bills, Notes, Bonds).",
			Path:             "/v2/accounting/od/avg_interest_rates",
			Method:           "GET",
			ParametersSchema: `{"type":"object","properties":{"sort":{"type":"string","description":"Field to sort by, e.g. -record_date"},"filter":{"type":"string","description":"Filtering criteria, e.g. record_calendar_year:eq:2026"}},"required":[]}`,
			Template:         "",
		}
		if err := db.SaveEndpoint(ctx, epRates); err != nil {
			log.Printf("Warning: Failed to seed Treasury rates endpoint: %v", err)
		}

		epEx := &storage.APIEndpoint{
			ID:               uuid.New().String(),
			ConnectionID:     treasuryConnID,
			ToolName:         "get_rates_of_exchange",
			ToolDescription:  "Fetch official Treasury reporting rates of exchange for global currencies against USD.",
			Path:             "/v1/accounting/od/rates_of_exchange",
			Method:           "GET",
			ParametersSchema: `{"type":"object","properties":{"sort":{"type":"string","description":"Field to sort by, e.g. -record_date"},"filter":{"type":"string","description":"Filtering criteria, e.g. currency:eq:Euro"}},"required":[]}`,
			Template:         "",
		}
		if err := db.SaveEndpoint(ctx, epEx); err != nil {
			log.Printf("Warning: Failed to seed Treasury exchange rates endpoint: %v", err)
		}
	}

	// 3. Seed Coinbase Exchange API
	coinbaseConnID := uuid.New().String()
	coinbaseConn := &storage.APIConnection{
		ID:            coinbaseConnID,
		Name:          "Coinbase Exchange API",
		Description:   "Real-time trading volume and currency stats from Coinbase Pro Exchange",
		BaseURL:       "https://api.exchange.coinbase.com",
		AuthType:      "none",
		AuthSecretRef: "",
		Enabled:       true,
		ToolPrefix:    "coinbase_",
	}
	if err := db.SaveConnection(ctx, coinbaseConn); err != nil {
		log.Printf("Warning: Failed to seed Coinbase connection: %v", err)
	} else {
		epBTC := &storage.APIEndpoint{
			ID:               uuid.New().String(),
			ConnectionID:     coinbaseConnID,
			ToolName:         "get_btc_stats",
			ToolDescription:  "Fetch real-time 24h trading statistics, volume, open/high/low/last prices for BTC-USD.",
			Path:             "/products/BTC-USD/stats",
			Method:           "GET",
			ParametersSchema: `{"type":"object","properties":{},"required":[]}`,
			Template:         "",
		}
		if err := db.SaveEndpoint(ctx, epBTC); err != nil {
			log.Printf("Warning: Failed to seed Coinbase BTC stats endpoint: %v", err)
		}

		epETH := &storage.APIEndpoint{
			ID:               uuid.New().String(),
			ConnectionID:     coinbaseConnID,
			ToolName:         "get_eth_stats",
			ToolDescription:  "Fetch real-time 24h trading statistics, volume, open/high/low/last prices for ETH-USD.",
			Path:             "/products/ETH-USD/stats",
			Method:           "GET",
			ParametersSchema: `{"type":"object","properties":{},"required":[]}`,
			Template:         "",
		}
		if err := db.SaveEndpoint(ctx, epETH); err != nil {
			log.Printf("Warning: Failed to seed Coinbase ETH stats endpoint: %v", err)
		}
	}

	// Client tokens are intentionally NOT seeded. A seeded, well-known token with
	// wildcard scope is a backdoor. Create tokens explicitly via the portal
	// (POST /api/tokens) or the CLI; the master GATEWAY_TOKEN can be used for
	// initial admin access.
	log.Println("Demo seeding complete (no client tokens seeded).")
}
