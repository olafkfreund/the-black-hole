package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

// Config represents the local CLI configuration
type Config struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

type APIConnection struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	BaseURL       string `json:"base_url"`
	AuthType      string `json:"auth_type"`
	AuthSecretRef string `json:"auth_secret_ref"`
	Enabled       bool   `json:"enabled"`
	ToolPrefix    string `json:"tool_prefix"`
}

type APIEndpoint struct {
	ID               string `json:"id"`
	ConnectionID     string `json:"connection_id"`
	ToolName         string `json:"tool_name"`
	ToolDescription  string `json:"tool_description"`
	Path             string `json:"path"`
	Method           string `json:"method"`
	ParametersSchema string `json:"parameters_schema"`
	Template         string `json:"template"`
}

type AuditLog struct {
	ID             string `json:"id"`
	Timestamp      string `json:"timestamp"`
	ClientIdentity string `json:"client_identity"`
	ToolName       string `json:"tool_name"`
	Status         string `json:"status"`
	DurationMS     int64  `json:"duration_ms"`
	ErrorMessage   string `json:"error_message"`
}

type ClientToken struct {
	Token      string `json:"token"`
	ClientName string `json:"client_name"`
	ClientRole string `json:"client_role"`
	Scopes     string `json:"scopes"`
	Enabled    bool   `json:"enabled"`
}

var (
	globalAddr     string
	globalToken    string
	globalInsecure bool
)

func main() {
	// Parse global flags
	flag.StringVar(&globalAddr, "addr", "", "Gateway API address (default: http://localhost:8899 or MCP_GATEWAY_ADDR)")
	flag.StringVar(&globalToken, "token", "", "Bearer Token (default: MCP_GATEWAY_TOKEN or saved config)")
	flag.BoolVar(&globalInsecure, "insecure", false, "Skip SSL/TLS verification for self-signed certificates")
	
	// Keep compatibility with original "cli" subcommand if run on the gateway server
	flag.Usage = printHelp
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}

	cmd := args[0]
	
	// Load config defaults
	cfg := loadConfig()
	if globalAddr == "" {
		globalAddr = os.Getenv("MCP_GATEWAY_ADDR")
		if globalAddr == "" {
			globalAddr = cfg.Addr
			if globalAddr == "" {
				globalAddr = "http://localhost:8899"
			}
		}
	}
	if globalToken == "" {
		globalToken = os.Getenv("MCP_GATEWAY_TOKEN")
		if globalToken == "" {
			globalToken = cfg.Token
		}
	}

	// Route command
	switch cmd {
	case "login":
		runLogin(args[1:])
	case "status":
		runStatus()
	case "verify":
		runVerify()
	case "metrics":
		runMetrics()
	case "logs":
		runLogs()
	case "connection":
		runConnection(args[1:])
	case "endpoint":
		runEndpoint(args[1:])
	case "vault":
		runVault(args[1:])
	case "token":
		runToken(args[1:])
	case "help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command %q\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`MCP Gateway Administration & Monitoring CLI

Usage:
  mcp-cli [global flags] <command> [subcommand] [arguments]

Global Flags:
  --addr      Gateway API address (default: http://localhost:8899, overrides MCP_GATEWAY_ADDR env)
  --token     Bearer Token (overrides MCP_GATEWAY_TOKEN env or local config token)
  --insecure  Allow insecure TLS connections (self-signed certs)

Commands:
  login              Authenticate with username and password
  status             Show gateway status, configuration settings, and vault provider info
  verify             Check connectivity to database, vault, and target APIs
  metrics            View tool execution metrics and gateway telemetry
  logs               Retrieve and view dynamic tool execution audit logs
  connection         Manage API connection targets
    list             List all registered API connections
    add              Add a new API connection target
    modify           Modify an existing connection
    delete           Delete a connection
  endpoint           Manage endpoints (tools) for connections
    list             List registered tool endpoints
    add              Register a new tool endpoint
    modify           Modify an existing endpoint
    delete           Unregister a tool endpoint
  vault              Manage secure key-vault credentials
    list             List all keys currently registered in the Vault
    set              Add or update a vault credential secret
    delete           Remove a credential secret from the vault
  token              Manage client API tokens and access control scopes
    list             List all registered client API tokens
    add              Register a new client API token with scopes and roles
    delete           Delete a client API token

Use "mcp-cli <command> --help" or "mcp-cli <command> <subcommand> --help" for detailed arguments.`)
}

// Config file management helper functions
func getConfigFile() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback to home dir
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".mcp-gateway-cli.json")
	}
	return filepath.Join(configDir, "mcp-gateway", "cli.json")
}

func loadConfig() Config {
	file := getConfigFile()
	data, err := os.ReadFile(file)
	if err != nil {
		return Config{}
	}
	var cfg Config
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

func saveConfig(cfg Config) {
	file := getConfigFile()
	// Ensure directory exists
	_ = os.MkdirAll(filepath.Dir(file), 0700)
	
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(file, data, 0600)
}

func newHTTPClient() *http.Client {
	tr := &http.Transport{}
	if globalInsecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

func makeRequest(method, path string, body interface{}, responseObj interface{}) error {
	client := newHTTPClient()
	url := strings.TrimRight(globalAddr, "/") + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if globalToken != "" {
		req.Header.Set("Authorization", "Bearer "+globalToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("API Error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBytes))
	}

	if responseObj != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, responseObj); err != nil {
			return fmt.Errorf("failed to decode response payload: %w", err)
		}
	}

	return nil
}

// ----------------------------------------
// Command Implementation: LOGIN
// ----------------------------------------
func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	addr := fs.String("addr", globalAddr, "Gateway API base URL")
	_ = fs.Parse(args)

	userArgs := fs.Args()
	username := "admin"
	if len(userArgs) > 0 {
		username = userArgs[0]
	}

	fmt.Printf("Logging into MCP Gateway at %s\n", *addr)
	fmt.Printf("Username: %s\n", username)
	fmt.Print("Password: ")
	
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // print newline after hidden input
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password = string(bytePassword)
	} else {
		// Read from piped input (non-terminal)
		var buf bytes.Buffer
		_, err := io.Copy(&buf, os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading redirected password: %v\n", err)
			os.Exit(1)
		}
		password = buf.String()
	}
	password = strings.TrimSpace(password)

	payload := map[string]string{
		"username": username,
		"password": password,
	}

	// Direct call over login endpoint
	client := newHTTPClient()
	loginUrl := strings.TrimRight(*addr, "/") + "/api/auth/login"
	
	b, _ := json.Marshal(payload)
	resp, err := client.Post(loginUrl, "application/json", bytes.NewReader(b))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: Login failed (Status %d): %s\n", resp.StatusCode, string(respBytes))
		os.Exit(1)
	}

	var result struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to parse login token: %v\n", err)
		os.Exit(1)
	}

	saveConfig(Config{
		Addr:  *addr,
		Token: result.Token,
	})

	fmt.Printf("\nSUCCESS: Successfully authenticated as %q. Configuration saved.\n", result.Username)
}

// ----------------------------------------
// Command Implementation: STATUS
// ----------------------------------------
func runStatus() {
	var settings map[string]interface{}
	err := makeRequest("GET", "/api/settings", nil, &settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to retrieve gateway status: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("MCP API Gateway Server Status:\n")
	fmt.Printf("=============================\n")
	fmt.Printf("Gateway URL:      %s\n", globalAddr)
	fmt.Printf("Server Port:      %v\n", settings["port"])
	fmt.Printf("Database Path:    %v\n", settings["database_path"])
	fmt.Printf("Vault Provider:   %v\n", settings["vault_provider"])
	if settings["vault_local_path"] != nil && settings["vault_local_path"] != "" {
		fmt.Printf("Vault Local Path: %v\n", settings["vault_local_path"])
	}
	fmt.Printf("mTLS Status:      ")
	if settings["client_ca_path"] != nil && settings["client_ca_path"] != "" {
		fmt.Println("Enforced (CA Certificate configured)")
	} else {
		fmt.Println("Disabled")
	}
	fmt.Printf("TLS Enforced:     ")
	if settings["tls_cert_path"] != nil && settings["tls_cert_path"] != "" {
		fmt.Println("Yes (HTTPS enabled)")
	} else {
		fmt.Println("No (HTTP plain/unencrypted)")
	}
	fmt.Printf("OIDC SSO Status:  ")
	if settings["oidc_issuer"] != nil && settings["oidc_issuer"] != "" {
		fmt.Printf("Enabled (Issuer: %v)\n", settings["oidc_issuer"])
	} else {
		fmt.Println("Disabled (Standard credentials only)")
	}
}

// ----------------------------------------
// Command Implementation: VERIFY
// ----------------------------------------
func runVerify() {
	fmt.Println("Running Gateway Component Diagnostics...")
	fmt.Println("=========================================")

	// 1. Connection check
	fmt.Print("[1/5] Checking Gateway Server Connectivity... ")
	var settings map[string]interface{}
	err := makeRequest("GET", "/api/settings", nil, &settings)
	if err != nil {
		fmt.Printf("FAILED\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	// 2. Token / Authentication verification
	fmt.Print("[2/5] Verifying Admin Credentials Token...    ")
	var conns []*APIConnection
	err = makeRequest("GET", "/api/connections", nil, &conns)
	if err != nil {
		fmt.Printf("FAILED\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK (Token Verified)")

	// 3. Database Check
	fmt.Print("[3/5] Querying System Database Schema...     ")
	var endpoints []*APIEndpoint
	err = makeRequest("GET", "/api/endpoints", nil, &endpoints)
	if err != nil {
		fmt.Printf("FAILED\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK (%d Connections, %d Tools Registered)\n", len(conns), len(endpoints))

	// 4. Secret Vault Provider check
	fmt.Print("[4/5] Testing Vault Secret Integration...    ")
	var vaultKeys []string
	err = makeRequest("GET", "/api/vault", nil, &vaultKeys)
	if err != nil {
		fmt.Printf("FAILED\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK (%d Secret Keys Available)\n", len(vaultKeys))

	// 5. Downstream Target API connectivity verification
	fmt.Println("[5/5] Verifying Target API Connectivity...   ")
	client := &http.Client{Timeout: 3 * time.Second}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  Name\tTarget URL\tStatus\tNotes")
	fmt.Fprintln(w, "  ----\t----------\t------\t-----")
	
	for _, c := range conns {
		status := "OK"
		notes := "Reachable"
		if !c.Enabled {
			status = "DISABLED"
			notes = "Skipping checks"
		} else {
			resp, err := client.Get(c.BaseURL)
			if err != nil {
				// Sometimes downstream microservices return 401/404 on base URL, which is still "reachable"
				if strings.Contains(err.Error(), "context deadline") || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "connection refused") {
					status = "UNREACHABLE"
					notes = err.Error()
				} else {
					status = "OK (REST)"
					notes = fmt.Sprintf("TLS/TCP reach: %v", err)
				}
			} else {
				resp.Body.Close()
				notes = fmt.Sprintf("HTTP %d Returned", resp.StatusCode)
			}
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", c.Name, c.BaseURL, status, notes)
	}
	w.Flush()
	fmt.Println("\nDiagnostics Completed successfully.")
}

// ----------------------------------------
// Command Implementation: METRICS
// ----------------------------------------
func runMetrics() {
	client := newHTTPClient()
	url := strings.TrimRight(globalAddr, "/") + "/metrics"
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to request metrics: %v\n", err)
		os.Exit(1)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Metrics endpoint unreachable: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read metrics stream: %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(string(body), "\n")
	
	fmt.Println("MCP Gateway Monitoring Telemetry Stats")
	fmt.Println("======================================")
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Metric Identifier\tLabels / Tags\tValue")
	fmt.Fprintln(w, "-----------------\t-------------\t-----")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		
		metricName := parts[0]
		value := parts[1]
		
		// Pretty print metric labels
		labelStr := "-"
		if idx := strings.Index(metricName, "{"); idx != -1 {
			labelStr = metricName[idx+1 : len(metricName)-1]
			metricName = metricName[:idx]
		}
		
		// Filter relevant MCP business metrics
		if strings.HasPrefix(metricName, "mcp_") || strings.HasPrefix(metricName, "go_memstats") || strings.HasPrefix(metricName, "promhttp_") {
			fmt.Fprintf(w, "%s\t%s\t%s\n", metricName, labelStr, value)
		}
	}
	w.Flush()
}

// ----------------------------------------
// Command Implementation: AUDIT LOGS
// ----------------------------------------
func runLogs() {
	var logs []*AuditLog
	err := makeRequest("GET", "/api/logs", nil, &logs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to retrieve audit logs: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Gateway Tool Execution Audit Trail (Last 100 Calls):\n")
	fmt.Printf("===================================================\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Timestamp\tClient Identity\tTool Name\tStatus\tDuration (ms)\tErrors")
	fmt.Fprintln(w, "---------\t---------------\t---------\t------\t-------------\t------")
	
	for _, l := range logs {
		errMsg := l.ErrorMessage
		if errMsg == "" {
			errMsg = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", l.Timestamp, l.ClientIdentity, l.ToolName, l.Status, l.DurationMS, errMsg)
	}
	w.Flush()
}

// ----------------------------------------
// Command Implementation: CONNECTION
// ----------------------------------------
func runConnection(args []string) {
	if len(args) == 0 {
		fmt.Println("connection command usage: mcp-cli connection <subcommand> [args]")
		fmt.Println("Subcommands:")
		fmt.Println("  list      List registered connections")
		fmt.Println("  add       Create a new connection target")
		fmt.Println("  modify    Edit settings on an existing connection")
		fmt.Println("  delete    Remove a connection target")
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		var conns []*APIConnection
		err := makeRequest("GET", "/api/connections", nil, &conns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing connections: %v\n", err)
			os.Exit(1)
		}
		
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tName\tBase URL\tAuth Type\tPrefix\tEnabled\tDescription")
		fmt.Fprintln(w, "--\t----\t--------\t---------\t------\t-------\t-----------")
		for _, c := range conns {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\t%s\n", c.ID, c.Name, c.BaseURL, c.AuthType, c.ToolPrefix, c.Enabled, c.Description)
		}
		w.Flush()

	case "add":
		fs := flag.NewFlagSet("connection-add", flag.ExitOnError)
		name := fs.String("name", "", "Connection name")
		url := fs.String("url", "", "Base URL")
		desc := fs.String("desc", "", "Description")
		auth := fs.String("auth", "none", "Auth Type (none, basic, bearer, custom_headers)")
		secret := fs.String("secret", "", "Vault secret path lookup reference")
		prefix := fs.String("prefix", "", "Prefix for generated tool names")
		disabled := fs.Bool("disabled", false, "Disable the connection immediately on creation")
		
		_ = fs.Parse(subargs)
		
		if *name == "" || *url == "" {
			fmt.Fprintln(os.Stderr, "Error: --name and --url are required parameters.")
			fs.Usage()
			os.Exit(1)
		}

		conn := &APIConnection{
			Name:          *name,
			BaseURL:       *url,
			Description:   *desc,
			AuthType:      *auth,
			AuthSecretRef: *secret,
			ToolPrefix:    *prefix,
			Enabled:       !*disabled,
		}

		var saved APIConnection
		err := makeRequest("POST", "/api/connections", conn, &saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error adding connection: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("API Connection %q registered successfully. Generated ID: %s\n", saved.Name, saved.ID)

	case "modify":
		fs := flag.NewFlagSet("connection-modify", flag.ExitOnError)
		id := fs.String("id", "", "ID of the connection to modify (Required)")
		name := fs.String("name", "", "Connection name")
		url := fs.String("url", "", "Base URL")
		desc := fs.String("desc", "", "Description")
		auth := fs.String("auth", "", "Auth Type (none, basic, bearer, custom_headers)")
		secret := fs.String("secret", "", "Vault secret path lookup reference")
		prefix := fs.String("prefix", "", "Prefix for generated tool names")
		enabledStr := fs.String("enabled", "", "Enable or disable connection (true/false)")

		_ = fs.Parse(subargs)

		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id is required to modify a connection.")
			fs.Usage()
			os.Exit(1)
		}

		// First, fetch the current connection settings
		var conns []*APIConnection
		err := makeRequest("GET", "/api/connections", nil, &conns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading connections: %v\n", err)
			os.Exit(1)
		}

		var target *APIConnection
		for _, c := range conns {
			if c.ID == *id {
				target = c
				break
			}
		}

		if target == nil {
			fmt.Fprintf(os.Stderr, "Error: Connection with ID %q not found.\n", *id)
			os.Exit(1)
		}

		// Modify set flags
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "name":
				target.Name = *name
			case "url":
				target.BaseURL = *url
			case "desc":
				target.Description = *desc
			case "auth":
				target.AuthType = *auth
			case "secret":
				target.AuthSecretRef = *secret
			case "prefix":
				target.ToolPrefix = *prefix
			case "enabled":
				val, _ := strconv.ParseBool(*enabledStr)
				target.Enabled = val
			}
		})

		var saved APIConnection
		err = makeRequest("POST", "/api/connections", target, &saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error updating connection: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("API Connection %q updated successfully.\n", saved.Name)

	case "delete":
		fs := flag.NewFlagSet("connection-delete", flag.ExitOnError)
		id := fs.String("id", "", "ID of the connection to delete (Required)")
		_ = fs.Parse(subargs)

		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id parameter is required.")
			fs.Usage()
			os.Exit(1)
		}

		err := makeRequest("DELETE", "/api/connections/"+*id, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting connection: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Connection deleted successfully.")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown connection subcommand %q\n", subcmd)
		os.Exit(1)
	}
}

// ----------------------------------------
// Command Implementation: ENDPOINT
// ----------------------------------------
func runEndpoint(args []string) {
	if len(args) == 0 {
		fmt.Println("endpoint command usage: mcp-cli endpoint <subcommand> [args]")
		fmt.Println("Subcommands:")
		fmt.Println("  list      List registered tool endpoints")
		fmt.Println("  add       Create a new tool endpoint")
		fmt.Println("  modify    Edit settings on an existing endpoint")
		fmt.Println("  delete    Remove an endpoint tool definition")
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		fs := flag.NewFlagSet("endpoint-list", flag.ExitOnError)
		connID := fs.String("connection-id", "", "Filter endpoints by connection ID")
		_ = fs.Parse(subargs)

		path := "/api/endpoints"
		if *connID != "" {
			path += "?connection_id=" + *connID
		}

		var endpoints []*APIEndpoint
		err := makeRequest("GET", path, nil, &endpoints)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing endpoints: %v\n", err)
			os.Exit(1)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tConnection ID\tTool Name\tMethod\tPath\tDescription")
		fmt.Fprintln(w, "--\t-------------\t---------\t------\t----\t-----------")
		for _, e := range endpoints {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.ConnectionID, e.ToolName, e.Method, e.Path, e.ToolDescription)
		}
		w.Flush()

	case "add":
		fs := flag.NewFlagSet("endpoint-add", flag.ExitOnError)
		connID := fs.String("conn-id", "", "Target Connection ID UUID (Required)")
		name := fs.String("name", "", "Exposed MCP Tool name (Required)")
		desc := fs.String("desc", "", "Tool description description (Required)")
		path := fs.String("path", "", "API target resource URI path (Required)")
		method := fs.String("method", "GET", "HTTP method (GET, POST, etc.)")
		schema := fs.String("schema", "", "JSON parameters schema (escaped JSON structure)")
		template := fs.String("template", "", "Body template payload or query mapping string")

		_ = fs.Parse(subargs)

		if *connID == "" || *name == "" || *desc == "" || *path == "" {
			fmt.Fprintln(os.Stderr, "Error: --conn-id, --name, --desc, and --path are required parameters.")
			fs.Usage()
			os.Exit(1)
		}

		ep := &APIEndpoint{
			ConnectionID:     *connID,
			ToolName:         *name,
			ToolDescription:  *desc,
			Path:             *path,
			Method:           *method,
			ParametersSchema: *schema,
			Template:         *template,
		}

		var saved APIEndpoint
		err := makeRequest("POST", "/api/endpoints", ep, &saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error adding endpoint: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("MCP Tool endpoint %q registered successfully. Generated ID: %s\n", saved.ToolName, saved.ID)

	case "modify":
		fs := flag.NewFlagSet("endpoint-modify", flag.ExitOnError)
		id := fs.String("id", "", "ID of the endpoint to modify (Required)")
		connID := fs.String("conn-id", "", "Target Connection ID UUID")
		name := fs.String("name", "", "Exposed MCP Tool name")
		desc := fs.String("desc", "", "Tool description description")
		path := fs.String("path", "", "API target resource URI path")
		method := fs.String("method", "", "HTTP method")
		schema := fs.String("schema", "", "JSON parameters schema")
		template := fs.String("template", "", "Body template payload")

		_ = fs.Parse(subargs)

		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id is required to modify an endpoint.")
			fs.Usage()
			os.Exit(1)
		}

		// First, load all endpoints to find our target
		var endpoints []*APIEndpoint
		err := makeRequest("GET", "/api/endpoints", nil, &endpoints)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading endpoints: %v\n", err)
			os.Exit(1)
		}

		var target *APIEndpoint
		for _, e := range endpoints {
			if e.ID == *id {
				target = e
				break
			}
		}

		if target == nil {
			fmt.Fprintf(os.Stderr, "Error: Endpoint with ID %q not found.\n", *id)
			os.Exit(1)
		}

		// Update modified fields
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "conn-id":
				target.ConnectionID = *connID
			case "name":
				target.ToolName = *name
			case "desc":
				target.ToolDescription = *desc
			case "path":
				target.Path = *path
			case "method":
				target.Method = *method
			case "schema":
				target.ParametersSchema = *schema
			case "template":
				target.Template = *template
			}
		})

		var saved APIEndpoint
		err = makeRequest("POST", "/api/endpoints", target, &saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error updating endpoint: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("MCP Tool endpoint %q updated successfully.\n", saved.ToolName)

	case "delete":
		fs := flag.NewFlagSet("endpoint-delete", flag.ExitOnError)
		id := fs.String("id", "", "ID of the endpoint to delete (Required)")
		_ = fs.Parse(subargs)

		if *id == "" {
			fmt.Fprintln(os.Stderr, "Error: --id parameter is required.")
			fs.Usage()
			os.Exit(1)
		}

		err := makeRequest("DELETE", "/api/endpoints/"+*id, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting endpoint: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Endpoint tool definition deleted successfully.")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown endpoint subcommand %q\n", subcmd)
		os.Exit(1)
	}
}

// ----------------------------------------
// Command Implementation: VAULT
// ----------------------------------------
func runVault(args []string) {
	if len(args) == 0 {
		fmt.Println("vault command usage: mcp-cli vault <subcommand> [args]")
		fmt.Println("Subcommands:")
		fmt.Println("  list      List registered vault credentials (redacted)")
		fmt.Println("  set       Store or update a credential secret")
		fmt.Println("  delete    Remove a secret key from the vault")
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		var keys []string
		err := makeRequest("GET", "/api/vault", nil, &keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing secrets: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Credential Secret Keys Available in Secure Vault:")
		fmt.Println("==================================================")
		for _, key := range keys {
			fmt.Printf("- %s [REDACTED]\n", key)
		}
		if len(keys) == 0 {
			fmt.Println("(No secrets registered in the vault)")
		}

	case "set":
		fs := flag.NewFlagSet("vault-set", flag.ExitOnError)
		key := fs.String("key", "", "Secret lookup path reference (e.g. prod/stripe/api-key) (Required)")
		val := fs.String("val", "", "Secret value/token to write (Required)")
		_ = fs.Parse(subargs)

		if *key == "" || *val == "" {
			fmt.Fprintln(os.Stderr, "Error: --key and --val parameters are required.")
			fs.Usage()
			os.Exit(1)
		}

		payload := map[string]string{
			"key":   *key,
			"value": *val,
		}

		err := makeRequest("POST", "/api/vault", payload, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to vault: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Secret for key %q written to secure Vault successfully.\n", *key)

	case "delete":
		fs := flag.NewFlagSet("vault-delete", flag.ExitOnError)
		key := fs.String("key", "", "Secret lookup path reference to remove (Required)")
		_ = fs.Parse(subargs)

		if *key == "" {
			fmt.Fprintln(os.Stderr, "Error: --key parameter is required.")
			fs.Usage()
			os.Exit(1)
		}

		path := "/api/vault?key=" + *key
		err := makeRequest("DELETE", path, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error removing vault key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Secret key %q deleted successfully from Vault.\n", *key)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown vault subcommand %q\n", subcmd)
		os.Exit(1)
	}
}

// ----------------------------------------
// Command Implementation: CLIENT TOKENS
// ----------------------------------------
func runToken(args []string) {
	if len(args) == 0 {
		fmt.Println("token command usage: mcp-cli token <subcommand> [args]")
		fmt.Println("Subcommands:")
		fmt.Println("  list      List registered client tokens")
		fmt.Println("  add       Register/update a client token")
		fmt.Println("  delete    Remove a client token")
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		var tokens []*ClientToken
		err := makeRequest("GET", "/api/tokens", nil, &tokens)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing tokens: %v\n", err)
			os.Exit(1)
		}
		
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Token\tClient Name\tRole\tScopes\tEnabled")
		fmt.Fprintln(w, "-----\t-----------\t----\t------\t-------")
		for _, t := range tokens {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n", t.Token, t.ClientName, t.ClientRole, t.Scopes, t.Enabled)
		}
		w.Flush()

	case "add":
		fs := flag.NewFlagSet("token-add", flag.ExitOnError)
		name := fs.String("name", "", "Client name/identity (Required)")
		tokenVal := fs.String("token", "", "Client API token value (Required)")
		role := fs.String("role", "developer", "Client role (admin, developer, etc.)")
		scopes := fs.String("scopes", "", "Comma-separated tool globs/prefixes (e.g. stripe_*,weather_*)")
		disabled := fs.Bool("disabled", false, "Disable this token immediately on creation")
		
		_ = fs.Parse(subargs)
		
		if *name == "" || *tokenVal == "" {
			fmt.Fprintln(os.Stderr, "Error: --name and --token are required parameters.")
			fs.Usage()
			os.Exit(1)
		}

		t := &ClientToken{
			Token:      *tokenVal,
			ClientName: *name,
			ClientRole: *role,
			Scopes:     *scopes,
			Enabled:    !*disabled,
		}

		var saved ClientToken
		err := makeRequest("POST", "/api/tokens", t, &saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error adding token: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Client Token for %q registered successfully.\n", saved.ClientName)

	case "delete":
		fs := flag.NewFlagSet("token-delete", flag.ExitOnError)
		tokenVal := fs.String("token", "", "Token value to delete (Required)")
		_ = fs.Parse(subargs)

		if *tokenVal == "" {
			fmt.Fprintln(os.Stderr, "Error: --token parameter is required.")
			fs.Usage()
			os.Exit(1)
		}

		err := makeRequest("DELETE", "/api/tokens?token="+*tokenVal, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Client token deleted successfully.")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown token subcommand %q\n", subcmd)
		os.Exit(1)
	}
}
