package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
	driver string
}

type APIConnection struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	BaseURL       string `json:"base_url"`
	AuthType      string `json:"auth_type"` // 'none', 'basic', 'bearer', 'custom_headers', 'oauth2'
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
	ParametersSchema string `json:"parameters_schema"` // JSON Schema string
	Template         string `json:"template"`          // Query/Body template string
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
	Scopes     string `json:"scopes"` // Comma-separated globs/prefixes (e.g., 'stripe_*,weather_*' or '*')
	Enabled    bool   `json:"enabled"`
}

func NewDB(dbPath string) (*DB, error) {
	driver := "sqlite3"
	if strings.HasPrefix(dbPath, "postgres://") || strings.HasPrefix(dbPath, "postgresql://") {
		driver = "postgres"
	}

	db, err := sql.Open(driver, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &DB{DB: db, driver: driver}
	if err := d.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return d, nil
}

func (d *DB) query(q string) string {
	if d.driver == "postgres" {
		var result strings.Builder
		paramIndex := 1
		for _, r := range q {
			if r == '?' {
				result.WriteString(fmt.Sprintf("$%d", paramIndex))
				paramIndex++
			} else {
				result.WriteRune(r)
			}
		}
		return result.String()
	}
	return q
}

func (d *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS api_connections (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		base_url TEXT NOT NULL,
		auth_type TEXT NOT NULL,
		auth_secret_ref TEXT,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS api_endpoints (
		id TEXT PRIMARY KEY,
		connection_id TEXT NOT NULL,
		tool_name TEXT NOT NULL UNIQUE,
		tool_description TEXT NOT NULL,
		path TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT 'GET',
		parameters_schema TEXT,
		template TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (connection_id) REFERENCES api_connections(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		client_identity TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		status TEXT NOT NULL,
		duration_ms INTEGER NOT NULL,
		error_message TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_endpoints_conn ON api_endpoints(connection_id);
	CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool_name);
	CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);

	CREATE TABLE IF NOT EXISTS client_tokens (
		token TEXT PRIMARY KEY,
		client_name TEXT NOT NULL UNIQUE,
		client_role TEXT NOT NULL DEFAULT 'developer',
		scopes TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := d.Exec(schema)
	if err != nil {
		return err
	}
	// Migrate database for connection prefixes
	_, _ = d.Exec("ALTER TABLE api_connections ADD COLUMN tool_prefix TEXT")
	return nil
}

// Connections CRUD

func (d *DB) GetConnections(ctx context.Context) ([]*APIConnection, error) {
	rows, err := d.QueryContext(ctx, d.query("SELECT id, name, description, base_url, auth_type, auth_secret_ref, enabled, COALESCE(tool_prefix, '') FROM api_connections"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []*APIConnection
	for rows.Next() {
		c := &APIConnection{}
		var enabledVal int
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.BaseURL, &c.AuthType, &c.AuthSecretRef, &enabledVal, &c.ToolPrefix); err != nil {
			return nil, err
		}
		c.Enabled = enabledVal == 1
		conns = append(conns, c)
	}
	return conns, nil
}

func (d *DB) GetConnection(ctx context.Context, id string) (*APIConnection, error) {
	row := d.QueryRowContext(ctx, d.query("SELECT id, name, description, base_url, auth_type, auth_secret_ref, enabled, COALESCE(tool_prefix, '') FROM api_connections WHERE id = ?"), id)
	c := &APIConnection{}
	var enabledVal int
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.BaseURL, &c.AuthType, &c.AuthSecretRef, &enabledVal, &c.ToolPrefix)
	if err != nil {
		return nil, err
	}
	c.Enabled = enabledVal == 1
	return c, nil
}

func (d *DB) SaveConnection(ctx context.Context, conn *APIConnection) error {
	enabledVal := 0
	if conn.Enabled {
		enabledVal = 1
	}
	query := `
		INSERT INTO api_connections (id, name, description, base_url, auth_type, auth_secret_ref, enabled, tool_prefix, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			base_url = excluded.base_url,
			auth_type = excluded.auth_type,
			auth_secret_ref = excluded.auth_secret_ref,
			enabled = excluded.enabled,
			tool_prefix = excluded.tool_prefix,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.ExecContext(ctx, d.query(query), conn.ID, conn.Name, conn.Description, conn.BaseURL, conn.AuthType, conn.AuthSecretRef, enabledVal, conn.ToolPrefix)
	return err
}

func (d *DB) DeleteConnection(ctx context.Context, id string) error {
	_, err := d.ExecContext(ctx, d.query("DELETE FROM api_connections WHERE id = ?"), id)
	return err
}

// Endpoints / Tools CRUD

func (d *DB) GetEndpoints(ctx context.Context, connID string) ([]*APIEndpoint, error) {
	rows, err := d.QueryContext(ctx, d.query("SELECT id, connection_id, tool_name, tool_description, path, method, parameters_schema, template FROM api_endpoints WHERE connection_id = ?"), connID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var eps []*APIEndpoint
	for rows.Next() {
		e := &APIEndpoint{}
		if err := rows.Scan(&e.ID, &e.ConnectionID, &e.ToolName, &e.ToolDescription, &e.Path, &e.Method, &e.ParametersSchema, &e.Template); err != nil {
			return nil, err
		}
		eps = append(eps, e)
	}
	return eps, nil
}

func (d *DB) GetAllEndpoints(ctx context.Context) ([]*APIEndpoint, error) {
	rows, err := d.QueryContext(ctx, d.query("SELECT id, connection_id, tool_name, tool_description, path, method, parameters_schema, template FROM api_endpoints"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var eps []*APIEndpoint
	for rows.Next() {
		e := &APIEndpoint{}
		if err := rows.Scan(&e.ID, &e.ConnectionID, &e.ToolName, &e.ToolDescription, &e.Path, &e.Method, &e.ParametersSchema, &e.Template); err != nil {
			return nil, err
		}
		eps = append(eps, e)
	}
	return eps, nil
}

func (d *DB) GetEndpointByToolName(ctx context.Context, name string) (*APIEndpoint, error) {
	row := d.QueryRowContext(ctx, d.query("SELECT id, connection_id, tool_name, tool_description, path, method, parameters_schema, template FROM api_endpoints WHERE tool_name = ?"), name)
	e := &APIEndpoint{}
	err := row.Scan(&e.ID, &e.ConnectionID, &e.ToolName, &e.ToolDescription, &e.Path, &e.Method, &e.ParametersSchema, &e.Template)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (d *DB) SaveEndpoint(ctx context.Context, ep *APIEndpoint) error {
	query := `
		INSERT INTO api_endpoints (id, connection_id, tool_name, tool_description, path, method, parameters_schema, template, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			connection_id = excluded.connection_id,
			tool_name = excluded.tool_name,
			tool_description = excluded.tool_description,
			path = excluded.path,
			method = excluded.method,
			parameters_schema = excluded.parameters_schema,
			template = excluded.template,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.ExecContext(ctx, d.query(query), ep.ID, ep.ConnectionID, ep.ToolName, ep.ToolDescription, ep.Path, ep.Method, ep.ParametersSchema, ep.Template)
	return err
}

func (d *DB) DeleteEndpoint(ctx context.Context, id string) error {
	_, err := d.ExecContext(ctx, d.query("DELETE FROM api_endpoints WHERE id = ?"), id)
	return err
}

// Audit Logs

func (d *DB) LogAudit(ctx context.Context, id, clientIdentity, toolName, status string, durationMS int64, errMsg string) error {
	query := `
		INSERT INTO audit_logs (id, client_identity, tool_name, status, duration_ms, error_message, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`
	var errStr interface{} = nil
	if errMsg != "" {
		errStr = errMsg
	}
	_, err := d.ExecContext(ctx, d.query(query), id, clientIdentity, toolName, status, durationMS, errStr)
	return err
}

func (d *DB) GetAuditLogs(ctx context.Context) ([]*AuditLog, error) {
	rows, err := d.QueryContext(ctx, d.query("SELECT id, timestamp, client_identity, tool_name, status, duration_ms, COALESCE(error_message, '') FROM audit_logs ORDER BY timestamp DESC LIMIT 100"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		l := &AuditLog{}
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.ClientIdentity, &l.ToolName, &l.Status, &l.DurationMS, &l.ErrorMessage); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// Client Tokens CRUD

func (d *DB) GetClientToken(ctx context.Context, token string) (*ClientToken, error) {
	row := d.QueryRowContext(ctx, d.query("SELECT token, client_name, client_role, scopes, enabled FROM client_tokens WHERE token = ?"), token)
	t := &ClientToken{}
	var enabledVal int
	err := row.Scan(&t.Token, &t.ClientName, &t.ClientRole, &t.Scopes, &enabledVal)
	if err != nil {
		return nil, err
	}
	t.Enabled = enabledVal == 1
	return t, nil
}

func (d *DB) SaveClientToken(ctx context.Context, t *ClientToken) error {
	enabledVal := 0
	if t.Enabled {
		enabledVal = 1
	}
	query := `
		INSERT INTO client_tokens (token, client_name, client_role, scopes, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(token) DO UPDATE SET
			client_name = excluded.client_name,
			client_role = excluded.client_role,
			scopes = excluded.scopes,
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.ExecContext(ctx, d.query(query), t.Token, t.ClientName, t.ClientRole, t.Scopes, enabledVal)
	return err
}

func (d *DB) DeleteClientToken(ctx context.Context, token string) error {
	_, err := d.ExecContext(ctx, d.query("DELETE FROM client_tokens WHERE token = ?"), token)
	return err
}

func (d *DB) GetClientTokens(ctx context.Context) ([]*ClientToken, error) {
	rows, err := d.QueryContext(ctx, d.query("SELECT token, client_name, client_role, scopes, enabled FROM client_tokens"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*ClientToken
	for rows.Next() {
		t := &ClientToken{}
		var enabledVal int
		if err := rows.Scan(&t.Token, &t.ClientName, &t.ClientRole, &t.Scopes, &enabledVal); err != nil {
			return nil, err
		}
		t.Enabled = enabledVal == 1
		tokens = append(tokens, t)
	}
	return tokens, nil
}
