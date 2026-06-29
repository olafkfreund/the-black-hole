# MCP API Gateway & Portal

An enterprise-grade, high-performance API Gateway and Web Portal that translates standard REST/HTTP APIs into Model Context Protocol (MCP) tools dynamically. Specifically designed for highly secured, regulated, and air-gapped environments.

## Features
- **Dynamic MCP Tool Translation**: Declare connection endpoints and map request body/parameters to JSON Schema templates. The gateway automatically generates MCP-compliant tool definitions.
- **Enterprise Security**:
  - **OIDC/OAuth2 SSO**: Integrate Okta, Keycloak, or Azure AD for Portal authentication.
  - **Token-Authenticated MCP Clients**: Restrict Claude, Copilot, or Antigravity connections via encrypted bearer tokens or JWTs.
  - **mTLS & SSL/TLS 1.3**: Direct support for Mutual TLS client verification and encrypted network paths.
- **Pluggable Security Vaults**: Read credentials dynamically at runtime using AWS Secrets Manager, Azure Key Vault, Google Cloud Secret Manager, or a local encrypted JSON store.
- **Air-Gap Preparedness**: A self-contained Go binary with embedded single-page assets (`//go:embed`), fully local database capabilities (SQLite), and zero-compilation build flows.

---

## Technical Architecture

```mermaid
graph TD
    %% Custom Styling matching Gruvbox Dark
    classDef client fill:#3c3836,stroke:#83a598,stroke-width:2px,color:#ebdbb2;
    classDef gateway fill:#282828,stroke:#fe8019,stroke-width:3px,color:#ebdbb2;
    classDef vault fill:#3c3836,stroke:#b16286,stroke-width:2px,color:#ebdbb2;
    classDef storage fill:#3c3836,stroke:#b8bb26,stroke-width:2px,color:#ebdbb2;
    classDef target fill:#3c3836,stroke:#cc241d,stroke-width:2px,color:#ebdbb2;
    
    subgraph Client Space ["Client Space"]
        C["LLM Client (Claude/Antigravity)"]:::client
        P["Admin Web Portal"]:::client
        CLI["Admin CLI Client"]:::client
    end

    subgraph TheBlackHole ["The Black Hole (MCP Gateway Core)"]
        direction TB
        Auth{"Auth Filter Middleware"}:::gateway
        Router{"Router/Dispatcher"}:::gateway
        Renderer["Template Engine"]:::gateway
        Audit["Audit Logger"]:::gateway
        OTel["OTel Metric Tracker"]:::gateway
    end
    
    subgraph Storage ["Storage & Auditing"]
        DB[("SQLite / Postgres configs")]:::storage
        Logs[("Audit Log Tables")]:::storage
    end

    subgraph Security ["Security Vaults"]
        Local["Local Encrypted JSON"]:::vault
        Cloud["Cloud Vault (AWS/GCP/Azure)"]:::vault
    end

    subgraph Internal ["Microservice Network"]
        API1["Internal REST API 1"]:::target
        API2["Internal REST API 2"]:::target
    end

    C -- "mTLS / SSE Token (TLS 1.3)" --> Auth
    P -- "OIDC / Session JWT" --> Auth
    CLI -- "Session JWT (REST)" --> Auth

    Auth -- "Valid?" --> Router
    Router -- "Read Configs" --> DB
    Router -- "1. Resolve Target URL" --> Renderer
    Router -- "2. Check Prefix Clashing" --> Renderer
    
    Renderer -- "3. Resolve Credentials" --> VaultResolver{"Secrets Resolver"}:::gateway
    VaultResolver -- "Local Adapter" --> Local
    VaultResolver -- "IAM / Instance Role" --> Cloud

    VaultResolver -- "4. Inject Headers & Call" --> API1
    VaultResolver -- "4. Inject Headers & Call" --> API2

    API1 --> Audit
    API2 --> Audit
    Audit --> Logs
    Audit --> OTel
```

### Detailed Execution Sequence

Here is the exact sequence of validation, vault credentials resolution, routing execution, and metric audits during a single MCP tool call:

```mermaid
sequenceDiagram
    autonumber
    participant Client as LLM Client
    participant GW as MCP Gateway Core
    participant DB as SQLite/Postgres DB
    participant Vault as Secret Vault
    participant Target as Downstream API

    Client->>GW: POST /messages?sessionId=... (tools/call)
    Note over Client,GW: Content-Type: json, Auth: Bearer Token / mTLS Cert
    GW->>GW: Authenticate Caller & Extract Claims
    alt Authentication Failed
        GW-->>Client: HTTP 401 Unauthorized
    else Authentication Verified
        GW->>DB: Query Connection & Tool Schema (toolName)
        DB-->>GW: Return Base URL, Path, Parameters, Auth Settings
        
        GW->>GW: Substitute Path Parameters (e.g. /users/{{id}} -> /users/123)
        
        alt Authentication Required (AuthType != none)
            GW->>Vault: Fetch Credentials (AuthSecretRef)
            Vault-->>GW: Return decrypted token/credentials
            GW->>GW: Inject headers (Bearer / Basic / Custom)
        end
        
        GW->>Target: Execute HTTP Request (GET/POST/etc.)
        alt Target API Timeout / Down
            Target-->>GW: Connection Refused / Timeout
            GW->>DB: Log Failed Execution (status=failure)
            GW-->>Client: Return JSON-RPC Error -32603
        else Target API Responds
            Target-->>GW: Return HTTP Payload (JSON/Text)
            GW->>GW: Clean and Format Response (Pretty JSON / Markdown)
            GW->>DB: Log Successful Execution (status=success, duration)
            GW-->>Client: Return JSON-RPC Response Content (Text/Markdown)
        end
    end
```

---

## Quick Start

### 1. Using Nix & Devenv
The repository comes equipped with a declarative Nix Flake and a `devenv` shell environment.

To activate the development shell:
```bash
# Allow direnv to auto-enter shell
direnv allow

# Or enter manually using devenv
devenv shell
```

Available scripts inside the devenv shell:
- `run-dev`: Starts the gateway web portal on `http://localhost:8080` (or https depending on configuration).
- `build`: Compiles the binary to `./mcp-gateway`.
- `lint`: Runs Golangci-lint checking rules.
- `test`: Executes backend unit tests.

### 2. Using Docker Compose
Run the stack using the pre-configured compose setup:
```bash
docker-compose up -d --build
```
This builds the multi-stage production container, mounts a persistent volume for the local SQLite file (`secrets.json` and `mcp-gateway.db`), and exposes the UI at `http://localhost:8080`.

---

## Operating Modes

### A. Server Mode (Portal & SSE) - Default
Exposes the web configuration dashboard (Portal) and the Server-Sent Events (SSE) stream listener. 

To run:
```bash
go run main.go
```

**SSO Configuration**: Set the following environment variables to activate OIDC:
- `OIDC_ISSUER`: Issuer URL (e.g. `https://keycloak.company.com/realms/internal`)
- `OIDC_CLIENT_ID`: OAuth client identifier
- `OIDC_CLIENT_SECRET`: OAuth client secret token

**SSL/TLS & mTLS Configuration**:
- `TLS_CERT_PATH`: Path to server certificate PEM.
- `TLS_KEY_PATH`: Path to server private key PEM.
- `CLIENT_CA_PATH`: Path to CA bundle (activates Mutual TLS).

### B. Stdio Mode (CLI Wrapper)
Used by local desktop clients (like Claude Desktop) to invoke tools through stdin/stdout.

To configure Claude Desktop to use this gateway:
Add the following connection to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "api-gateway": {
      "command": "/path/to/mcp-gateway",
      "args": ["-stdio"],
      "env": {
        "DATABASE_PATH": "/path/to/mcp-gateway.db",
        "VAULT_PROVIDER": "local",
        "VAULT_LOCAL_PATH": "/path/to/secrets.json"
      }
    }
  }
}
---

## Configuration Settings

Configure the gateway using standard environment variables:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `8899` | Port to host the Web Portal and SSE endpoints. |
| `DATABASE_PATH` | `./mcp-gateway.db` | Local SQLite database file location. |
| `DATABASE_URL` | `""` | Connection URI for remote PostgreSQL database (ex: `postgres://user:pass@host:5432/db`). Overrides `DATABASE_PATH` when set. |
| `VAULT_PROVIDER` | `local` | Pluggable vault provider (`local`, `aws`, `gcp`, `azure`). |
| `VAULT_LOCAL_PATH` | `./secrets.json` | JSON vault secrets file (used when provider is `local`). |
| `JWT_SECRET` | *(Random)* | Secret key used to sign portal JWT session tokens. |
| `TLS_CERT_PATH` | `""` | Path to HTTPS server certificate. |
| `TLS_KEY_PATH` | `""` | Path to HTTPS private key. |
| `CLIENT_CA_PATH` | `""` | Path to CA root (activates **Mutual TLS (mTLS)**). |
| `OIDC_ISSUER` | `""` | OpenID Connect identity provider URL (e.g. Okta, Keycloak). |

---

## Administrative & Monitoring CLI (`mcp-cli`)

For administrators and operators, the gateway includes a standalone, cross-platform CLI tool (`mcp-cli`) compiled for macOS (Intel/Apple Silicon), Linux, and Windows. The CLI connects remotely to the Gateway REST API over HTTPS/HTTP, providing complete administration, verification, and performance monitoring capabilities.

### 1. Build Instructions
To build the CLI for your current platform:
```bash
just build-cli
```
To cross-compile for all systems (outputs saved in `dist/`):
```bash
just build-cli-all
```

### 2. Available Commands

* **Authentication**:
  ```bash
  mcp-cli login <username> --addr <gateway-url>
  ```
  Authenticates with the gateway server and caches the session token in the user configuration directory (`~/.config/mcp-gateway/cli.json`).

* **Diagnostics & Verification**:
  ```bash
  mcp-cli verify
  ```
  Runs a comprehensive health check: pings the gateway server, verifies database schemas, checks vault integration, and validates outbound network connectivity for all downstream API endpoints.

* **Performance & Telemetry Monitoring**:
  ```bash
  mcp-cli status    # Shows gateway settings, active port, vault provider, and mTLS status
  mcp-cli metrics   # Fetches and parses scrapable Prometheus metrics for live status tracking
  mcp-cli logs      # Lists the last 100 tool execution audit logs (status, duration, error messages)
  ```

* **API Connections CRUD**:
  ```bash
  mcp-cli connection list
  mcp-cli connection add --name <name> --url <url> [--prefix <prefix>] [--auth <type>] [--secret <ref>]
  mcp-cli connection modify --id <uuid> [--name <name>] [--url <url>] [--prefix <prefix>] [--enabled <true|false>]
  mcp-cli connection delete --id <uuid>
  ```

* **Tool Endpoints CRUD**:
  ```bash
  mcp-cli endpoint list
  mcp-cli endpoint add --conn-id <conn-uuid> --name <tool-name> --desc <description> --path <route> --method <HTTP-method>
  mcp-cli endpoint modify --id <endpoint-uuid> [--name <name>] [--path <route>] [--method <HTTP-method>]
  mcp-cli endpoint delete --id <endpoint-uuid>
  ```

* **Vault Secrets Management**:
  ```bash
  mcp-cli vault list
  mcp-cli vault set --key <secret-path> --val <secret-value>
  mcp-cli vault delete --key <secret-path>
  ```

---

## Integrating with Secret Vaults

Sensitive auth tokens (Basic, Bearer, Custom Headers) are retrieved at query runtime from your chosen vault.

| Provider (`VAULT_PROVIDER`) | Config Requirements | Auth Mechanism |
| :--- | :--- | :--- |
| `local` | `VAULT_LOCAL_PATH` | Local JSON dictionary |
| `aws` | AWS environment keys | IAM Instance Profile / IRSA |
| `gcp` | GCP environment keys | Workload Identity / ADC |
| `azure` | Azure credentials | Managed Identity |

### Storing a Secret
Open the Portal UI, navigate to the **Security Vault** view, and insert the secret mapping:
- **Secret Path**: `prod/billing-service/api-key`
- **Secret Value**: `Bearer xoxb-123456789-abcdef`

When setting up your **API Connection**, map `Auth Secret Ref` to `prod/billing-service/api-key`.

---

## Real-Life Scenarios

### Scenario A: Securing legacy REST APIs inside a regulated bank

In this scenario, a banking SRE team needs to expose internal customer account databases to developers using Claude Desktop, without revealing target credentials.

#### 1. Setup the connection target
Register the internal accounts database via the command line client:
```bash
# Add connection target
./mcp-cli connection add \
  --name "Accounts Database" \
  --url "https://internal.bank.net/api/v1" \
  --prefix "accounts_" \
  --desc "Protected customer banking records database" \
  --auth "bearer" \
  --secret "prod/database/accounts-key"
```

#### 2. Store the credentials securely in the vault
Write the API authorization token into the configured Vault (resolving at execution time):
```bash
./mcp-cli vault set \
  --key "prod/database/accounts-key" \
  --val "sk_secure_banking_token_558839"
```

#### 3. Define the tool endpoint mapping
Expose a specific, restricted endpoint as a structured MCP tool:
```bash
./mcp-cli endpoint add \
  --conn-id "<connection-uuid>" \
  --name "get_balance" \
  --desc "Retrieve checking and savings balances for a client ID" \
  --path "/balance/{{client_id}}" \
  --method "GET" \
  --schema '{"type":"object","properties":{"client_id":{"type":"string","description":"Client account identifier"}},"required":["client_id"]}'
```

---

### Scenario B: Dynamic image and media formatting for LLM users

LLMs like Claude, Antigravity, and Copilot render standard Markdown directly in their chat UIs. Here is how we expose dynamic image generation services for users.

#### 1. Register a public image generator API
Add the public Dog CEO API connection:
```bash
./mcp-cli connection add \
  --name "Dog Ceo Pictures" \
  --url "https://dog.ceo/api" \
  --prefix "dog_" \
  --desc "Generates random breed photos and dog images" \
  --auth "none"
```

#### 2. Register the random image endpoint
```bash
./mcp-cli endpoint add \
  --conn-id "<dog-connection-uuid>" \
  --name "random_image" \
  --desc "Fetch a random dog picture URL" \
  --path "/breeds/image/random" \
  --method "GET"
```

#### 3. Query the tool in real life
When an LLM client runs the tool `dog_random_image`, it receives the JSON response:
```json
{
  "message": "https://images.dog.ceo/breeds/terrier/n02093754_3839.jpg",
  "status": "success"
}
```
The LLM client automatically processes the image URL, translating it to a standard Markdown tag:
```markdown
Here is the random dog image:
![Dog](https://images.dog.ceo/breeds/terrier/n02093754_3839.jpg)
```
The user's chat client renders the dog picture inline immediately.

---

### Scenario C: Component Health and Live Performance Telemetry

Administrators must verify the status and monitor performance loads of the gateway under usage.

#### 1. Check Server Component Diagnostics
Run the command-line diagnostic suite to verify routing integrity:
```bash
./mcp-cli verify
```
*Verification output:*
```text
Running Gateway Component Diagnostics...
=========================================
[1/5] Checking Gateway Server Connectivity... OK
[2/5] Verifying Admin Credentials Token...    OK (Token Verified)
[3/5] Querying System Database Schema...     OK (3 Connections, 6 Tools Registered)
[4/5] Testing Vault Secret Integration...    OK (1 Secret Keys Available)
[5/5] Verifying Target API Connectivity...   
  Name                  Target URL               Status   Notes
  ----                  ----------               ------   -----
  Accounts Database     https://internal.bank... OK       HTTP 401 Unauthorized
  Dog Ceo Pictures      https://dog.ceo/api      OK       HTTP 200 OK
```

#### 2. Query Live Prometheus Telemetry
Scrape system telemetry stats directly from the active exporter stream:
```bash
./mcp-cli metrics
```
*Sample metrics payload:*
```text
MCP Gateway Monitoring Telemetry Stats
======================================
Metric Identifier                   Labels / Tags                                     Value
-----------------                   -------------                                     -----
mcp_tool_execution_count_total      status="success",tool_name="dog_random_image"     18
mcp_tool_execution_latency_seconds  quantile="0.9",tool_name="accounts_get_balance"   0.142
go_memstats_alloc_bytes             -                                                 8234810
```

---

### Scenario D: Enterprise API Restriction & Scoped Client Access

In enterprise environments, different development teams or LLM agents require restricted access to specific APIs only. We configure role-based access controls and scope globs to isolate client tokens.

#### 1. Issue a Scoped Client Token via CLI
Generate and register a token restricted only to weather APIs (tools prefixing with `weather_`):
```bash
./mcp-cli token add \
  --name "Weather Team Token" \
  --token "mcp_client_weather_dev_552" \
  --role "developer" \
  --scopes "weather_*"
```

Alternatively, this can be done visually in the **Client Tokens** section of the Web Portal, featuring a secure token generator.

#### 2. Verify Scoped Access in Stdio/SSE Client
When a client connects using the token `mcp_client_weather_dev_552`, they only see tools matching the `weather_*` pattern.

Query tools over Stdio:
```bash
export MCP_GATEWAY_TOKEN=mcp_client_weather_dev_552
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | ./mcp-gateway -stdio
```
*Response payload:*
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "weather_get_forecast",
        "description": "Retrieve real-time weather and forecast data for coordinates",
        "inputSchema": {
          "properties": {
            "current_weather": { "type": "boolean" },
            "latitude": { "type": "number" },
            "longitude": { "type": "number" }
          },
          "required": ["latitude", "longitude"],
          "type": "object"
        }
      }
    ]
  },
  "id": 1
}
```
All other connections (e.g. `stripe_*`) and administrative tools (e.g. `admin_*`) are filtered out completely from the listing and rejected with a standard JSON-RPC `-32601` error code if called directly.

---

### Scenario E: High-Availability Scale-Out in Kubernetes Cluster

For production workloads, the gateway server is deployed as multiple stateless replicas inside a Kubernetes cluster behind an Ingress controller configured with session affinity.

#### 1. Kubernetes Architecture & Traffic Flow
Below is the architectural diagram of a scaled-out Kubernetes deployment:

```mermaid
graph TD
    %% Custom Styling matching Gruvbox Dark
    classDef lb fill:#3c3836,stroke:#458588,stroke-width:2px,color:#ebdbb2;
    classDef pod fill:#282828,stroke:#b8bb26,stroke-width:3px,color:#ebdbb2;
    classDef db fill:#3c3836,stroke:#d3869b,stroke-width:2px,color:#ebdbb2;
    classDef client fill:#3c3836,stroke:#fe8019,stroke-width:2px,color:#ebdbb2;
    
    C["LLM Client (Claude)"]:::client
    
    subgraph K8s ["Kubernetes Cluster Namespace"]
        Ing["NGINX Ingress Controller <br/> [Sticky Session Affinity Cookie]"]:::lb
        
        subgraph Pods ["Stateless Pod Replicas"]
            Pod1["Gateway Pod 1"]:::pod
            Pod2["Gateway Pod 2"]:::pod
            Pod3["Gateway Pod N"]:::pod
        end
        
        Service["K8s ClusterIP Service"]:::lb
    end
    
    SharedDB[("Shared PostgreSQL Cluster")]:::db
    Vault["Cloud Secrets Manager (AWS/GCP/Azure)"]:::db
    
    C -- "1. Establish SSE stream" --> Ing
    Ing -- "2. Sticks connection using cookie" --> Pod1
    
    C -- "3. POST /messages" --> Ing
    Ing -- "4. Routes back to active session" --> Pod1
    
    Pods -- "Fetch Configs & Tokens" --> SharedDB
    Pods -- "Resolve Vault Credentials" --> Vault
```

#### 2. Deploy Stateless Pods with PostgreSQL
Update the `mcp-gateway-secrets` Secret to include your database configuration, and apply `k8s-deployment.yaml` with a PostgreSQL connection string:
```bash
# Apply deployments
kubectl apply -f k8s-deployment.yaml
```

Set the environment variable:
```yaml
- name: DATABASE_URL
  value: "postgres://postgres:secure_db_pass@postgres-service.default.svc.cluster.local:5432/mcp_db?sslmode=disable"
```
Because the storage is delegated to a shared PostgreSQL cluster, pods run completely stateless. You can scale replicas on the fly:
```bash
# Scale gateway instances to 5 pods
kubectl scale deployment mcp-api-gateway --replicas=5
```

#### 3. Establish Ingress Session Affinity
The included `Ingress` controller resource configures sticky sessions. NGINX will automatically insert a routing cookie (`route`) on client SSE requests and forward corresponding JSON-RPC POST calls back to the same pod instance, preventing "Session not found" discrepancies during execution.

---

### Scenario F: LCH Group Concorde API & MCP Integration (DPG Trade Volume & Non-Cash Collateral)

Exposes daily cleared trade statistics and non-cash asset breakdown (market values and haircuts) as governed MCP tools.

#### 1. Out-of-the-Box Simulated Targets
The gateway automatically registers the mock services database mapping upon initial startup. It exposes two downstream endpoints under `http://127.0.0.1:<port>/api/mock`:
* `/dpg/trade-volume`: Daily trade volumes and currency breakdown.
* `/collateral/non-cash`: ISIN listings and valuations.

#### 2. Querying via REST API
LCH applications can query data directly over standard HTTP/REST:
```bash
# Query daily trade volume
curl http://localhost:8899/api/mock/dpg/trade-volume?member_id=MEM-LCH-001

# Query non-cash collateral asset breakdown
curl http://localhost:8899/api/mock/collateral/non-cash?member_id=MEM-LCH-001
```

#### 3. Invoking via MCP Facade
LLM clients (such as Claude Desktop or Concorde Portal agents) communicate over the standard Stdio or SSE stream using a client token (e.g. `lch_member_test_token_889`):
```bash
export MCP_GATEWAY_TOKEN=lch_member_test_token_889
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lch_get_dpg_trade_volume","arguments":{"member_id":"MEM-LCH-001"}},"id":1}' | ./mcp-gateway -stdio
```
The gateway parses the parameter `member_id`, forwards the query to the underlying REST service, validates outputs, and returns clean, structured data to the client.

---

## File Structure
- `main.go`: Application lifecycle.
- `schema.sql`: Local DB table layouts.
- `pkg/config`: Configuration schemas.
- `pkg/storage`: DB connector, CRUD actions, and audit logs.
- `pkg/vault`: Interface for AWS, GCP, Azure, and Local vaults.
- `pkg/auth`: JWT issuers, SSO authentication, and TLS profiles.
- `pkg/gateway`: Dynamic parameter rendering and HTTP call execution.
- `pkg/mcp`: Model Context Protocol JSON-RPC implementation.
- `pkg/portal`: REST API and static single page serving.
- `pkg/portal/static`: Front-end HTML/CSS/JS files.
