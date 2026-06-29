# LCH Group Concorde: API & MCP Facade Architectural Proposal

This document outlines the strategic shift, technical architecture, governance framework, service delivery plan, and usage guide for evolving LCH Group's clearing data distribution from a legacy file-based system to a real-time, secure, and governed **API + Model Context Protocol (MCP) Facade**.

---

## 1. Executive Summary & Problem Statement

### Today's Challenges: Legacy File-Based Distribution
Today, LCH Ltd generates and distributes thousands of static reports (PDF, CSV, XML) daily via SFTP and web portal downloads. This model is operationally expensive and increasingly unfit for modern clearing needs:
*   **Stale, Batch-Driven Data**: Reports are generated intra-day (ITD) or end-of-day (EOD) overnight (T+1), restricting clearing members from making real-time margin and collateral decisions.
*   **Operationally Heavy & Fragile Delivery**: Large-scale file generation requires heavy computing infrastructure. Distribution paths are prone to SFTP connection failures, network delays, file formatting issues, and subsequent client-side ingestion errors.
*   **High Client and Support Friction**: Fixed report formats cannot adapt to ad-hoc member queries, leading to repetitive support requests and manual Excel reprocessing.
*   **Locked Intelligence**: Data is trapped inside isolated files, with no capability to programmatically query, cross-reference, or feed directly into members' local AI/copilot tools.

This results in a fragmented, inefficient experience, where effort is spent in generating files and accessing data rather than deriving value.

```
[ Legacy Model ]
  Clearing Data Store ──> File Gen Engine ──> SFTP Server ──> Member Ingestion (Failures, T+1 Stale)

[ Evolved Model ]
  Clearing Data Store ──> Governed REST API ──> MCP Facade (The Black Hole) ──> Member AI / Copilots (Real-Time)
```

---

## 2. Objectives & Outcomes

We propose transitioning to a real-time, on-demand query architecture mediated by an **API Gateway and MCP Facade**:

### A. APIs (Foundational Data Layer)
APIs are a proven, industry-standard mechanism for secure and scalable data distribution. They provide a stable, governed, and testable interface. As part of this evolution, data distribution will be enabled via REST/HTTP APIs. This layer decouples internal databases from external querying clients, standardizing authentication and parameters.

### B. MCP Facade (Controlled Intelligence Layer)
The MCP Facade acts as the semantic bridge between structured APIs and intelligent consumption (LLMs, copilots, and agents).
1.  **Intent Interpretation**: Converts natural language requests (e.g., *"What is our current US Treasury collateral value after haircuts?"*) into structured API parameters.
2.  **API Mediation**: The MCP Facade does not access databases or data stores directly. It translates requests and orchestrates calls strictly via registered REST APIs.
3.  **Deterministic & Governed Outputs**: Inputs are validated against strict JSON Schema templates before reaching downstream APIs.
4.  **Contextual Summarization**: Layers explainability, translation, and summaries over raw API outputs.
5.  **Auditable Audit Trail**: Every transaction is logged (status, execution duration, caller identity) for security operations (SIEM) visibility.

> [!IMPORTANT]
> **Critical Governance Principle**: The MCP Facade serves as a secure proxy. The LLM engine never possesses static API tokens, nor does it write queries directly against LCH clearing databases. All outputs are API-mediated, deterministic, and auditable, ensuring full control.

### Future Option (Very Long Term)
Potential to explore more direct MCP–data interaction (e.g. querying federated Lakehouses directly under strict isolation boundaries) for advanced use cases, subject to strict governance and commercial controls.

---

## 3. Service Scope & Details

### Service Description
Analysis and design of APIs for collateral services and integration with MCP server to produce deterministic responses to a member request for data. This includes:
*   **Glossary & Semantic Layer**: Formatting and dictionary translation between clearing data terms and natural language questions.
*   **Integration Implementation**: Mapping REST endpoints to MCP dynamic tools.
*   **Environments Support**: Configuration, health monitoring, and scaling of development, test, and production environments.
*   **Test Planning/Execution Support**: Testing stdio and SSE connections, simulating API latencies.
*   **Member-Test Readiness**: Providing developer documentation, OpenAPI definitions, and training materials.
*   **Rollout Support**: Assisting additional business lines (SwapClear, RepoClear, ForexClear) as they onboard onto the gateway.

### Service Details (How Delivered)
*   **Agreed Delivery Plan**: Work to an established project roadmap and bi-weekly sprint cadence.
*   **Design & Runbooks**: Produce and maintain detailed architecture plans, API schemas, and support runbooks.
*   **Risk & Dependency Management**: Manage downstream API availability, token lifecycle dependencies, and network access routes.
*   **Quality Gates**: Execute strict quality checks for dev/test and member test readiness, delivering documented verification logs as evidence.

### Service Location
*   **London-Led Delivery**: Core engineering, architecture, and governance operations are led from London, with remote delivery support as required.
*   **Customer Governance Compliance**: Supplier resources must work with Customer on secure environments (bastion hosts, secure workstations) and strictly follow Customer change control and governance processes.

### Completion Criteria
*   End users send requests to the MCP, which then invokes the underlying APIs to retrieve LCH Ltd collateral data, successfully returning formatted answers.

---

## 4. Technical Solution Architecture

The diagram below details the architecture and information flow of the facade:

```mermaid
graph TD
    %% Custom Styling
    classDef client fill:#3c3836,stroke:#83a598,stroke-width:2px,color:#ebdbb2;
    classDef gateway fill:#282828,stroke:#fe8019,stroke-width:3px,color:#ebdbb2;
    classDef secure fill:#3c3836,stroke:#b16286,stroke-width:2px,color:#ebdbb2;
    classDef target fill:#3c3836,stroke:#cc241d,stroke-width:2px,color:#ebdbb2;

    subgraph Client Layer ["Client / Member Space"]
        Claude[Claude Desktop / Copilot]:::client
        Concorde[Concorde Portal UI]:::client
        CLI[Admin CLI Utility]:::client
    end

    subgraph Facade Layer ["Controlled Intelligence Layer (The Black Hole)"]
        direction TB
        Auth{"Auth & mTLS Validator"}:::gateway
        Router{"Namespace Router"}:::gateway
        Renderer["JSON Schema Renderer"]:::gateway
        Audit["Audit Logger"]:::gateway
    end

    subgraph Secrets & Configs ["Security & State Store"]
        DB[("PostgreSQL Cluster / SQLite")]:::secure
        Vault["LCH Vault (AWS/GCP/Azure)"]:::secure
    end

    subgraph API Layer ["Foundational Data Layer (REST APIs)"]
        DPG["DPG Trade Volume Service"]:::target
        Coll["Non-Cash Collateral Service"]:::target
    end

    Claude -- "MCP over SSE (mTLS + Token)" --> Auth
    Concorde -- "HTTPS / OIDC Session" --> Auth
    CLI -- "HTTPS / JWT Token" --> Auth

    Auth -- "Verified" --> Router
    Router -- "Read Scopes" --> DB
    Router -- "Resolve Target Path" --> Renderer
    
    Renderer -- "Dynamic Credentials Injection" --> Vault
    Vault -- "Secure Request" --> DPG
    Vault -- "Secure Request" --> Coll

    DPG --> Audit
    Coll --> Audit
    Audit -- "Emit Metrics" --> OTel[OpenTelemetry & Prometheus]
```

### Sequence Diagram (Detailed Tool Resolution & Call)

```mermaid
sequenceDiagram
    autonumber
    actor Member as Clearing Member
    participant LLM as LLM Engine / Client
    participant GW as MCP Gateway Facade
    participant Vault as HSM/Secrets Vault
    participant API as LCH Downstream REST API

    Member->>LLM: "Get DPG Trade Volume stats for MEM-LCH-001"
    Note over LLM: Matches intent to tool:<br/>lch_get_dpg_trade_volume(member_id: "MEM-LCH-001")
    
    LLM->>GW: POST /messages (JSON-RPC tools/call)
    Note right of LLM: Authorization: Bearer <Token><br/>Payload: {member_id: "MEM-LCH-001"}
    
    activate GW
    GW->>GW: Authenticate caller token & verify scopes
    GW->>GW: Validate inputs against JSON Schema
    
    alt Credentials Required
        GW->>Vault: Fetch dynamic API token (ref: prod/lch/api-key)
        Vault-->>GW: Return decrypted token
    end

    GW->>GW: Construct API path: /api/mock/dpg/trade-volume?member_id=MEM-LCH-001
    GW->>API: HTTP GET /api/mock/dpg/trade-volume?member_id=MEM-LCH-001 (TLS 1.3)
    activate API
    API-->>GW: HTTP 200 OK {"trade_count": 8420, "total_volume_usd": 12450800000.5}
    deactivate API

    GW->>GW: Log audit trail (status: success, duration: 25ms)
    GW-->>LLM: Return JSON-RPC response with structured data
    deactivate GW
    
    LLM->>LLM: Apply contextual summarization & formatting
    LLM-->>Member: Markdown Output: "Your clearing trade count is 8,420 with total USD volume of..."
```

---

## 5. Architectural Decisions & Rationale (ADRs)

### ADR 01: Compiled Go Backend Core
*   **Decision**: Implement the Gateway and CLI utility in Go.
*   **Rationale**: Go compiles into a single static binary with zero external runtime package dependencies. This is critical for air-gapped zones in Customer where downloading packages at runtime is blocked. Go's native support for HTTP/TLS 1.3 and goroutine-based concurrency ensures low-latency routing under peak clearing loads.

### ADR 02: REST API Wrapper vs Direct DB Access
*   **Decision**: Wrap data retrieval strictly in REST APIs; do not permit direct SQL database queries by the MCP server.
*   **Rationale**: Direct SQL generation by LLMs poses a severe threat of SQL injection, data leakage, and query execution timeouts. Standardizing data access behind REST APIs allows the security team to enforce rate limits, parameter checking, and strict schema validation before any query reaches LCH Ltd systems.

### ADR 03: Scoped Authorization Tokens
*   **Decision**: Restrict MCP clients using Bearer tokens mapped to namespace glob filters (e.g. `lch_*`, `repo_*`).
*   **Rationale**: Multi-tenancy is enforced. A developer token issued for SwapClear testing must not be allowed to list or call RepoClear tool endpoints. The gateway validates token scopes dynamically before listing tools or routing executions.

### ADR 04: Ingress Session Affinity (Sticky Sessions)
*   **Decision**: Enforce cookie-based session affinity at the NGINX Ingress level for Kubernetes scale-out.
*   **Rationale**: Server-Sent Events (SSE) establish long-running HTTP connections. In a multi-replica deployment, stateless round-robin routing breaks SSE context when a JSON-RPC tool execution POST is routed to a different pod than the one holding the SSE listener. Cookie-based affinity ensures all messages in a session go to the same replica.

---

## 6. Management, User, & Access Management

### Multi-Tenancy & Roles
1.  **Admin Role**:
    *   Access to the Web Portal dashboard and Admin REST APIs.
    *   Ability to add/modify connections, register endpoints, configure vaults, and issue client tokens.
    *   Managed via OIDC Identity Providers (e.g. Okta, Keycloak, Active Directory).
2.  **Client Role (Clearing Developer)**:
    *   Access is strictly programmatic (via Bearer tokens).
    *   Cannot log in to the Web Portal dashboard.
    *   Token validation restricts them to their mapped namespaces (e.g. `lch_` prefix for DPG and Collateral).

### Secrets Vault Integration
The gateway utilizes a `VaultProvider` adapter to resolve API keys and passwords dynamically at runtime.
*   **Local Mode**: Reads encrypted records from a local JSON file (`secrets.json`).
*   **Cloud Mode**: Interfaces directly with AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault using IAM roles (Workload Identity). Plaintext credentials never exist in databases or configuration files.

### Audit Trails
Every connection and tool call writes a detailed entry to the audit log:
*   Timestamp and execution duration (ms).
*   Calling Client ID / token reference.
*   Target Tool name and HTTP status response.
*   Metrics are exposed to Prometheus for automated alerting on error rates.

---

## 7. Installation & Deployment Runbook

### A. Local Sandbox Setup (Nix & Devenv)
To compile and run the gateway locally with default seeded DPG and Collateral mock services:

```bash
# 1. Enter the Nix shell environment
devenv shell

# 2. Build the server and CLI binaries
just build

# 3. Start the server (deletes old DB to trigger fresh LCH seeding)
rm -f mcp-gateway.db
PORT=8899 DATABASE_PATH=./mcp-gateway.db ./mcp-gateway
```
*At startup, the server detects an empty database and seeds the default LCH mock configurations, U.S. Treasury, and Coinbase statistics connections.*

### B. Production Scale-Out (Kubernetes)
For high-availability production environments, the gateway runs as stateless pods using a shared PostgreSQL database cluster:

```bash
# 1. Update your PostgreSQL connection string in the secrets block:
# DATABASE_URL = postgres://user:password@postgres-service:5432/mcp_db?sslmode=disable

# 2. Apply the Kubernetes manifest (creates Deployment, Service, PVC, and Ingress)
kubectl apply -f k8s-deployment.yaml

# 3. Scale instances on demand
kubectl scale deployment mcp-api-gateway --replicas=5
```

---

## 8. Usage & Integration Guide

### A. Integrating with Claude Desktop
Add the following configuration to your `claude_desktop_config.json` to enable local testing:

```json
{
  "mcpServers": {
    "lch-gateway": {
      "command": "/path/to/mcp-gateway",
      "args": ["-stdio"],
      "env": {
        "DATABASE_PATH": "/path/to/mcp-gateway.db",
        "MCP_GATEWAY_TOKEN": "lch_member_test_token_889"
      }
    }
  }
}
```

### B. Integrating with Antigravity / Gemini Developer Tools
When building autonomous agents using the Google Antigravity SDK, register the gateway as a tool provider:

```python
from antigravity_sdk import Agent, ToolRegistry

# Configure the gateway token
token = "lch_member_test_token_889"

# Load tools from gateway facade
registry = ToolRegistry.from_mcp_sse(
    url="http://localhost:8899/sse",
    headers={"Authorization": f"Bearer {token}"}
)

# Initialize the agent equipped with LCH tools
agent = Agent(
    name="LCH Collateral Assistant",
    instructions="Help clearing members evaluate collateral holdings and volumes.",
    tools=registry.list_tools()
)
```

### C. Integrating with GitHub Copilot & Codex
To use the facade with GitHub Copilot Chat or OpenAI Codex, register the gateway as an external API resource or configure it through custom workspace tool extensions (such as Cline/Roo-Code in VS Code):
1.  **Configure Cline/Roo-Code**: In your IDE extension settings, select **MCP Servers**, click **Add Server**, choose **command**, and point it to the compiled binary `/path/to/mcp-gateway -stdio` with environment variable `MCP_GATEWAY_TOKEN` set.
2.  **Visual Studio Code / Copilot Settings**: Configure the API gateway as a Custom Skill Endpoint in the workspace configurations, routing requests directly to the REST APIs or via the proxy.

### D. Conversational Queries & Document Generation
Once connected, users can query data using natural language, and the LLM will format the output automatically.

#### Scenario 1: Fetching Clearing Volumetrics
*   **User Query**: *"Show me our trade count and currency volume breakdown for today."*
*   **Tool Executed**: `lch_get_dpg_trade_volume`
*   **Raw Output**: `{"trade_count":8420,"total_volume_usd":12450800000.5,...}`
*   **LLM Summary**: 
    > ### Daily Clearing Volume Report
    > Today, **8,420** trades were cleared. The total volume reached **$12,450,800,000.50 USD**.
    > *   **USD**: $6.50 Billion
    > *   **EUR**: $4.20 Billion
    > *   **GBP**: $1.75 Billion

#### Scenario 2: Collateral Valuation with Haircut Calculations
*   **User Query**: *"Check our Treasury collateral holdings. If the current average interest rate on Treasury Bills is above 3.5%, what is our total collateral valuation after haircut?"*
*   **Tool Executed**: `lch_get_non_cash_collateral` then `ustreasury_get_avg_interest_rates`
*   **Raw Outputs**: 
    *   Collateral holdings: `[{"isin":"US912828GD97","market_value_eur":25000000,"haircut_pct":2}]`
    *   Treasury Bills average rate: `3.690%`
*   **LLM Summary**:
    > ### Collateral Evaluation Summary
    > *   **U.S. Treasury Bill Rate**: Verified at **3.690%** (exceeds the 3.5% threshold).
    > *   **Asset ISIN**: US912828GD97
    > *   **Market Value**: €25,000,000.00 EUR
    > *   **Haircut Applied**: 2.0%
    > *   **Net Collateral Value**: **€24,500,000.00 EUR**

### E. Secure Information Gathering
Users gather information securely because:
1.  **Read-Only Scope Protection**: Bearer tokens prevent LLMs from writing commands or executing updates; the gateway exposes only mapped `GET` queries.
2.  **No Direct DB Injection**: Schema verification blocks any SQL injections; parameters are mapped strictly to designated template variables.
3.  **Comprehensive Audits**: The security operations team can trace every LLM decision path back to the underlying API execution.
