# Snowflake & Concorde API Integration & Mapping Specification

This document provides a technical mapping, structural overview, and architectural roadmap for integrating the **Snowflake Data Warehouse** and the **Concorde Data Platform** (Customer's internal data platform) with the **Janus MCP API Gateway**.

---

## 1. Architectural Integration Principles
To satisfy strict financial data governance, security, and auditability guidelines, the following principles must be enforced:

1. **Governed Facade (No Direct SQL)**: AI agents (such as Claude or Copilot) **must never** generate and execute raw SQL statements directly on Snowflake. Instead, all data retrieval must be mediated via defined, parameterized REST API wrappers (the "Concorde API").
2. **Secrets Decoupling**: Database connection credentials, JWT tokens, and OAuth client secrets are kept out of configurations and resolved dynamically at runtime using the **AWS Secrets Manager** vault provider.
3. **Namespace Isolation**: All tools exposed from the Concorde platform are isolated under a dedicated namespace prefix (e.g., `concorde_`) within the Janus gateway.

---

## 2. API Specifications & Mapping

### A. Snowflake SQL API Reference
Snowflake provides the **SQL API**, a RESTful API to execute SQL statements and manage resources.

*   **API Specification Base**: `https://<org>-<account>.snowflakecomputing.com/api/v2`
*   **Authentication**: JWT Token signed with a private key (using RSA key-pair authentication) or OAuth 2.0.
*   **Key OpenAPI Endpoints**:
    *   `POST /statements`: Submits a SQL statement for execution. Supports parameter binding.
    *   `GET /statements/{statementId}`: Retrieves the status and paginated results of a submitted statement.
    *   `POST /statements/{statementId}/cancel`: Cancels the execution of a running statement.

#### Mapping to Janus Gateway:
To execute queries safely, Janus utilizes **prepared parameter bindings** inside tool mappings. The LLM translates user intent into parameters (e.g., `member_id`, `date`), which Janus binds to a static SQL query template before calling the Snowflake SQL API:

```
[ LLM Client ] ──(Intent: "Get Trades")──> [ Janus Gateway ] 
                                                │
                                    (Injects bounds into template)
                                                ▼
[ Snowflake SQL API ] <──(POST /statements)─────┘
```

---

### B. Concorde REST API (Internal Data Facade)
The Customer's Concorde platform engineers wrap Snowflake tables and S3 files into governed microservices running inside Amazon EKS.

#### 1. Daily Trade Volume (DPG)
*   **Internal API Route**: `GET /api/concorde/dpg/trade-volume?member_id={id}&date={date}`
*   **Mapped Janus Tool**: `concorde_get_dpg_trade_volume`
*   **Janus Template Mapping**:
    *   *Path*: `/api/concorde/dpg/trade-volume`
    *   *Query Parameters*: `member_id={{args.member_id}}`, `date={{args.date}}`

#### 2. Non-Cash Collateral Valuation
*   **Internal API Route**: `GET /api/concorde/collateral/non-cash?member_id={id}`
*   **Mapped Janus Tool**: `concorde_get_non_cash_collateral`
*   **Janus Template Mapping**:
    *   *Path*: `/api/concorde/collateral/non-cash`
    *   *Query Parameters*: `member_id={{args.member_id}}`

#### 3. Clearing Member Status Reports
*   **Internal API Route**: `GET /api/concorde/reports/member-status?member_id={id}`
*   **Mapped Janus Tool**: `concorde_get_member_status_report`
*   **Janus Template Mapping**:
    *   *Path*: `/api/concorde/reports/member-status`
    *   *Query Parameters*: `member_id={{args.member_id}}`

---

## 3. Step-by-Step Action Plan to Reach 100% Production Readiness

To successfully operationalize this integration, the engineering and security teams must execute the following action items:

### Step 1: Deploy REST API Wrappers in Amazon EKS
*   **What needs to be done**: Concorde platform engineers must deploy lightweight REST wrappers (Go, Python/FastAPI, or Spring Boot) that query the underlying Snowflake tables and return structured JSON.
*   **Status**: Pre-configured mock endpoints are currently running inside Janus for testing. These must be replaced with the actual EKS internal URLs.

### Step 2: Configure IAM and Secrets in AWS
*   **What needs to be done**: 
    1. Store Snowflake private keys or API tokens securely in **AWS Secrets Manager** under a path like `prod/concorde/snowflake-auth`.
    2. Enforce OIDC Workload Identity on EKS by associating the Janus gateway ServiceAccount with a role authorized to read the KMS-encrypted secret.
    3. Start the Janus container with the environment variable `VAULT_PROVIDER=aws`.

### Step 3: Register Janus Connections & Bind Secrets
*   **What needs to be done**: Register the Concorde API base URL in the Janus Portal (or via CLI) and bind the authentication headers:
    ```bash
    ./mcp-cli connection add \
      --name "Concorde Data Platform" \
      --url "https://concorde-api.internal/v1" \
      --auth "bearer" \
      --secret "prod/concorde/snowflake-auth" \
      --prefix "concorde_"
    ```

### Step 4: Map Tools and Enforce Client Scopes
*   **What needs to be done**: 
    1. Register the endpoints as tools within the Janus gateway.
    2. Issue restricted Client Access Tokens for downstream AI interfaces (such as Claude Desktop or portal UI agents) and assign them the specific scope pattern `concorde_*` to ensure total isolation.

### Step 5: Connect Telemetry & APM Observability
*   **What needs to be done**: 
    1. Format container stdout logs as JSON so they are parsed automatically by the DataDog agent.
    2. Annotate the Janus EKS pods to allow DataDog to scrape the `/metrics` endpoint.
    3. Initialize the Langfuse SDK in the portal client to capture tracing, costs, and query execution feedback.
