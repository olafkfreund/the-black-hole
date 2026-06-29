# Concorde Data Platform: Step-by-Step Janus Integration Walkthrough

This guide provides a reproducible, step-by-step walk-through for integrating the Customer's **Concorde Data Platform** (a secure clearing data platform built on Snowflake) with **Janus**.

We will walk through a real-life scenario: **Exposing daily cleared trade volumes and non-cash collateral asset valuations to clearing member AI assistants.**

---

## 1. Scenario Overview
*   **Source Data**: Snowflake database tables containing raw clearing data:
    *   `CONCORDE_DB.PUBLIC.DAILY_TRADE_VOLUMES`
    *   `CONCORDE_DB.PUBLIC.NON_CASH_COLLATERAL`
*   **Requirement**: Expose this data securely via natural language (MCP tools) to LLM clients, guaranteeing that:
    1.  The LLM has no direct SQL access to Snowflake.
    2.  Clearing member separation is strictly enforced (members can only view their own ID).
    3.  All queries are authenticated and audited.

---

## 2. Step-by-Step Implementation Guide

### Step 1: Build & Deploy the REST API Wrapper (Concorde side)
Concorde platform engineers deploy a lightweight microservice inside Amazon EKS to serve as a secure gatekeeper over Snowflake. Below is a sample Go REST API implementation query wrapper:

```go
// main.go (Concorde microservice)
package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	_ "github.com/snowflakedb/gosnowflake"
)

type TradeVolume struct {
	MemberID   string  `json:"member_id"`
	TradeDate  string  `json:"trade_date"`
	TradeCount int     `json:"trade_count"`
	VolumeUSD  float64 `json:"volume_usd"`
}

func main() {
	// Establish secure connection to Snowflake
	db, err := sql.Open("snowflake", "concorde_user:pass@my_org-my_acct/CONCORDE_DB")
	if err != nil {
		log.Fatalf("Failed to connect to Snowflake: %v", err)
	}
	defer db.Close()

	// Expose endpoint
	http.HandleFunc("/v1/dpg/trade-volume", func(w http.ResponseWriter, r *http.Request) {
		// Enforce auth header verification
		if r.Header.Get("Authorization") != "Bearer secret-concorde-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		memberID := r.URL.Query().Get("member_id")
		date := r.URL.Query().Get("date")

		// Query Snowflake securely using parameterized placeholders
		row := db.QueryRowContext(r.Context(), 
			"SELECT member_id, trade_date, trade_count, volume_usd FROM DAILY_TRADE_VOLUMES WHERE member_id = ? AND trade_date = ?", 
			memberID, date)

		var t TradeVolume
		if err := row.Scan(&t.MemberID, &t.TradeDate, &t.TradeCount, &t.VolumeUSD); err != nil {
			http.Error(w, "Record not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
	})

	log.Println("Concorde service listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Step 2: Store Service Credentials in the Vault
Store the microservice token (`Bearer secret-concorde-token`) securely in the Janus Vault.

### Using the Janus Admin Portal:
1.  Navigate to the **Settings** page.
2.  Locate the **Security Vault Proxy Configuration** card.
3.  Add a new secret:
    *   **Secret Key Reference Path**: `prod/concorde/api-token`
    *   **Secret Value**: `Bearer secret-concorde-token`
4.  Click **Store Secret Securely**.

---

## Step 3: Register the Concorde API Connection
Define the base route and credential mappings in Janus to connect it to the microservice.

### Using the SRE Command Line:
```bash
./mcp-cli connection add \
  --name "Concorde Core Service" \
  --url "https://concorde-api.eks.internal/v1" \
  --auth "bearer" \
  --secret "prod/concorde/api-token" \
  --prefix "concorde_"
```

*   **Prefix (`concorde_`)**: Ensures all exposed tools are isolated under names like `concorde_get_dpg_trade_volume` to prevent conflict with other business units.

---

## Step 4: Map the Endpoint as an MCP Tool
Expose the specific query path `/dpg/trade-volume` as a parameterized tool, translating parameters using JSON Schema.

### Using the SRE Command Line:
```bash
./mcp-cli endpoint add \
  --conn-id "<concorde-connection-uuid>" \
  --name "get_dpg_trade_volume" \
  --desc "Retrieve daily cleared trade counts and USD valuations for a member on a specific date" \
  --path "/dpg/trade-volume?member_id={{args.member_id}}&date={{args.date}}" \
  --method "GET"
```

### JSON Schema mapping automatically verified:
When this tool is called, Janus binds variables matching this schema:
```json
{
  "type": "object",
  "properties": {
    "member_id": {
      "type": "string",
      "description": "Clearing member ID (e.g. MEM-LCH-001)"
    },
    "date": {
      "type": "string",
      "description": "ISO date YYYY-MM-DD"
    }
  },
  "required": ["member_id", "date"]
}
```

---

## Step 5: Test and Verify Client Execution
Now, clearing member developers connect their AI assistants (e.g., Claude Desktop) to Janus.

### A. Client Tool Discovery (`tools/list`)
The AI assistant checks the available capabilities and discovers the tool:
```json
{
  "name": "concorde_get_dpg_trade_volume",
  "description": "Retrieve daily cleared trade counts and USD valuations for a member on a specific date",
  "inputSchema": {
    "type": "object",
    "properties": {
      "member_id": {"type": "string", "description": "Clearing member ID (e.g. MEM-LCH-001)"},
      "date": {"type": "string", "description": "ISO date YYYY-MM-DD"}
    },
    "required": ["member_id", "date"]
  }
}
```

### B. Executing the Tool call (`tools/call`)
When a user asks: *"What was our cleared volume for MEM-LCH-001 on June 29, 2026?"*, the client executes:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "concorde_get_dpg_trade_volume",
    "arguments": {
      "member_id": "MEM-LCH-001",
      "date": "2026-06-29"
    }
  },
  "id": 1
}
```

### C. Janus Dynamic Mediation Flow:
1.  Janus intercepts the call and verifies the client token's scope (e.g. `concorde_*` is authorized).
2.  Janus resolves `prod/concorde/api-token` from the Secrets Vault (`Bearer secret-concorde-token`).
3.  Janus binds the arguments and issues a REST call:
    `GET https://concorde-api.eks.internal/v1/dpg/trade-volume?member_id=MEM-LCH-001&date=2026-06-29`
    *Header: Authorization: Bearer secret-concorde-token*
4.  The Concorde service fetches parameters, executes the prepared query on Snowflake, and returns structured JSON back to Janus.
5.  Janus sanitizes response headers, logs the execution latency to Audit logs/Prometheus, and returns the payload to the LLM client:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"member_id\":\"MEM-LCH-001\",\"trade_date\":\"2026-06-29\",\"trade_count\":14502,\"volume_usd\":245008000.50}"
      }
    ]
  },
  "id": 1
}
```
6.  The AI assistant parses the JSON and presents a natural language summary to the clearing member.
