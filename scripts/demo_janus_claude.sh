#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Terminal colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

clear
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}       Janus Gateway: AWS EKS & Claude Code integration Demo    ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e ""
echo -e "${CYAN}[1/4] Architecture Overview:${NC}"
echo -e "  * Gateway Facade: Deployed under namespace ${GREEN}janus${NC} on AWS EKS cluster."
echo -e "  * SSL/TLS Endpoint: ${GREEN}https://janus.13.134.88.9.nip.io/sse${NC} (Let's Encrypt)"
echo -e "  * Authentication: Secure Bearer Token validation."
echo -e "  * Downstream Services: Dynamic routing to LCH clearing and Treasury yield APIs."
echo -e ""
sleep 2

echo -e "${CYAN}[2/4] Claude Code MCP Configuration (.mcp.json):${NC}"
echo -e "Showing the project MCP config that registers Janus as a remote SSE server..."
echo -e ""
echo -e "${YELLOW}"
cat .mcp.json
echo -e "${NC}"
sleep 2

# Allow overriding the gateway token without editing .mcp.json
: "${JANUS_GATEWAY_TOKEN:=highly-secure-mcp-bearer-token-key-for-llm-clients}"
export JANUS_GATEWAY_TOKEN

if ! command -v claude >/dev/null 2>&1; then
  echo -e "${YELLOW}! 'claude' CLI not found. Install Claude Code, then re-run.${NC}"
  echo -e "  https://docs.claude.com/en/docs/claude-code"
  exit 1
fi

echo -e "${CYAN}[3/4] Triggering Claude Code (headless) agent session...${NC}"
echo -e "The agent will:"
echo -e "  1. Load the ${GREEN}janus-gateway${NC} remote MCP tools via EKS (.mcp.json)."
echo -e "  2. Query LCH collateral and Treasury APIs through the gateway."
echo -e "  3. Compile a structured collateral valuation / audit report."
echo -e ""
PROMPT="Using the janus-gateway MCP tools, fetch the non-cash collateral holdings for LCH member MEM-LCH-002 and the latest US Treasury average interest rates, then compile a structured collateral valuation and margin audit report."
echo -e "${MAGENTA}Running: claude -p \"<collateral report prompt>\" --mcp-config .mcp.json --allowedTools \"mcp__janus-gateway\"${NC}"
echo -e ""

claude -p "$PROMPT" \
  --mcp-config .mcp.json \
  --allowedTools "mcp__janus-gateway"

echo -e ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}✓ Demo completed successfully!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "How to run interactively in the TUI:"
echo -e "  1. Start Claude Code in this directory: ${CYAN}claude${NC}"
echo -e "  2. Approve the ${GREEN}janus-gateway${NC} MCP server when prompted (project .mcp.json)."
echo -e "  3. Type ${CYAN}/mcp${NC} to view registered Janus gateway tools."
echo -e "  4. Ask: ${CYAN}\"Generate collateral report for MEM-LCH-002\"${NC}"
echo -e "${BLUE}================================================================${NC}"
