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

clear
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}       Janus Gateway: AWS EKS & Antigravity integration Demo    ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e ""
echo -e "${CYAN}[1/4] Architecture Overview:${NC}"
echo -e "  * Gateway Facade: Deployed under namespace ${GREEN}janus${NC} on AWS EKS cluster."
echo -e "  * SSL/TLS Endpoint: ${GREEN}https://janus.13.134.88.9.nip.io/sse${NC} (Let's Encrypt)"
echo -e "  * Authentication: Secure Bearer Token validation."
echo -e "  * Downstream Services: Dynamic routing to LCH clearing and Treasury yield APIs."
echo -e ""
sleep 2

echo -e "${CYAN}[2/4] Workspace MCP Configuration (.agents/mcp_config.json):${NC}"
echo -e "Showing local workspace agent config that registers Janus as a remote server..."
echo -e ""
echo -e "${YELLOW}"
cat .agents/mcp_config.json
echo -e "${NC}"
sleep 2

echo -e "${CYAN}[3/4] Triggering Antigravity CLI agent session...${NC}"
echo -e "The agent will:"
echo -e "  1. Automatically load the ${GREEN}janus-gateway${NC} remote tools via EKS."
echo -e "  2. Activate the ${GREEN}lch-collateral-reporting${NC} governed compliance skill."
echo -e "  3. Query LCH and Treasury APIs deterministically through the gateway."
echo -e "  4. Compile a structured audit and margin valuation report."
echo -e ""
echo -e "${MAGENTA}Running: agy --print \"Generate a collateral valuation report for LCH member MEM-LCH-002 using the lch-collateral-reporting skill.\"${NC}"
echo -e ""

# Execute agy command
agy --print "Generate a collateral valuation report for LCH member MEM-LCH-002 using the lch-collateral-reporting skill."

echo -e ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}✓ Demo completed successfully!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "How to run interactively in the TUI:"
echo -e "  1. Start the CLI in this directory: ${CYAN}agy${NC}"
echo -e "  2. Type ${CYAN}/mcp${NC} to view registered Janus gateway tools."
echo -e "  3. Ask the agent: ${CYAN}\"Generate collateral report for MEM-LCH-002\"${NC}"
echo -e "${BLUE}================================================================${NC}"
