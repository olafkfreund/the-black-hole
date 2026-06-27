#!/usr/bin/env bash
set -euo pipefail

# 1. Clean and build everything
echo "=== Step 1: Rebuilding all target binaries ==="
mkdir -p dist
rm -rf dist/*

# Build Gateway Server
GOOS=linux GOARCH=amd64 go build -o dist/mcp-gateway-linux-amd64 main.go
GOOS=darwin GOARCH=amd64 go build -o dist/mcp-gateway-darwin-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -o dist/mcp-gateway-darwin-arm64 main.go
GOOS=windows GOARCH=amd64 go build -o dist/mcp-gateway-windows-amd64.exe main.go

# Build Admin CLI Client
GOOS=linux GOARCH=amd64 go build -o dist/mcp-cli-linux-amd64 cmd/mcp-cli/main.go
GOOS=darwin GOARCH=amd64 go build -o dist/mcp-cli-darwin-amd64 cmd/mcp-cli/main.go
GOOS=darwin GOARCH=arm64 go build -o dist/mcp-cli-darwin-arm64 cmd/mcp-cli/main.go
GOOS=windows GOARCH=amd64 go build -o dist/mcp-cli-windows-amd64.exe cmd/mcp-cli/main.go

# 2. Build SBOM and run generator
echo "=== Step 2: Generating SPDX 2.3 SBOM ==="
go build -o sbom-gen cmd/sbom-gen/main.go
./sbom-gen go.mod dist/sbom.spdx.json
rm sbom-gen

# 3. Calculate checksum hashes
echo "=== Step 3: Generating SHA256 hashes ==="
cd dist
sha256sum * > checksums.txt
cd ..

# 4. Create Git Tag and push
echo "=== Step 4: Tagging version ==="
git tag -fa v0.9 -m "Release v0.9"
git push origin v0.9 -f

# 5. Create GitHub Release
echo "=== Step 5: Publishing GitHub Release v0.9 ==="
gh release create v0.9 dist/* --title "Release v0.9" --notes "First beta release of The Black Hole: Enterprise-grade MCP API Gateway & Portal."
echo "Release v0.9 created successfully."
