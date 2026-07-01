{ pkgs, ... }:

{
  # Package list for the shell environment
  packages = with pkgs; [
    git
    sqlite
    golangci-lint
    delve # for debugging Go
    just
    docker-compose
  ];

  # Language configuration (matches go.mod 1.26 / Dockerfile / CI)
  languages.go = {
    enable = true;
    package = pkgs.go_1_26;
  };

  # Environment variables for development. JWT_SECRET/GATEWAY_TOKEN must be
  # >= 32 bytes or the fail-closed config refuses to start (dev-only values here).
  env = {
    PORT = "8080";
    DATABASE_PATH = "./mcp-gateway.db";
    VAULT_PROVIDER = "local";
    VAULT_LOCAL_PATH = "./secrets.json";
    JWT_SECRET = "dev-jwt-secret-key-should-be-changed-in-production";
    GATEWAY_TOKEN = "dev-gateway-token-should-be-changed-in-production";
  };

  # Scripts to make common operations easier
  scripts = {
    run-dev.exec = "go run main.go";
    build.exec = "go build -o mcp-gateway main.go";
    lint.exec = "golangci-lint run";
    test.exec = "go test ./...";
  };

  # Message printed when entering the shell
  enterShell = ''
    echo "=================================================="
    echo "  Welcome to the MCP API Gateway Development Shell"
    echo "=================================================="
    echo "  Go version:      $(go version | cut -d' ' -f3)"
    echo "  SQLite version:  $(sqlite3 --version | cut -d' ' -f1,2)"
    echo "  Available scripts:"
    echo "    - run-dev:  Start the development server"
    echo "    - build:    Compile the production binary"
    echo "    - lint:     Lint the Go codebase"
    echo "    - test:     Run tests"
    echo "=================================================="
  '';
}
