.PHONY: build install test clean demo-start demo-stop run-mock run-mock-workflow run-keep help

# Detect OS for binary extension
GOOS     := $(shell go env GOOS)
GOPATH   := $(shell go env GOPATH)

ifeq ($(GOOS),windows)
  BIN_EXT := .exe
else
  BIN_EXT :=
endif

GATE_BIN  := bin/portcullis-gate$(BIN_EXT)
KEEP_BIN  := bin/portcullis-keep$(BIN_EXT)
GUARD_BIN := bin/portcullis-guard$(BIN_EXT)

VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
VERSION_PKG := github.com/paclabsnet/PortcullisMCP/internal/version
LDFLAGS     := -ldflags "-X $(VERSION_PKG).Version=$(VERSION)"

# Write deploy/docker-singletenant/.env so docker compose picks up the same version automatically
deploy/docker-singletenant/.env:
	@echo "VERSION=$(VERSION)" > deploy/docker-singletenant/.env

# Build all binaries into bin/
build: deploy/docker-singletenant/.env
	@echo "Building portcullis-gate..."
	@go build $(LDFLAGS) -o $(GATE_BIN) ./cmd/portcullis-gate
	@echo "Building portcullis-keep..."
	@go build $(LDFLAGS) -o $(KEEP_BIN) ./cmd/portcullis-keep
	@echo "Building portcullis-guard..."
	@go build $(LDFLAGS) -o $(GUARD_BIN) ./cmd/portcullis-guard
	@echo "Build complete ($(VERSION)). Binaries in bin/"

# Install portcullis-gate to GOPATH/bin so it can be referenced in MCP client config
install: build
	@echo "Installing portcullis-gate to $(GOPATH)/bin..."
	@go install $(LDFLAGS) ./cmd/portcullis-gate
	@echo ""
	@echo "portcullis-gate installed. Configure your MCP client to launch it:"
	@echo '  { "command": "portcullis-gate", "args": ["-config", "~/.portcullis/gate.yaml"] }'
	@echo ""
	@echo "The MCP client (Claude, Copilot, etc.) will start gate automatically via stdio."

# Run all tests
test:
	@go test ./...

# Remove build artifacts
clean:
	@rm -rf bin/

# Start demo stack (OPA + Keep + Guard + mock backends) via docker compose
demo-start:
	@docker compose -f deploy/docker-singletenant/docker-compose.yml up -d --build
	@echo "Demo stack running. Keep: http://localhost:8080  Guard: http://localhost:8444  OPA: http://localhost:8181"

# Stop demo stack
demo-stop:
	@docker compose -f deploy/docker-singletenant/docker-compose.yml down

# Run the mock enterprise API backend (development only)
run-mock:
	@go run ./examples/mock-enterprise-api

# Run the mock workflow server (development only)
# Simulates an enterprise approval system: receives Keep webhooks, waits APPROVAL_DELAY, deposits to Guard.
# Example: make run-mock-workflow GUARD_URL=http://localhost:8444 GUARD_TOKEN=dev-guard-token
run-mock-workflow:
	@GUARD_URL=$${GUARD_URL:-http://localhost:8444} \
	 GUARD_TOKEN=$${GUARD_TOKEN:-dev-guard-token} \
	 APPROVAL_DELAY=$${APPROVAL_DELAY:-5s} \
	 go run ./examples/mock-workflow-server

# Run portcullis-keep with minimal config (development only)
run-keep:
	@$(KEEP_BIN) -config config/keep-config.minimal.yaml

# Show help
help:
	@echo "PortcullisMCP Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build      - Compile portcullis-gate and portcullis-keep into bin/"
	@echo "  install    - Build and install portcullis-gate to GOPATH/bin"
	@echo "  test       - Run all unit tests"
	@echo "  clean      - Remove build artifacts"
	@echo "  demo-start - Start demo stack (OPA + Keep + Guard + backends) via docker compose"
	@echo "  demo-stop  - Stop demo stack"
	@echo "  run-mock          - Run the mock enterprise API backend (dev only)"
	@echo "  run-mock-workflow - Run the mock workflow approval server (dev only)"
	@echo "  run-keep          - Run portcullis-keep with minimal config (dev only)"
	@echo ""
	@echo "Quick start (development):"
	@echo "  1. make build        # compile binaries"
	@echo "  2. make install      # install portcullis-gate to PATH"
	@echo "  3. make demo-start   # start OPA + demo backends"
	@echo "  4. make run-keep     # start portcullis-keep"
	@echo "  5. Configure your MCP client to launch portcullis-gate"
	@echo "     portcullis-gate is started automatically by the MCP client — do not run it manually"
