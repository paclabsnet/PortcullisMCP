.PHONY: build install test clean opa-start opa-stop run-mock run-keep help

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

# Write .env so docker compose picks up the same version automatically
.env:
	@echo "VERSION=$(VERSION)" > .env

# Build all binaries into bin/
build: .env
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

# Start OPA + backends with docker-compose
opa-start:
	@docker-compose up -d
	@echo "OPA running on http://localhost:8181"

# Stop docker-compose services
opa-stop:
	@docker-compose down

# Run the mock enterprise API backend (development only)
run-mock:
	@go run ./examples/mock-enterprise-api

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
	@echo "  opa-start  - Start OPA + backends via docker-compose"
	@echo "  opa-stop   - Stop docker-compose services"
	@echo "  run-mock   - Run the mock enterprise API backend (dev only)"
	@echo "  run-keep   - Run portcullis-keep with minimal config (dev only)"
	@echo ""
	@echo "Quick start (development):"
	@echo "  1. make build        # compile binaries"
	@echo "  2. make install      # install portcullis-gate to PATH"
	@echo "  3. make opa-start    # start OPA + demo backends"
	@echo "  4. make run-keep     # start portcullis-keep"
	@echo "  5. Configure your MCP client to launch portcullis-gate"
	@echo "     portcullis-gate is started automatically by the MCP client — do not run it manually"
