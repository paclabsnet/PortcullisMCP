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

PLATFORMS := windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
COMPONENTS := gate keep guard

VERSION     := $(shell git describe --tags --exact-match 2>/dev/null || echo "0.4.1")
VERSION_PKG := github.com/paclabsnet/PortcullisMCP/internal/version
LDFLAGS     := -ldflags "-X $(VERSION_PKG).Version=$(VERSION)"

# Write deploy/docker-singletenant/.env so docker compose picks up the same version automatically
deploy/docker-singletenant/.env:
	@echo "VERSION=$(VERSION)" > deploy/docker-singletenant/.env

# Build all binaries for the current platform
build: deploy/docker-singletenant/.env
	@echo "Building portcullis-gate..."
	@go build $(LDFLAGS) -o $(GATE_BIN) ./cmd/portcullis-gate
	@echo "Building portcullis-keep..."
	@go build $(LDFLAGS) -o $(KEEP_BIN) ./cmd/portcullis-keep
	@echo "Building portcullis-guard..."
	@go build $(LDFLAGS) -o $(GUARD_BIN) ./cmd/portcullis-guard
	@echo "Build complete ($(VERSION)). Binaries in bin/"

# Template for generating cross-compilation targets
# $(1): OS, $(2): ARCH, $(3): COMPONENT
define BUILD_TEMPLATE
bin/dist/portcullis-$(3)-$(1)-$(2)$(if $(filter windows,$(1)),.exe,):
	@mkdir -p bin/dist
	@echo "Building $(3) for $(1)/$(2)..."
	@GOOS=$(1) GOARCH=$(2) go build $$(LDFLAGS) -o $$@ ./cmd/portcullis-$(3)
endef

# Generate all targets
$(foreach os,windows darwin linux, \
	$(foreach arch,amd64 arm64, \
		$(foreach comp,$(COMPONENTS), \
			$(eval $(call BUILD_TEMPLATE,$(os),$(arch),$(comp))) \
		) \
	) \
)

# New build-all depends on all generated binaries
ALL_BINARIES := $(foreach os,windows darwin linux, \
	$(foreach arch,amd64 arm64, \
		$(foreach comp,$(COMPONENTS), \
			bin/dist/portcullis-$(comp)-$(os)-$(arch)$(if $(filter windows,$(os)),.exe,) \
		) \
	) \
)

# Cross-compile for all major platforms
build-all: deploy/docker-singletenant/.env $(ALL_BINARIES)
	@echo "Multi-platform build complete. Binaries in bin/dist/"

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
