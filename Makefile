.PHONY: build test clean opa-start opa-stop run-mock run-keep run-gate help

# Build both binaries
build:
	@echo "Building portcullis-keep..."
	@go build -o bin/portcullis-keep.exe ./cmd/portcullis-keep
	@echo "Building portcullis-gate..."
	@go build -o bin/portcullis-gate.exe ./cmd/portcullis-gate
	@echo "Build complete. Binaries in bin/"

# Run all tests
test:
	@echo "Running tests..."
	@go test ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@if exist bin rmdir /s /q bin
	@echo "Clean complete."

# Start OPA with docker-compose
opa-start:
	@echo "Starting OPA..."
	@docker-compose up -d
	@echo "OPA running on http://localhost:8181"

# Stop OPA
opa-stop:
	@echo "Stopping OPA..."
	@docker-compose down

# Run mock HTTP MCP server
run-mock:
	@echo "Starting mock HTTP MCP server..."
	@go run .\examples\mock-enterprise-api

# Run portcullis-keep (requires OPA and mock server to be running)
run-keep:
	@echo "Starting portcullis-keep..."
	@.\bin\portcullis-keep.exe -config config/keep-config.minimal.yaml

# Run portcullis-gate (requires keep to be running)
run-gate:
	@echo "Starting portcullis-gate..."
	@.\bin\portcullis-gate.exe -config config/gate-config.minimal.yaml

# Show help
help:
	@echo "PortcullisMCP Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build      - Build both portcullis-keep and portcullis-gate"
	@echo "  test       - Run all unit tests"
	@echo "  clean      - Remove build artifacts"
	@echo "  opa-start  - Start OPA using docker-compose"
	@echo "  opa-stop   - Stop OPA"
	@echo "  run-mock   - Run the mock HTTP MCP server"
	@echo "  run-keep   - Run portcullis-keep with minimal config"
	@echo "  run-gate   - Run portcullis-gate with minimal config"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make build"
	@echo "  2. make opa-start"
	@echo "  3. make run-mock    (in one terminal)"
	@echo "  4. make run-keep    (in another terminal)"
	@echo "  5. make run-gate    (in a third terminal)"
