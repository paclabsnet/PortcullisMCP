# PortcullisMCP Quick Start Script for Windows
# This script sets up and runs the POC environment

Write-Host "=== PortcullisMCP Quick Start ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build binaries
Write-Host "[1/4] Building binaries..." -ForegroundColor Yellow
go build -o bin/portcullis-keep.exe ./cmd/portcullis-keep
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to build portcullis-keep" -ForegroundColor Red
    exit 1
}

go build -o bin/portcullis-gate.exe ./cmd/portcullis-gate
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to build portcullis-gate" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ Binaries built successfully" -ForegroundColor Green
Write-Host ""

# Step 2: Start OPA
Write-Host "[2/4] Starting OPA..." -ForegroundColor Yellow
docker-compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to start OPA. Is Docker running?" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ OPA started on http://localhost:8181" -ForegroundColor Green
Write-Host ""

# Wait for OPA to be ready
Write-Host "[3/4] Waiting for OPA to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
$opaReady = $false
for ($i = 1; $i -le 10; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8181/health" -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $opaReady = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if (-not $opaReady) {
    Write-Host "  ⚠ OPA may not be fully ready yet, but continuing..." -ForegroundColor Yellow
} else {
    Write-Host "  ✓ OPA is ready" -ForegroundColor Green
}
Write-Host ""

# Step 4: Instructions
Write-Host "[4/4] Starting services..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Run these commands in separate terminals:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Terminal 1 (Mock HTTP MCP Server):" -ForegroundColor White
Write-Host "    go run .\examples\mock-enterprise-api" -ForegroundColor Gray
Write-Host ""
Write-Host "  Terminal 2 (Keep):" -ForegroundColor White
Write-Host "    .\bin\portcullis-keep.exe -config config\keep-config.minimal.yaml" -ForegroundColor Gray
Write-Host ""
Write-Host "  Terminal 3 (Gate):" -ForegroundColor White
Write-Host "    .\bin\portcullis-gate.exe -config config\gate-config.minimal.yaml" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop OPA when done:" -ForegroundColor Cyan
Write-Host "    docker-compose down" -ForegroundColor Gray
Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
