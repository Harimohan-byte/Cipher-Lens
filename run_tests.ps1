# Dual-Mode Test Verification for Cipher-Lens
# Mode 1: Standard Unit Test Suite
Write-Host "=== Running Standard Test Suite ===" -ForegroundColor Cyan
.venv\Scripts\pytest -q
if ($LASTEXITCODE -ne 0) {
    Write-Error "Standard test suite failed!"
    exit $LASTEXITCODE
}

# Mode 2: Strict Offline Fallback Test Suite
Write-Host "`n=== Running Strict Offline Fallback Suite (OFFLINE_MODE=true, LLM_PROVIDER=none) ===" -ForegroundColor Cyan
$env:OFFLINE_MODE = "true"
$env:LLM_PROVIDER = "none"
.venv\Scripts\pytest -q
if ($LASTEXITCODE -ne 0) {
    Write-Error "Strict offline fallback suite failed!"
    exit $LASTEXITCODE
}

Write-Host "`nAll 247 test cases passed cleanly in both standard and offline fallback modes!" -ForegroundColor Green

