#!/usr/bin/env pwsh
# Test all API endpoints for Corvid (PowerShell/Windows compatible)
# Usage: .\test_api_endpoints.ps1 [URL]

param(
    [string]$BaseUrl = "http://localhost:8000"
)

$Green = "`e[0;32m"
$Red = "`e[0;31m"
$Yellow = "`e[1;33m"
$NC = "`e[0m"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Corvid API Endpoint Tests" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Testing against: $BaseUrl"
Write-Host ""

$total = 0
$passed = 0
$failed = 0

function Test-Endpoint {
    param(
        [string]$Method,
        [string]$Name,
        [string]$Endpoint,
        [string]$Data = $null
    )

    $script:total++

    try {
        $params = @{
            Uri = "$BaseUrl$Endpoint"
            Method = $Method
            ContentType = "application/json"
            TimeoutSec = 30
        }
        if ($Data) {
            $params.Body = $Data
        }

        $response = Invoke-RestMethod @params -ErrorAction SilentlyContinue
        $statusCode = 200
        
        Write-Host "  $Method $Endpoint ... " -NoNewline
        Write-Host "OK ($statusCode)" -ForegroundColor $Green
        $script:passed++
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  $Method $Endpoint ... " -NoNewline
        Write-Host "FAIL ($statusCode)" -ForegroundColor $Red
        $script:failed++
    }
}

# Health
Write-Host "Health Endpoints" -ForegroundColor Yellow
Test-Endpoint -Method "GET" -Name "Health" -Endpoint "/health"

# IOC Endpoints
Write-Host "`nIOC Endpoints" -ForegroundColor Yellow

# Create test IOC
$iocBody = @{
    type = "ip"
    value = "192.0.2.1"
    tags = @("ps-test")
} | ConvertTo-Json

try {
    $iocResponse = Invoke-RestMethod -Uri "$BaseUrl/api/v1/iocs/" -Method POST -Body $iocBody -ContentType "application/json"
    $iocId = $iocResponse.id
} catch {
    $iocId = $null
}

Test-Endpoint -Method "GET" -Name "List IOCs" -Endpoint "/api/v1/iocs"
Test-Endpoint -Method "GET" -Name "List IOCs paginated" -Endpoint "/api/v1/iocs?limit=10&offset=0"
Test-Endpoint -Method "GET" -Name "List IOCs by type" -Endpoint "/api/v1/iocs?type=ip"

if ($iocId) {
    Test-Endpoint -Method "GET" -Name "Get IOC by ID" -Endpoint "/api/v1/iocs/$iocId"
    Test-Endpoint -Method "DELETE" -Name "Delete IOC" -Endpoint "/api/v1/iocs/$iocId"
}

# Invalid inputs
Test-Endpoint -Method "POST" -Name "Invalid type" -Endpoint "/api/v1/iocs/" -Data '{"type": "invalid", "value": "test"}'
Test-Endpoint -Method "POST" -Name "Empty value" -Endpoint "/api/v1/iocs/" -Data '{"type": "ip", "value": ""}'
Test-Endpoint -Method "POST" -Name "Type mismatch" -Endpoint "/api/v1/iocs/" -Data '{"type": "ip", "value": "not.an.ip"}'

# Valid IOC types
Test-Endpoint -Method "POST" -Name "Valid IP" -Endpoint "/api/v1/iocs/" -Data '{"type": "ip", "value": "8.8.8.8"}'
Test-Endpoint -Method "POST" -Name "Valid domain" -Endpoint "/api/v1/iocs/" -Data '{"type": "domain", "value": "example.com"}'
Test-Endpoint -Method "POST" -Name "Valid URL" -Endpoint "/api/v1/iocs/" -Data '{"type": "url", "value": "https://example.com/test"}'
Test-Endpoint -Method "POST" -Name "Valid MD5" -Endpoint "/api/v1/iocs/" -Data '{"type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}'
Test-Endpoint -Method "POST" -Name "Valid SHA256" -Endpoint "/api/v1/iocs/" -Data '{"type": "hash_sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
Test-Endpoint -Method "POST" -Name "Valid email" -Endpoint "/api/v1/iocs/" -Data '{"type": "email", "value": "test@example.com"}'

# Non-existent
Test-Endpoint -Method "GET" -Name "Non-existent IOC" -Endpoint "/api/v1/iocs/00000000-0000-0000-0000-000000000000"

# Analysis
Write-Host "`nAnalysis Endpoints" -ForegroundColor Yellow
Test-Endpoint -Method "POST" -Name "Analyze single IOC" -Endpoint "/api/v1/iocs/analyze" -Data '{"iocs": [{"type": "ip", "value": "8.8.8.8"}], "context": "test", "priority": "low"}'
Test-Endpoint -Method "POST" -Name "Analyze multiple IOCs" -Endpoint "/api/v1/iocs/analyze" -Data '{"iocs": [{"type": "ip", "value": "8.8.8.8"}, {"type": "domain", "value": "example.com"}], "context": "test", "priority": "medium"}'
Test-Endpoint -Method "POST" -Name "Analyze empty iocs" -Endpoint "/api/v1/iocs/analyze" -Data '{"iocs": [], "context": "test", "priority": "low"}'

Test-Endpoint -Method "GET" -Name "List analyses" -Endpoint "/api/v1/analyses?limit=5"

# Summary
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Total:  $total"
Write-Host "Passed: $passed" -ForegroundColor $Green
Write-Host "Failed: $failed" -ForegroundColor $Red
Write-Host ""

if ($failed -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed" -ForegroundColor Yellow
    exit 0
}
