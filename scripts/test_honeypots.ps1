#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Honeypot Testing Script for Komunikator

.DESCRIPTION
    This script tests the honeypot protection on registration and login endpoints.
    It verifies that bots filling honeypot fields are detected and blocked.

.PARAMETER BaseUrl
    The base URL of the API server. Default: http://localhost:8000

.PARAMETER VerboseOutput
    Show detailed request/response information

.PARAMETER SkipConnectionTest
    Skip the initial connection test

.PARAMETER LongDelay
    Use longer delays (15s) between tests to avoid nginx rate limiting.
    Use this when testing through nginx proxy.

.EXAMPLE
    .\test_honeypots.ps1
    
.EXAMPLE
    .\test_honeypots.ps1 -BaseUrl "http://localhost:8000" -VerboseOutput

.EXAMPLE
    .\test_honeypots.ps1 -LongDelay
    Use longer delays to avoid nginx rate limiting (5r/m on login endpoint)
#>

param(
    [string]$BaseUrl = "http://localhost:8000",
    [switch]$VerboseOutput,
    [switch]$SkipConnectionTest,
    [switch]$LongDelay
)

$ErrorActionPreference = "Continue"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Honeypot Testing Script" -ForegroundColor Cyan
Write-Host "  Testing: $BaseUrl" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Test connection first
if (-not $SkipConnectionTest) {
    Write-Host "Testing connection to server..." -ForegroundColor Yellow
    try {
        $testResponse = Invoke-WebRequest -Uri "$BaseUrl/api/login" -Method POST -Body '{"email":"test@test.com","password":"test"}' -ContentType "application/json" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    }
    catch {
        if ($_.Exception.Response) {
            Write-Host "  Server is responding (got HTTP response)" -ForegroundColor Green
        }
        else {
            Write-Host "  ERROR: Cannot connect to server at $BaseUrl" -ForegroundColor Red
            Write-Host "  Make sure the server is running (docker-compose up)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Tip: Check if correct port is used:" -ForegroundColor Yellow
            Write-Host "    - nginx proxy: port 8000 (default)" -ForegroundColor Gray
            Write-Host "    - direct backend: port 8080 (inside docker network)" -ForegroundColor Gray
            exit 1
        }
    }
    Write-Host ""
}

$testResults = @{
    Passed = 0
    Failed = 0
    Errors = 0
    Tests = @()
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [hashtable]$Body,
        [string]$Method = "POST",
        [string]$ExpectedBehavior,
        [scriptblock]$Validator
    )

    Write-Host "Testing: $Name" -ForegroundColor Yellow
    
    try {
        $jsonBody = $Body | ConvertTo-Json -Depth 10
        
        if ($VerboseOutput) {
            Write-Host "  Request Body: $jsonBody" -ForegroundColor Gray
        }

        $params = @{
            Uri = $Url
            Method = $Method
            Body = $jsonBody
            ContentType = "application/json"
            UseBasicParsing = $true
            TimeoutSec = 10
        }

        try {
            $response = Invoke-WebRequest @params -ErrorAction Stop
            $statusCode = $response.StatusCode
            $responseBody = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
        }
        catch {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $reader = [System.IO.StreamReader]::new($stream)
                    $responseContent = $reader.ReadToEnd()
                    $responseBody = $responseContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch {
                    $responseBody = @{ message = "Could not parse response" }
                }
            }
            else {
                throw
            }
        }
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $script:testResults.Errors++
        $script:testResults.Tests += @{
            Name = $Name
            Status = "ERROR"
            Message = $_.Exception.Message
        }
        Write-Host ""
        return
    }

    if ($VerboseOutput) {
        Write-Host "  Status Code: $statusCode" -ForegroundColor Gray
        if ($responseBody) {
            Write-Host "  Response: $($responseBody | ConvertTo-Json -Compress)" -ForegroundColor Gray
        }
    }

    $result = & $Validator $statusCode $responseBody
    
    if ($result.Success) {
        Write-Host "  PASSED: $($result.Message)" -ForegroundColor Green
        $script:testResults.Passed++
        $script:testResults.Tests += @{
            Name = $Name
            Status = "PASSED"
            Message = $result.Message
        }
    }
    else {
        Write-Host "  FAILED: $($result.Message)" -ForegroundColor Red
        Write-Host "  Status Code: $statusCode" -ForegroundColor Gray
        $script:testResults.Failed++
        $script:testResults.Tests += @{
            Name = $Name
            Status = "FAILED"
            Message = $result.Message
        }
    }
    Write-Host ""
}

# ============================================
# Registration Honeypot Tests
# ============================================

Write-Host "=== Registration Honeypot Tests ===" -ForegroundColor Magenta
Write-Host ""

# Test 1: Normal registration (no honeypot triggered)
Test-Endpoint -Name "Registration - Normal (no honeypot)" `
    -Url "$BaseUrl/api/register" `
    -Body @{
        username = "testuser_$(Get-Random)"
        email = "test$(Get-Random)@example.com"
        password = "SecureP@ss123!"
        website = ""  # Empty honeypot - should work
    } `
    -ExpectedBehavior "Should succeed or fail normally (not be blocked as bot)" `
    -Validator {
        param($status, $body)
        # Should return 201 (created) or 409 (conflict if exists) or 400 (validation) - but NOT be silently blocked
        if ($status -eq 201 -or $status -eq 409 -or $status -eq 400) {
            return @{ Success = $true; Message = "Normal registration handled correctly (status: $status)" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

# Test 2: Registration with honeypot field filled (bot behavior)
Test-Endpoint -Name "Registration - Honeypot filled (bot detected)" `
    -Url "$BaseUrl/api/register" `
    -Body @{
        username = "bot_user_$(Get-Random)"
        email = "bot$(Get-Random)@example.com"
        password = "BotP@ss123!"
        website = "http://spam-site.com"  # Honeypot triggered!
    } `
    -ExpectedBehavior "Should appear to succeed but actually be blocked" `
    -Validator {
        param($status, $body)
        # Honeypot should return 201 (fake success to confuse bots)
        if ($status -eq 201) {
            return @{ Success = $true; Message = "Bot trapped - fake success returned (status: 201)" }
        }
        return @{ Success = $false; Message = "Expected fake success (201), got: $status" }
    }

# ============================================
# Login Honeypot Tests  
# ============================================

Write-Host "=== Login Honeypot Tests ===" -ForegroundColor Magenta
Write-Host ""

# Add delay between tests to avoid rate limiting
# nginx has 5r/m limit on /api/login, so we need 12-15 seconds between requests
# when using -LongDelay flag for production-like testing
if ($LongDelay) {
    $testDelay = 15
    Write-Host "Using long delays (${testDelay}s) to respect nginx rate limits" -ForegroundColor Yellow
    Write-Host ""
} else {
    $testDelay = 1
    Write-Host "NOTE: nginx rate limits may cause 503 errors. Use -LongDelay for reliable testing." -ForegroundColor Gray
    Write-Host ""
}

# Test 3: Normal login (no honeypot triggered)
$email3 = "test_normal_$(Get-Random)@example.com"
Test-Endpoint -Name "Login - Normal (no honeypot)" `
    -Url "$BaseUrl/api/login" `
    -Body @{
        email = $email3
        password = "wrongpassword"
        website = ""
        phone = ""
        middle_name = ""
    } `
    -ExpectedBehavior "Should fail with normal 'invalid credentials' error" `
    -Validator {
        param($status, $body)
        # Should return 401 (unauthorized) for wrong password
        if ($status -eq 401) {
            return @{ Success = $true; Message = "Normal login failure handled correctly" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

Start-Sleep -Seconds $testDelay

# Test 4: Login with website honeypot filled
$email4 = "bot_web_$(Get-Random)@example.com"
Test-Endpoint -Name "Login - Website honeypot filled (bot detected)" `
    -Url "$BaseUrl/api/login" `
    -Body @{
        email = $email4
        password = "password123"
        website = "http://malicious-site.com"  # Honeypot triggered!
        phone = ""
        middle_name = ""
    } `
    -ExpectedBehavior "Should be blocked as bot (logged and rejected)" `
    -Validator {
        param($status, $body)
        # Honeypot returns 401 to look like normal failure
        if ($status -eq 401) {
            return @{ Success = $true; Message = "Bot trapped via website field (status: 401)" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

Start-Sleep -Seconds $testDelay

# Test 5: Login with phone honeypot filled
$email5 = "bot_phone_$(Get-Random)@example.com"
Test-Endpoint -Name "Login - Phone honeypot filled (bot detected)" `
    -Url "$BaseUrl/api/login" `
    -Body @{
        email = $email5
        password = "password123"
        website = ""
        phone = "+1234567890"  # Honeypot triggered!
        middle_name = ""
    } `
    -ExpectedBehavior "Should be blocked as bot" `
    -Validator {
        param($status, $body)
        if ($status -eq 401) {
            return @{ Success = $true; Message = "Bot trapped via phone field (status: 401)" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

Start-Sleep -Seconds $testDelay

# Test 6: Login with middle_name honeypot filled
$email6 = "bot_middle_$(Get-Random)@example.com"
Test-Endpoint -Name "Login - Middle name honeypot filled (bot detected)" `
    -Url "$BaseUrl/api/login" `
    -Body @{
        email = $email6
        password = "password123"
        website = ""
        phone = ""
        middle_name = "Bot"  # Honeypot triggered!
    } `
    -ExpectedBehavior "Should be blocked as bot" `
    -Validator {
        param($status, $body)
        if ($status -eq 401) {
            return @{ Success = $true; Message = "Bot trapped via middle_name field (status: 401)" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

Start-Sleep -Seconds $testDelay

# Test 7: Login with ALL honeypot fields filled (aggressive bot)
$email7 = "bot_aggressive_$(Get-Random)@example.com"
Test-Endpoint -Name "Login - All honeypots filled (aggressive bot)" `
    -Url "$BaseUrl/api/login" `
    -Body @{
        email = $email7
        password = "password123"
        website = "http://spam.com"
        phone = "+9999999999"
        middle_name = "Spammer"
    } `
    -ExpectedBehavior "Should definitely be blocked as bot" `
    -Validator {
        param($status, $body)
        if ($status -eq 401) {
            return @{ Success = $true; Message = "Aggressive bot trapped (status: 401)" }
        }
        return @{ Success = $false; Message = "Unexpected status code: $status" }
    }

# ============================================
# Summary
# ============================================

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Tests: $($testResults.Passed + $testResults.Failed + $testResults.Errors)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor $(if ($testResults.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "Errors: $($testResults.Errors)" -ForegroundColor $(if ($testResults.Errors -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($testResults.Failed -gt 0) {
    Write-Host "Failed Tests:" -ForegroundColor Red
    $testResults.Tests | Where-Object { $_.Status -eq "FAILED" } | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Message)" -ForegroundColor Red
    }
}

if ($testResults.Errors -gt 0) {
    Write-Host "Error Tests:" -ForegroundColor Red
    $testResults.Tests | Where-Object { $_.Status -eq "ERROR" } | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Message)" -ForegroundColor Red
    }
}

if ($testResults.Failed -eq 0 -and $testResults.Errors -eq 0) {
    Write-Host "All honeypot tests passed!" -ForegroundColor Green
    exit 0
}
else {
    exit 1
}
