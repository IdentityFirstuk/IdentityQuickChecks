# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================

# Okta QuickChecks - Main Module
# ============================================================================

# Okta API Connection Helper
function Connect-OktaOrg {
    param(
        [Parameter(Mandatory)]
        [string]$OrgUrl,
        
        [Parameter(Mandatory)]
        [string]$ApiToken,
        
        [switch]$TrustAllCerts
    )
    
    $ErrorActionPreference = "Stop"
    
    $script:OktaOrgUrl = $OrgUrl.TrimEnd('/')
    $script:OktaApiToken = $ApiToken
    
    $headers = @{
        "Authorization" = "SSWS $ApiToken"
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }
    
    $script:OktaHeaders = $headers
    
    # Test connection
    try {
        $response = Invoke-RestMethod -Uri "$OrgUrl/api/v1/org" -Headers $headers -Method Get
        Write-Host "[OKTA] Connected to organization: $($response.companyName)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "[OKTA] Failed to connect: $($_.Exception.Message)"
        return $false
    }
}

# Helper function to invoke Okta API
function Invoke-OktaApi {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        
        [string]$Method = "GET",
        
        [object]$Body = $null,
        
        [int]$Limit = 200
    )
    
    $ErrorActionPreference = "Stop"
    
    $uri = "$script:OktaOrgUrl/api/v1/$Endpoint"
    $headers = $script:OktaHeaders
    
    $params = @{
        Uri = $uri
        Headers = $headers
        Method = $Method
    }
    
    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }
    
    # Handle pagination for GET requests
    if ($Method -eq "GET") {
        $allResults = @()
        $pageUri = $uri
        $pageCount = 0
        
        while ($pageUri) {
            try {
                $response = Invoke-RestMethod @params -Uri $pageUri
                $allResults += $response
                $pageCount++
                
                # Check for pagination link header
                $nextLink = $response.Headers['Link'] | Where-Object { $_ -match 'rel="next"' }
                if ($nextLink) {
                    $pageUri = ($nextLink -match '<([^>]+)>')[1]
                }
                else {
                    $pageUri = $null
                }
                
                # Safety limit
                if ($pageCount -gt 100) {
                    Write-Warning "Pagination limit reached (100 pages)"
                    break
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limiting - wait and retry
                    Start-Sleep -Seconds 5
                    continue
                }
                throw
            }
        }
        
        return $allResults
    }
    else {
        return Invoke-RestMethod @params
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Connect-OktaOrg',
    'Invoke-OktaApi'
) -ErrorAction SilentlyContinue
