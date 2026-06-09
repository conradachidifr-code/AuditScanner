#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigFile,
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string]$Auditor = $env:USERNAME,
    [string]$OutputPath,
    [switch]$DryRun,
    [string[]]$SkipControls = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:ControlSeverity = @{}
$Script:SessionLogFile = $null
$Script:SessionStartTime = Get-Date

$validDomains = @('LOG', 'IAM', 'DET', 'DAT', 'GOV', 'ORG', 'NET', 'CIC', 'BCK', 'INC', 'WRK')

if ($PSScriptRoot) {
    $scriptRoot = $PSScriptRoot
}
else {
    $scriptRoot = (Get-Location).Path
}

if (-not $ConfigFile) {
    $ConfigFile = Join-Path $scriptRoot 'accounts.json'
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptRoot 'output'
}

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
        default { Write-Host $entry -ForegroundColor White }
    }

    if ($Script:SessionLogFile) {
        Add-Content -Path $Script:SessionLogFile -Value $entry -Encoding UTF8
    }
}

function Invoke-AWSCLI {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $cliArgs = @($Arguments) + @('--output', 'json', '--region', $Region)

    if ($env:AWS_ACCESS_KEY_ID) {
        $output = & aws @cliArgs 2>&1
    }
    else {
        $profileName = $env:AWS_PROFILE
        if (-not $profileName) {
            return $null
        }
        $output = & aws @cliArgs '--profile' $profileName 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $outputText = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($outputText)) {
        return $null
    }

    return ($outputText | ConvertFrom-Json)
}

function New-AuditResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ControlId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'PARTIAL', 'NOT_TESTED')]
        [string]$Status,

        $Evidence = $null,
        [string]$Notes = ''
    )

    $severity = 'P2'
    if ($Script:ControlSeverity.ContainsKey($ControlId)) {
        $severity = $Script:ControlSeverity[$ControlId]
    }

    return [PSCustomObject]@{
        Timestamp   = (Get-Date).ToString('o')
        AccountId   = $AccountId
        AccountName = $AccountName
        Region      = $Region
        ControlId   = $ControlId
        Status      = $Status
        Evidence    = $Evidence
        Notes       = $Notes
        Severity    = $severity
    }
}

function Get-GlobalControlGate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ControlId
    )

    if ($Region -eq 'eu-west-1') {
        return $null
    }

    return New-AuditResult `
        -AccountId $AccountId `
        -AccountName $AccountName `
        -Region $Region `
        -ControlId $ControlId `
        -Status 'NOT_TESTED' `
        -Evidence $null `
        -Notes 'Global control - checked in eu-west-1 only'
}

function New-WorkshopControlResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ControlId,

        [Parameter(Mandatory = $true)]
        [string]$Notes
    )

    return New-AuditResult `
        -AccountId $AccountId `
        -AccountName $AccountName `
        -Region $Region `
        -ControlId $ControlId `
        -Status 'NOT_TESTED' `
        -Evidence $null `
        -Notes $Notes
}

function New-NullApiPartialResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ControlId
    )

    return New-AuditResult `
        -AccountId $AccountId `
        -AccountName $AccountName `
        -Region $Region `
        -ControlId $ControlId `
        -Status 'PARTIAL' `
        -Evidence $null `
        -Notes 'API call returned null - possible permission issue'
}

function Clear-AccountSession {
    Remove-Item Env:AWS_ACCESS_KEY_ID -ErrorAction SilentlyContinue
    Remove-Item Env:AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:AWS_PROFILE -ErrorAction SilentlyContinue
}

function Set-AccountSession {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$RoleArn
    )

    Clear-AccountSession

    $sessionName = 'AuditScan-{0}-{1}' -f $AccountId, (Get-Date -Format 'HHmm')
    $assumeArgs = @(
        'sts', 'assume-role',
        '--role-arn', $RoleArn,
        '--role-session-name', $sessionName,
        '--output', 'json'
    )

    $output = & aws @assumeArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($output | Out-String).Trim()
        Write-AuditLog -Message "Failed to assume role for $AccountName ($AccountId): $errorText" -Level WARN
        return $false
    }

    $outputText = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($outputText)) {
        Write-AuditLog -Message "Empty response when assuming role for $AccountName ($AccountId)" -Level WARN
        return $false
    }

    $credentials = ($outputText | ConvertFrom-Json).Credentials
    if (-not $credentials) {
        Write-AuditLog -Message "No credentials returned for $AccountName ($AccountId)" -Level WARN
        return $false
    }

    $env:AWS_ACCESS_KEY_ID = $credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = $credentials.SessionToken

    return $true
}

function Get-AccountsFromConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }

    $rawConfig = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    if (-not $rawConfig.default_role_name) {
        throw 'Config missing required field: default_role_name'
    }
    if (-not $rawConfig.default_regions) {
        throw 'Config missing required field: default_regions'
    }
    if (-not $rawConfig.accounts) {
        throw 'Config missing required field: accounts'
    }

    $accounts = @()
    foreach ($entry in $rawConfig.accounts) {
        if (-not $entry.id) {
            throw 'Account entry missing required field: id'
        }
        if (-not $entry.name) {
            throw 'Account entry missing required field: name'
        }

        $roleArn = $entry.role_arn
        if (-not $roleArn) {
            $roleArn = 'arn:aws:iam::{0}:role/{1}' -f $entry.id, $rawConfig.default_role_name
        }

        $regions = $entry.regions
        if (-not $regions) {
            $regions = @($rawConfig.default_regions)
        }

        $skip = $false
        if ($entry.PSObject.Properties.Name -contains 'skip') {
            $skip = [bool]$entry.skip
        }

        $skipReason = ''
        if ($entry.PSObject.Properties.Name -contains 'skip_reason') {
            $skipReason = [string]$entry.skip_reason
        }

        $accounts += [PSCustomObject]@{
            id          = [string]$entry.id
            name        = [string]$entry.name
            role_arn    = [string]$roleArn
            regions     = @($regions)
            skip        = $skip
            skip_reason = $skipReason
        }
    }

    return ,@{
        default_role_name = [string]$rawConfig.default_role_name
        default_regions   = @($rawConfig.default_regions)
        accounts          = $accounts
    }
}

function Get-ProfilesFromConfig {
    if ($env:AWS_CONFIG_FILE) {
        $configPath = $env:AWS_CONFIG_FILE
    }
    elseif ($env:USERPROFILE) {
        $configPath = Join-Path $env:USERPROFILE '.aws\config'
    }
    else {
        $configPath = Join-Path $HOME '.aws/config'
    }

    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "AWS config file not found: $configPath"
    }

    $profiles = @()
    $currentProfile = $null
    $lines = Get-Content -LiteralPath $configPath -Encoding UTF8

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[(.+)\]$') {
            $sectionName = $Matches[1]
            if ($sectionName -like 'profile *') {
                $currentProfile = $sectionName.Substring(8)
            }
            else {
                $currentProfile = $null
            }
            continue
        }

        if ($currentProfile -and $trimmed -match '^sso_account_id\s*=\s*(.+)$') {
            $accountId = $Matches[1].Trim()
            $profiles += [PSCustomObject]@{
                Name      = $currentProfile
                AccountId = $accountId
            }
        }
    }

    return $profiles
}

function Test-AccountConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        $Account
    )

    $result = [PSCustomObject]@{
        AccountId   = $Account.id
        AccountName = $Account.name
        Status      = 'FAILED'
        Identity    = $null
        Error       = $null
    }

    try {
        $sessionOk = Set-AccountSession -AccountId $Account.id -AccountName $Account.name -RoleArn $Account.role_arn
        if (-not $sessionOk) {
            $result.Error = 'Failed to assume role'
            return $result
        }

        $identityOutput = & aws sts get-caller-identity --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $result.Error = ($identityOutput | Out-String).Trim()
            return $result
        }

        $identityText = ($identityOutput | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($identityText)) {
            $result.Error = 'Empty response from get-caller-identity'
            return $result
        }

        $identity = $identityText | ConvertFrom-Json
        $result.Status = 'OK'
        $result.Identity = $identity.Arn
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        Clear-AccountSession
    }

    return $result
}

function Get-SummaryRow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $passed = 0
    $failed = 0
    $partial = 0
    $notTested = 0

    foreach ($item in $Results) {
        switch ($item.Status) {
            'PASS'       { $passed++ }
            'FAIL'       { $failed++ }
            'PARTIAL'    { $partial++ }
            'NOT_TESTED' { $notTested++ }
        }
    }

    return [PSCustomObject]@{
        Account    = $AccountName
        Passed     = $passed
        Failed     = $failed
        Partial    = $partial
        NotTested  = $notTested
    }
}

# --- Main execution ---

if ($validDomains -notcontains $Domain) {
    Write-Error "Invalid domain '$Domain'. Must be one of: $($validDomains -join ', ')"
    exit 1
}

$errorsPath = Join-Path $OutputPath 'errors'
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $errorsPath)) {
    New-Item -ItemType Directory -Path $errorsPath -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
$Script:SessionLogFile = Join-Path $errorsPath ("AuditSession_{0}.log" -f $timestamp)

$configSource = 'config'
$defaultRegions = @()
$accounts = @()

try {
    $config = Get-AccountsFromConfig -Path $ConfigFile
    $defaultRegions = @($config.default_regions)
    $accounts = @($config.accounts)
}
catch {
    Write-AuditLog -Message $_.Exception.Message -Level WARN
    Write-AuditLog -Message 'Falling back to AWS profile discovery from ~/.aws/config' -Level WARN
    $configSource = 'profiles'

    $profiles = Get-ProfilesFromConfig
    $fallbackRoleName = 'CCOE_DataRead'
    $defaultRegions = @('eu-west-1', 'eu-west-2', 'eu-west-3')

    foreach ($profile in $profiles) {
        $roleArn = 'arn:aws:iam::{0}:role/{1}' -f $profile.AccountId, $fallbackRoleName
        $accounts += [PSCustomObject]@{
            id          = [string]$profile.AccountId
            name        = [string]$profile.Name
            role_arn    = $roleArn
            regions     = @($defaultRegions)
            skip        = $false
            skip_reason = ''
        }
    }
}

$regionBanner = ($defaultRegions -join ', ')
if ($accounts.Count -gt 0 -and $configSource -eq 'config') {
    $allAccountRegions = @()
    foreach ($account in $accounts) {
        foreach ($region in $account.regions) {
            if ($allAccountRegions -notcontains $region) {
                $allAccountRegions += $region
            }
        }
    }
    if ($allAccountRegions.Count -gt 0) {
        $regionBanner = ($allAccountRegions -join ', ')
    }
}

Write-Host '===================================='
Write-Host 'AWS Audit Scanner'
Write-Host ('Domain  : {0}' -f $Domain)
Write-Host ('Accounts: {0}' -f $accounts.Count)
Write-Host ('Regions : {0}' -f $regionBanner)
Write-Host ('Auditor : {0}' -f $Auditor)
Write-Host ('DryRun  : {0}' -f $DryRun.IsPresent)
Write-Host '===================================='

Write-AuditLog -Message "Session started. Domain=$Domain Accounts=$($accounts.Count) DryRun=$($DryRun.IsPresent)"

if ($DryRun) {
    $dryRunResults = @()

    foreach ($account in $accounts) {
        if ($account.skip) {
            $dryRunResults += [PSCustomObject]@{
                Name      = $account.name
                AccountId = $account.id
                Status    = 'SKIPPED'
                Identity  = $null
                Error     = $account.skip_reason
            }
            continue
        }

        $connectivity = Test-AccountConnectivity -Account $account
        $dryRunResults += [PSCustomObject]@{
            Name      = $connectivity.AccountName
            AccountId = $connectivity.AccountId
            Status    = $connectivity.Status
            Identity  = $connectivity.Identity
            Error     = $connectivity.Error
        }
    }

    $dryRunResults | Format-Table Name, AccountId, Status, Identity, Error -AutoSize | Out-String | Write-Host
    Write-AuditLog -Message 'Dry run completed'
    exit 0
}

$domainModulePath = Join-Path $scriptRoot ('domains\{0}.ps1' -f $Domain)
if (-not (Test-Path -LiteralPath $domainModulePath)) {
    Write-Error "Domain module not found: $domainModulePath"
    exit 1
}

. $domainModulePath

if (-not (Get-Variable -Name 'DomainSeverity' -ErrorAction SilentlyContinue)) {
    Write-Error "Domain module $Domain.ps1 must define `$DomainSeverity hashtable"
    exit 1
}

foreach ($controlId in $DomainSeverity.Keys) {
    $Script:ControlSeverity[$controlId] = $DomainSeverity[$controlId]
}

if (-not (Get-Command -Name 'Get-DomainChecks' -ErrorAction SilentlyContinue)) {
    Write-Error "Domain module $Domain.ps1 must define Get-DomainChecks"
    exit 1
}

$domainChecks = Get-DomainChecks
if (-not $domainChecks) {
    Write-Error "Get-DomainChecks returned no checks for domain $Domain"
    exit 1
}

$summaryRows = @()
$allAccountResults = @{}

foreach ($account in $accounts) {
    if ($account.skip) {
        Write-AuditLog -Message "Skipped account $($account.name) ($($account.id)): $($account.skip_reason)" -Level WARN
        continue
    }

    Write-Host ('--- Account: {0} ({1}) ---' -f $account.name, $account.id)

    $sessionOk = Set-AccountSession -AccountId $account.id -AccountName $account.name -RoleArn $account.role_arn
    if (-not $sessionOk) {
        Write-AuditLog -Message "Could not establish session for $($account.name) ($($account.id))" -Level ERROR

        $accountResults = @()
        foreach ($region in $account.regions) {
            foreach ($controlId in $domainChecks.Keys) {
                $accountResults += New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'NOT_TESTED' `
                    -Evidence $null `
                    -Notes 'Could not assume role for account'
            }
        }

        $allAccountResults[$account.name] = $accountResults
        $summaryRows += Get-SummaryRow -AccountName $account.name -Results $accountResults
        Clear-AccountSession
        continue
    }

    $accountResults = @()

    foreach ($region in $account.regions) {
        Write-Host ('  Region: {0}' -f $region)

        foreach ($controlId in $domainChecks.Keys) {
            $checkBlock = $domainChecks[$controlId]

            if ($SkipControls -contains $controlId) {
                $accountResults += New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'NOT_TESTED' `
                    -Evidence $null `
                    -Notes 'Skipped by parameter'
                continue
            }

            $result = $null
            try {
                $result = & $checkBlock -AccountId $account.id -AccountName $account.name -Region $region
            }
            catch {
                $result = New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'PARTIAL' `
                    -Evidence $null `
                    -Notes ("Exception: {0}" -f $_.Exception.Message)
            }

            if (-not $result) {
                $result = New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'PARTIAL' `
                    -Evidence $null `
                    -Notes 'Check returned no result'
            }

            $accountResults += $result

            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) {
                Write-Host ('    {0}: {1}' -f $controlId, $result.Status)
            }
        }
    }

    Clear-AccountSession

    $outputFile = Join-Path $OutputPath ('{0}_{1}_{2}_{3}.json' -f $account.name, $account.id, $Domain, $timestamp)
    $outputObject = @{
        metadata = @{
            account_id   = $account.id
            account_name = $account.name
            domain       = $Domain
            auditor      = $Auditor
            timestamp    = $timestamp
            role_arn     = $account.role_arn
            regions      = @($account.regions)
        }
        results = @($accountResults)
    }

    $outputObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-AuditLog -Message "Written: $outputFile"

    $allAccountResults[$account.name] = $accountResults
    $summaryRows += Get-SummaryRow -AccountName $account.name -Results $accountResults
}

Write-Host ''
Write-Host 'Summary'
$summaryDisplay = foreach ($row in $summaryRows) {
    [PSCustomObject]@{
        Account     = $row.Account
        Passed      = $row.Passed
        Failed      = $row.Failed
        Partial     = $row.Partial
        'Not Tested' = $row.NotTested
    }
}
$summaryDisplay | Format-Table -AutoSize | Out-String | Write-Host

$elapsed = (Get-Date) - $Script:SessionStartTime
Write-Host ('Total elapsed time: {0:g}' -f $elapsed)
Write-AuditLog -Message ("Session completed in {0:g}" -f $elapsed)
