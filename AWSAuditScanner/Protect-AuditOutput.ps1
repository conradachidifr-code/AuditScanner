#Requires -Version 5.1
<#
.SYNOPSIS
    Anonymize AWS Audit Scanner output for sharing with an AI audit evaluator.

.DESCRIPTION
    Copies scan output (JSON results, evidence, diagnostics, session logs) to a new
    folder with account names, IDs, profiles, ARNs, resource identifiers, auditor
    identity, and local file paths removed or replaced with stable pseudonyms.

    The anonymized output preserves control IDs, statuses, severities, regions,
    evidence structure, and counts so an AI evaluator can assess audit quality
    without seeing real AWS account or resource identifiers.

    IMPORTANT: Do not share the optional mapping file with the AI evaluator.
    It is the only file that links pseudonyms back to real account names.

.PARAMETER InputPath
    Source output folder (default: ./output).

.PARAMETER OutputPath
    Destination folder for anonymized files (default: ./output/anonymized).

.PARAMETER ConfigFile
    accounts.json used to discover account names, IDs, and profile names.

.PARAMETER MappingFile
  Where to write the pseudonym mapping for your internal records only.
  Default: ./output/anonymization-map.local.json

.PARAMETER Force
    Overwrite the output folder if it already exists.

.EXAMPLE
    .\Protect-AuditOutput.ps1

.EXAMPLE
    .\Protect-AuditOutput.ps1 -InputPath .\output -OutputPath .\share\audit-review
#>

[CmdletBinding()]
param(
    [string]$InputPath,
    [string]$OutputPath,
    [string]$ConfigFile,
    [string]$MappingFile,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSScriptRoot) {
    $scriptRoot = $PSScriptRoot
}
else {
    $scriptRoot = (Get-Location).Path
}

if (-not $InputPath) {
    $InputPath = Join-Path $scriptRoot 'output'
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $InputPath 'anonymized'
}

if (-not $ConfigFile) {
    $ConfigFile = Join-Path $scriptRoot 'accounts.json'
}

if (-not $MappingFile) {
    $MappingFile = Join-Path $InputPath 'anonymization-map.local.json'
}

$Script:Anonymization = @{
    AccountIdToPseudonym   = @{}
    AccountNameToPseudonym = @{}
    ProfileToPseudonym     = @{}
    RoleArnToPseudonym     = @{}
    ResourceCounters       = @{}
    NextAccountIndex       = 1
}

function Add-AnonymizationAccount {
    param(
        [string]$AccountId,
        [string]$AccountName,
        [string]$ProfileName,
        [string]$RoleArn
    )

    if ([string]::IsNullOrWhiteSpace($AccountId)) {
        return
    }

    if (-not $Script:Anonymization.AccountIdToPseudonym.ContainsKey($AccountId)) {
        $pseudonym = 'ACCOUNT-{0:D3}' -f $Script:Anonymization.NextAccountIndex
        $Script:Anonymization.NextAccountIndex++
        $Script:Anonymization.AccountIdToPseudonym[$AccountId] = $pseudonym
    }

    $accountPseudonym = $Script:Anonymization.AccountIdToPseudonym[$AccountId]

    if (-not [string]::IsNullOrWhiteSpace($AccountName)) {
        $Script:Anonymization.AccountNameToPseudonym[$AccountName] = $accountPseudonym
    }

    if (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        $Script:Anonymization.ProfileToPseudonym[$ProfileName] = ('PROFILE-{0}' -f $accountPseudonym)
    }

    if (-not [string]::IsNullOrWhiteSpace($RoleArn)) {
        $Script:Anonymization.RoleArnToPseudonym[$RoleArn] = '[REDACTED-ROLE-ARN]'
    }
}

function Initialize-AnonymizationMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$AccountsConfigPath
    )

    if (Test-Path -LiteralPath $AccountsConfigPath) {
        $config = Get-Content -LiteralPath $AccountsConfigPath -Raw | ConvertFrom-Json

        if ($config.default_role_path) {
            $Script:Anonymization.RoleArnToPseudonym[[string]$config.default_role_path] = '[REDACTED-ROLE-ARN]'
        }

        if ($config.accounts) {
            foreach ($account in $config.accounts) {
                $profileName = ''
                if ($account.PSObject.Properties.Name -contains 'profile') {
                    $profileName = [string]$account.profile
                }
                elseif ($account.PSObject.Properties.Name -contains 'sso_profile') {
                    $profileName = [string]$account.sso_profile
                }

                $roleArn = ''
                if ($account.PSObject.Properties.Name -contains 'role_arn') {
                    $roleArn = [string]$account.role_arn
                }

                Add-AnonymizationAccount `
                    -AccountId ([string]$account.id) `
                    -AccountName ([string]$account.name) `
                    -ProfileName $profileName `
                    -RoleArn $roleArn
            }
        }
    }

    if (Test-Path -LiteralPath $SourcePath) {
        $folderPattern = '^(.+)_(\d{12})$'
        foreach ($child in (Get-ChildItem -LiteralPath $SourcePath -Directory)) {
            if ($child.Name -match $folderPattern) {
                Add-AnonymizationAccount -AccountId $Matches[2] -AccountName $Matches[1] -ProfileName $Matches[1]
            }
        }
    }
}

function Get-ResourcePseudonym {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    if (-not $Script:Anonymization.ResourceCounters.ContainsKey($Prefix)) {
        $Script:Anonymization.ResourceCounters[$Prefix] = 0
    }

    $Script:Anonymization.ResourceCounters[$Prefix]++
    return ('{0}-{1:D4}' -f $Prefix, $Script:Anonymization.ResourceCounters[$Prefix])
}

function Protect-AuditText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $result = $Text

    foreach ($roleArn in @($Script:Anonymization.RoleArnToPseudonym.Keys)) {
        if (-not [string]::IsNullOrWhiteSpace($roleArn)) {
            $result = $result.Replace($roleArn, $Script:Anonymization.RoleArnToPseudonym[$roleArn])
        }
    }

    foreach ($accountId in @($Script:Anonymization.AccountIdToPseudonym.Keys | Sort-Object)) {
        $pseudonym = $Script:Anonymization.AccountIdToPseudonym[$accountId]
        $result = $result.Replace($accountId, $pseudonym)
    }

    foreach ($accountName in @($Script:Anonymization.AccountNameToPseudonym.Keys | Sort-Object { $_.Length } -Descending)) {
        $pseudonym = $Script:Anonymization.AccountNameToPseudonym[$accountName]
        $result = $result.Replace($accountName, $pseudonym)
    }

    foreach ($profileName in @($Script:Anonymization.ProfileToPseudonym.Keys | Sort-Object { $_.Length } -Descending)) {
        if (-not [string]::IsNullOrWhiteSpace($profileName)) {
            $profilePseudonym = $Script:Anonymization.ProfileToPseudonym[$profileName]
            $result = $result.Replace(('--profile ' + $profileName), ('--profile ' + $profilePseudonym))
            $result = $result.Replace(('--profile ' + $profileName + ' '), ('--profile ' + $profilePseudonym + ' '))
        }
    }

    $result = [regex]::Replace(
        $result,
        'arn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:\d{12}:.+',
        '[REDACTED-ARN]'
    )

    $result = [regex]::Replace(
        $result,
        'arn:aws:iam::\d{12}:role/.+',
        '[REDACTED-ROLE-ARN]'
    )

    $result = [regex]::Replace($result, 'Auditor\s*:\s*.+$', 'Auditor   : [REDACTED]', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $result = [regex]::Replace($result, '"auditor"\s*:\s*"[^"]*"', '"auditor": "[REDACTED]"')
    $result = [regex]::Replace($result, '"sso_profile"\s*:\s*"[^"]*"', '"sso_profile": "[REDACTED]"')
    $result = [regex]::Replace($result, '"role_arn"\s*:\s*"[^"]*"', '"role_arn": "[REDACTED]"')

    $result = [regex]::Replace($result, 'C:\\Users\\[^\\"\s]+', 'C:\Users\[REDACTED]')
    $result = [regex]::Replace($result, '/Users/[^/"\s]+', '/Users/[REDACTED]')

    $result = [regex]::Replace(
        $result,
        '\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b',
        '[REDACTED-EMAIL]'
    )

    $resourcePatterns = @(
        @{ Prefix = 'vpc'; Pattern = '\bvpc-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'subnet'; Pattern = '\bsubnet-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'sg'; Pattern = '\bsg-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'i'; Pattern = '\bi-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'ami'; Pattern = '\bami-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'vol'; Pattern = '\bvol-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'eni'; Pattern = '\beni-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'rtb'; Pattern = '\brtb-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'igw'; Pattern = '\bigw-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'nat'; Pattern = '\bnat-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'pl'; Pattern = '\bpl-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'pcx'; Pattern = '\bpcx-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'tgw'; Pattern = '\btgw-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'acl'; Pattern = '\bacl-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'vpce'; Pattern = '\bvpce-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'elb'; Pattern = '\belb-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'arn'; Pattern = '\barn-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'fs'; Pattern = '\bfs-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'db'; Pattern = '\bdb-[0-9a-f]{8,17}\b' }
        @{ Prefix = 'cluster'; Pattern = '\bcluster-[0-9a-f]{8,17}\b' }
    )

    foreach ($entry in $resourcePatterns) {
        $prefix = $entry.Prefix
        $pattern = $entry.Pattern
        while ($result -match $pattern) {
            $replacement = Get-ResourcePseudonym -Prefix $prefix
            $result = [regex]::Replace($result, $pattern, $replacement, 1)
        }
    }

    $result = [regex]::Replace($result, 's3://[a-z0-9.\-_]+', 's3://[REDACTED-BUCKET]')
    $result = [regex]::Replace($result, '"bucket(?:_name)?"\s*:\s*"[^"]+"', '"bucket": "[REDACTED-BUCKET]"')

    $result = [regex]::Replace(
        $result,
        '\b(?!(?:0\.0\.0\.0|255\.255\.255\.255)\b)(?:\d{1,3}\.){3}\d{1,3}\b',
        '[REDACTED-IP]'
    )

    $result = [regex]::Replace(
        $result,
        '\bAWSReservedSSO_[A-Za-z0-9_-]+\b',
        '[REDACTED-SSO-ROLE]'
    )

    $result = [regex]::Replace(
        $result,
        'aws-reserved/sso\.amazonaws\.com/[a-z0-9-]+/AWSReservedSSO_[A-Za-z0-9_]+',
        '[REDACTED-SSO-PATH]'
    )

    return $result
}

function Get-AnonymizedRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $segments = @($RelativePath -split '[\\/]')
    $mapped = @()

    foreach ($segment in $segments) {
        if ($segment -match '^(.+)_(\d{12})$') {
            $accountId = $Matches[2]
            if ($Script:Anonymization.AccountIdToPseudonym.ContainsKey($accountId)) {
                $mapped += $Script:Anonymization.AccountIdToPseudonym[$accountId]
            }
            else {
                $mapped += ('ACCOUNT-UNKNOWN')
            }
        }
        else {
            $mapped += (Protect-AuditText -Text $segment)
        }
    }

    return ($mapped -join [IO.Path]::DirectorySeparatorChar)
}

function Write-AnonymizationMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $export = [ordered]@{
        generated_at = (Get-Date).ToString('o')
        warning    = 'INTERNAL ONLY - do not share with AI audit evaluator'
        accounts   = @()
        profiles   = @()
    }

    foreach ($accountId in @($Script:Anonymization.AccountIdToPseudonym.Keys | Sort-Object)) {
        $pseudonym = $Script:Anonymization.AccountIdToPseudonym[$accountId]
        $realName = ''
        foreach ($pair in $Script:Anonymization.AccountNameToPseudonym.GetEnumerator()) {
            if ($pair.Value -eq $pseudonym) {
                $realName = $pair.Key
                break
            }
        }

        $export.accounts += [ordered]@{
            pseudonym    = $pseudonym
            account_id   = $accountId
            account_name = $realName
        }
    }

    foreach ($profileName in @($Script:Anonymization.ProfileToPseudonym.Keys | Sort-Object)) {
        $export.profiles += [ordered]@{
            profile   = $profileName
            pseudonym = $Script:Anonymization.ProfileToPseudonym[$profileName]
        }
    }

    $mapDirectory = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($mapDirectory) -and -not (Test-Path -LiteralPath $mapDirectory)) {
        New-Item -ItemType Directory -Path $mapDirectory -Force | Out-Null
    }

    $export | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
}

# --- Main ---

if (-not (Test-Path -LiteralPath $InputPath)) {
    Write-Error "Input path not found: $InputPath"
    exit 1
}

if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    Write-Error "Output path already exists: $OutputPath. Use -Force to overwrite."
    exit 1
}

if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Recurse -Force
}

Initialize-AnonymizationMap -SourcePath $InputPath -AccountsConfigPath $ConfigFile

if ($Script:Anonymization.AccountIdToPseudonym.Count -eq 0) {
    Write-Warning 'No AWS accounts discovered in output folders or accounts.json.'
}

$inputRoot = (Resolve-Path -LiteralPath $InputPath).Path
$files = Get-ChildItem -LiteralPath $inputRoot -Recurse -File |
    Where-Object {
        $_.Extension -in @('.json', '.log', '.txt') -and
        $_.Name -notlike 'anonymization-map*.json'
    }

$processedCount = 0
foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($inputRoot.Length).TrimStart('\', '/')
    if ($relativePath -like 'anonymized*' -or $relativePath -like 'anonymized/*' -or $relativePath -like 'anonymized\*') {
        continue
    }

    $targetRelative = Get-AnonymizedRelativePath -RelativePath $relativePath
    $targetPath = Join-Path $OutputPath $targetRelative
    $targetDirectory = Split-Path -Parent $targetPath

    if (-not (Test-Path -LiteralPath $targetDirectory)) {
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
    }

    $rawContent = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    $sanitizedContent = Protect-AuditText -Text $rawContent
    Set-Content -LiteralPath $targetPath -Value $sanitizedContent -Encoding UTF8
    $processedCount++
}

Write-AnonymizationMap -Path $MappingFile

Write-Host '===================================='
Write-Host 'Audit output anonymized'
Write-Host ('Source      : {0}' -f $inputRoot)
Write-Host ('Destination : {0}' -f $OutputPath)
Write-Host ('Files       : {0}' -f $processedCount)
Write-Host ('Accounts    : {0}' -f $Script:Anonymization.AccountIdToPseudonym.Count)
Write-Host ('Mapping     : {0}' -f $MappingFile)
Write-Host ''
Write-Host 'Share only the anonymized folder with the AI evaluator.'
Write-Host 'Keep the mapping file internal - it reverses the pseudonyms.'
Write-Host '===================================='
