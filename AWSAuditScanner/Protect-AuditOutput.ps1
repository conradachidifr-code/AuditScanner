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

    Resource coverage includes TGW attachments, VPC flow logs, CloudWatch log
    groups/streams, S3 buckets, KMS keys/aliases, and hyphenated AWS service
    IDs (vpc-, subnet-, fl-, tgw-attach-, etc.) plus a generic fallback for
    remaining prefix-hex identifiers.

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

function Get-AwsHyphenatedResourcePatterns {
    # Longer prefixes first so e.g. tgw-attach matches before tgw.
    $prefixes = @(
        'tgw-attach'
        'vpce-svc'
        'cvpn-endpoint'
        'ipam-pool'
        'ipam-scope'
        'vpn-connection'
        'replicationgroup'
        'cache-cluster'
        'eipalloc'
        'ipalloc'
        'customer-gateway'
        'fsmt'
        'fsap'
        'snap'
        'subnet'
        'vpce'
        'pcx'
        'rtb'
        'acl'
        'eni'
        'vol'
        'ami'
        'vpc'
        'tgw'
        'igw'
        'eigw'
        'nat'
        'vgw'
        'vpn'
        'cgw'
        'dopt'
        'dhcp'
        'pl'
        'lgw'
        'lpg'
        'fle'
        'fl'
        'sg'
        'sgr'
        'sgp'
        'gp'
        'db'
        'fs'
        'esm'
        'elb'
        'arn'
        'cb'
        'cr'
        'ls'
        'ni'
        'net'
        'efa'
        'i'
    ) | Sort-Object { $_.Length } -Descending

    $patterns = @()
    foreach ($prefix in $prefixes) {
        $escaped = [regex]::Escape($prefix)
        $patterns += @{
            Prefix  = $prefix
            Pattern = ('\b{0}-[0-9a-f]{{8,32}}\b' -f $escaped)
        }
    }

    return $patterns
}

function Protect-AwsPrefixedResourceIds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $result = $Text
    foreach ($entry in (Get-AwsHyphenatedResourcePatterns)) {
        $prefix = $entry.Prefix
        $pattern = $entry.Pattern
        while ($result -match $pattern) {
            $replacement = Get-ResourcePseudonym -Prefix $prefix
            $result = [regex]::Replace($result, $pattern, $replacement, 1)
        }
    }

    return $result
}

function Protect-AwsGenericHyphenatedIds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    # Catch-all for service-prefix-hex IDs not covered above.
    # Skips regions (e.g. eu-west-1), control IDs (NET-03), and pseudonyms (ACCOUNT-001).
    $pattern = '\b(?!(?:eu|us|ap|sa|ca|me|af|cn|il|mx)-)([a-z][a-z0-9]{1,22})-([0-9a-f]{8,32})\b'
    $result = $Text

    $guard = 0
    while ($result -match $pattern) {
        $prefix = $Matches[1]
        if ($prefix -match '^(?:account|profile|redacted|log|kms|hostedzone)$' -or $prefix -match '^\d+$') {
            $result = [regex]::Replace($result, $pattern, '[REDACTED-AWS-ID]', 1)
        }
        else {
            $replacement = Get-ResourcePseudonym -Prefix $prefix
            $result = [regex]::Replace($result, $pattern, $replacement, 1)
        }

        $guard++
        if ($guard -gt 5000) {
            break
        }
    }

    return $result
}

function Protect-AwsLogIdentifiers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $result = $Text

    # CloudWatch / CloudTrail / VPC flow log paths and names.
    $logPathPattern = '/aws/[a-zA-Z0-9_./-]+'
    while ($result -match $logPathPattern) {
        $replacement = Get-ResourcePseudonym -Prefix 'log-group'
        $result = [regex]::Replace($result, $logPathPattern, $replacement, 1)
    }

    $logFieldReplacements = @(
        @{ Match = '"flow_log_id"\s*:\s*"[^"]*"'; Replace = '"flow_log_id": "[REDACTED-LOG-ID]"' }
        @{ Match = '"FlowLogId"\s*:\s*"[^"]*"'; Replace = '"FlowLogId": "[REDACTED-LOG-ID]"' }
        @{ Match = '"log_group"\s*:\s*"[^"]*"'; Replace = '"log_group": "[REDACTED-LOG-ID]"' }
        @{ Match = '"LogGroupName"\s*:\s*"[^"]*"'; Replace = '"LogGroupName": "[REDACTED-LOG-ID]"' }
        @{ Match = '"log_group_name"\s*:\s*"[^"]*"'; Replace = '"log_group_name": "[REDACTED-LOG-ID]"' }
        @{ Match = '"logGroupName"\s*:\s*"[^"]*"'; Replace = '"logGroupName": "[REDACTED-LOG-ID]"' }
        @{ Match = '"log_group_arn"\s*:\s*"[^"]*"'; Replace = '"log_group_arn": "[REDACTED-LOG-ARN]"' }
        @{ Match = '"LogGroupArn"\s*:\s*"[^"]*"'; Replace = '"LogGroupArn": "[REDACTED-LOG-ARN]"' }
        @{ Match = '"cloudwatch_log_group"\s*:\s*"[^"]*"'; Replace = '"cloudwatch_log_group": "[REDACTED-LOG-ID]"' }
        @{ Match = '"stream_name"\s*:\s*"[^"]*"'; Replace = '"stream_name": "[REDACTED-LOG-STREAM]"' }
        @{ Match = '"logStreamName"\s*:\s*"[^"]*"'; Replace = '"logStreamName": "[REDACTED-LOG-STREAM]"' }
        @{ Match = '"delivery_channel"\s*:\s*"[^"]*"'; Replace = '"delivery_channel": "[REDACTED-LOG-ID]"' }
        @{ Match = '"DeliveryChannelName"\s*:\s*"[^"]*"'; Replace = '"DeliveryChannelName": "[REDACTED-LOG-ID]"' }
        @{ Match = '"trail_name"\s*:\s*"[^"]*"'; Replace = '"trail_name": "[REDACTED-LOG-ID]"' }
        @{ Match = '"TrailARN"\s*:\s*"[^"]*"'; Replace = '"TrailARN": "[REDACTED-LOG-ARN]"' }
        @{ Match = '"trail_arn"\s*:\s*"[^"]*"'; Replace = '"trail_arn": "[REDACTED-LOG-ARN]"' }
        @{ Match = '"s3_key_prefix"\s*:\s*"[^"]*"'; Replace = '"s3_key_prefix": "[REDACTED-LOG-PREFIX]"' }
        @{ Match = '"id"\s*:\s*"fl-[0-9a-f]+"'; Replace = '"id": "[REDACTED-FLOW-LOG-ID]"' }
    )

    foreach ($entry in $logFieldReplacements) {
        $result = [regex]::Replace($result, $entry.Match, $entry.Replace)
    }

    return $result
}

function Protect-AwsKmsAndSecrets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $result = $Text

    # KMS key UUIDs and multi-Region keys (mrk-...).
    while ($result -match '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b') {
        $replacement = Get-ResourcePseudonym -Prefix 'kms-key'
        $result = [regex]::Replace(
            $result,
            '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            $replacement,
            1
        )
    }

    $result = [regex]::Replace(
        $result,
        '\bmrk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        '[REDACTED-MRK-KEY]'
    )

    $aliasPattern = 'alias/[a-zA-Z0-9/_-]+'
    while ($result -match $aliasPattern) {
        $replacement = 'alias/{0}' -f (Get-ResourcePseudonym -Prefix 'kms-alias')
        $result = [regex]::Replace($result, $aliasPattern, $replacement, 1)
    }

    $kmsFieldReplacements = @(
        @{ Match = '"key_id"\s*:\s*"[^"]*"'; Replace = '"key_id": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"KeyId"\s*:\s*"[^"]*"'; Replace = '"KeyId": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"KeyArn"\s*:\s*"[^"]*"'; Replace = '"KeyArn": "[REDACTED-KMS-ARN]"' }
        @{ Match = '"kms_key_id"\s*:\s*"[^"]*"'; Replace = '"kms_key_id": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"KmsKeyId"\s*:\s*"[^"]*"'; Replace = '"KmsKeyId": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"master_key_id"\s*:\s*"[^"]*"'; Replace = '"master_key_id": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"MasterKeyId"\s*:\s*"[^"]*"'; Replace = '"MasterKeyId": "[REDACTED-KMS-KEY]"' }
        @{ Match = '"customer_master_key"\s*:\s*"[^"]*"'; Replace = '"customer_master_key": "[REDACTED-KMS-KEY]"' }
    )

    foreach ($entry in $kmsFieldReplacements) {
        $result = [regex]::Replace($result, $entry.Match, $entry.Replace)
    }

    $result = [regex]::Replace(
        $result,
        'arn:aws:kms:[a-z0-9-]+:[^:]+:key/[0-9a-f-]+',
        '[REDACTED-KMS-ARN]'
    )

    return $result
}

function Protect-AwsStorageAndDataIdentifiers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $result = $Text

    $result = [regex]::Replace($result, 's3://[a-z0-9.\-_]+', 's3://[REDACTED-BUCKET]')
    $result = [regex]::Replace($result, 's3a://[a-z0-9.\-_]+', 's3a://[REDACTED-BUCKET]')
    $result = [regex]::Replace($result, 'https://s3[.-][a-z0-9.-]+\.amazonaws\.com/[a-z0-9.\-_/]+', 'https://s3.[REDACTED-BUCKET].amazonaws.com/[REDACTED-KEY]')

    $storageFieldReplacements = @(
        @{ Match = '"bucket"\s*:\s*"[^"]*"'; Replace = '"bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"Bucket"\s*:\s*"[^"]*"'; Replace = '"Bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"bucket_name"\s*:\s*"[^"]*"'; Replace = '"bucket_name": "[REDACTED-BUCKET]"' }
        @{ Match = '"BucketName"\s*:\s*"[^"]*"'; Replace = '"BucketName": "[REDACTED-BUCKET]"' }
        @{ Match = '"s3_bucket"\s*:\s*"[^"]*"'; Replace = '"s3_bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"S3Bucket"\s*:\s*"[^"]*"'; Replace = '"S3Bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"s3BucketName"\s*:\s*"[^"]*"'; Replace = '"s3BucketName": "[REDACTED-BUCKET]"' }
        @{ Match = '"log_bucket"\s*:\s*"[^"]*"'; Replace = '"log_bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"LogBucket"\s*:\s*"[^"]*"'; Replace = '"LogBucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"target_bucket"\s*:\s*"[^"]*"'; Replace = '"target_bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"source_bucket"\s*:\s*"[^"]*"'; Replace = '"source_bucket": "[REDACTED-BUCKET]"' }
        @{ Match = '"table_name"\s*:\s*"[^"]*"'; Replace = '"table_name": "[REDACTED-TABLE]"' }
        @{ Match = '"TableName"\s*:\s*"[^"]*"'; Replace = '"TableName": "[REDACTED-TABLE]"' }
        @{ Match = '"secret_name"\s*:\s*"[^"]*"'; Replace = '"secret_name": "[REDACTED-SECRET]"' }
        @{ Match = '"SecretId"\s*:\s*"[^"]*"'; Replace = '"SecretId": "[REDACTED-SECRET]"' }
        @{ Match = '"secret_arn"\s*:\s*"[^"]*"'; Replace = '"secret_arn": "[REDACTED-SECRET-ARN]"' }
        @{ Match = '"parameter_name"\s*:\s*"[^"]*"'; Replace = '"parameter_name": "[REDACTED-PARAMETER]"' }
        @{ Match = '"ParameterName"\s*:\s*"[^"]*"'; Replace = '"ParameterName": "[REDACTED-PARAMETER]"' }
    )

    foreach ($entry in $storageFieldReplacements) {
        $result = [regex]::Replace($result, $entry.Match, $entry.Replace)
    }

    # Route53 hosted zone IDs.
    while ($result -match '\bZ[0-9A-Z]{10,32}\b') {
        $replacement = Get-ResourcePseudonym -Prefix 'hostedzone'
        $result = [regex]::Replace($result, '\bZ[0-9A-Z]{10,32}\b', $replacement, 1)
    }

    return $result
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

    $result = Protect-AwsPrefixedResourceIds -Text $result
    $result = Protect-AwsLogIdentifiers -Text $result
    $result = Protect-AwsKmsAndSecrets -Text $result
    $result = Protect-AwsStorageAndDataIdentifiers -Text $result
    $result = Protect-AwsGenericHyphenatedIds -Text $result

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
