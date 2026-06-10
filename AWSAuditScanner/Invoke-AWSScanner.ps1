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
$Script:DiagnosticFile = $null
$Script:DiagnosticDomain = ''
$Script:CheckContext = @{}
$Script:CheckCliLog = @()
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

function Get-SafeErrorMessage {
    param(
        $ErrorRecord,

        [string]$Fallback = 'Unknown error'
    )

    if ($null -eq $ErrorRecord) {
        return $Fallback
    }

    $message = [string]$ErrorRecord.Exception.Message
    if (-not [string]::IsNullOrWhiteSpace($message)) {
        return $message
    }

    $exceptionType = [string]$ErrorRecord.Exception.GetType().FullName
    if (-not [string]::IsNullOrWhiteSpace($exceptionType)) {
        return $exceptionType
    }

    return $Fallback
}

function Get-AuditCliArray {
    param(
        $Items
    )

    if ($null -eq $Items) {
        return @()
    }

    if ($Items -is [string]) {
        return ,$Items
    }

    if ($Items -is [System.Array]) {
        return $Items
    }

    if ($Items.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        return ,$Items
    }

    if ($Items -is [System.Collections.ICollection]) {
        if ($Items.Count -eq 0) {
            return @()
        }

        $result = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Items) {
            [void]$result.Add($item)
        }
        return $result.ToArray()
    }

    return ,$Items
}

function Test-AuditHasProperty {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $false
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -ieq $PropertyName) {
                return $true
            }
        }
        return $false
    }

    foreach ($name in $Object.PSObject.Properties.Name) {
        if ($name -ieq $PropertyName) {
            return $true
        }
    }

    return $false
}

function New-AuditList {
    return New-Object 'System.Collections.Generic.List[object]'
}

function Get-AuditCollectionCount {
    param(
        $Items
    )

    if ($null -eq $Items) {
        return 0
    }

    if ($Items -is [string]) {
        return 1
    }

    if ($Items -is [System.Collections.ICollection]) {
        return $Items.Count
    }

    if ($Items.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        return 1
    }

    if ($Items -is [System.Collections.IEnumerable]) {
        $count = 0
        foreach ($item in $Items) {
            $count++
        }
        return $count
    }

    return 1
}

function Get-AuditPropertyValue {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($propertyName in $PropertyNames) {
            foreach ($key in $Object.Keys) {
                if ([string]$key -ieq $propertyName) {
                    return $Object[$key]
                }
            }
        }
        return $null
    }

    foreach ($propertyName in $PropertyNames) {
        foreach ($prop in $Object.PSObject.Properties) {
            if ($prop.Name -ieq $propertyName) {
                return $prop.Value
            }
        }
    }

    return $null
}

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = '(no message)'
    }

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

function Set-AuditCheckContext {
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

    $Script:CheckContext = @{
        AccountId   = $AccountId
        AccountName = $AccountName
        Region      = $Region
        ControlId   = $ControlId
    }
    $Script:CheckCliLog = @()
}

function Get-AwsCliCommandString {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $parts = @('aws') + @($Arguments) + @('--output', 'json', '--region', $Region)

    if ($env:AWS_ACCESS_KEY_ID) {
        $parts += '[env credentials]'
    }
    elseif ($env:AWS_PROFILE) {
        $parts += @('--profile', $env:AWS_PROFILE)
    }

    return ($parts -join ' ')
}

function Add-AuditCliLogEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [bool]$Success,

        $ExitCode = $null,
        [string]$Output = ''
    )

    $Script:CheckCliLog += [PSCustomObject]@{
        Command  = $Command
        Success  = $Success
        ExitCode = $ExitCode
        Output   = $Output
    }
}

function Write-AuditDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('powershell_exception', 'cli_failure', 'cli_json_error', 'cli_no_credentials', 'cli_empty_response')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [string]$ExceptionType = '',
        [string]$StackTrace = '',
        [object[]]$FailedCommands = @()
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = '(no message)'
    }

    if (-not $Script:DiagnosticFile) {
        return
    }

    $ctx = $Script:CheckContext
    $accountLabel = 'unknown'
    if ($ctx -and $ctx.AccountName -and $ctx.AccountId) {
        $accountLabel = '{0} ({1})' -f $ctx.AccountName, $ctx.AccountId
    }

    $controlId = ''
    $region = ''
    if ($ctx) {
        if ($ctx.ControlId) { $controlId = [string]$ctx.ControlId }
        if ($ctx.Region) { $region = [string]$ctx.Region }
    }

    $lines = @()
    $lines += '================================================================================'
    $lines += ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Type.ToUpper())
    $lines += ('Domain      : {0}' -f $Script:DiagnosticDomain)
    $lines += ('Account     : {0}' -f $accountLabel)
    $lines += ('Region      : {0}' -f $region)
    $lines += ('Control     : {0}' -f $controlId)
    $lines += ('Message     : {0}' -f $Message)

    if (-not [string]::IsNullOrWhiteSpace($ExceptionType)) {
        $lines += ('ExceptionType: {0}' -f $ExceptionType)
    }

    if (-not [string]::IsNullOrWhiteSpace($StackTrace)) {
        $lines += 'Stack trace :'
        foreach ($stackLine in ($StackTrace -split "`r?`n")) {
            if (-not [string]::IsNullOrWhiteSpace($stackLine)) {
                $lines += ('  {0}' -f $stackLine)
            }
        }
    }

    if ($FailedCommands -and $FailedCommands.Count -gt 0) {
        $lines += 'Failed command(s):'
        foreach ($cmd in $FailedCommands) {
            $statusLabel = 'FAIL'
            if ($cmd.Success -eq $true) {
                $statusLabel = 'OK'
            }

            $exitLabel = ''
            if ($null -ne $cmd.ExitCode) {
                $exitLabel = ' exit={0}' -f $cmd.ExitCode
            }

            $commandText = [string]$cmd.Command
            if ($cmd.PSObject.Properties.Name -contains 'command') {
                $commandText = [string]$cmd.command
            }

            $lines += ('  [{0}{1}] {2}' -f $statusLabel, $exitLabel, $commandText)

            $outputText = ''
            if ($cmd.PSObject.Properties.Name -contains 'Output') {
                $outputText = [string]$cmd.Output
            }
            elseif ($cmd.PSObject.Properties.Name -contains 'output') {
                $outputText = [string]$cmd.output
            }

            if (-not [string]::IsNullOrWhiteSpace($outputText)) {
                foreach ($outputLine in ($outputText -split "`r?`n")) {
                    $lines += ('    {0}' -f $outputLine)
                }
            }
        }
    }

    if ($Script:CheckCliLog -and $Script:CheckCliLog.Count -gt 0) {
        $lines += 'All CLI commands during this check:'
        foreach ($cmd in $Script:CheckCliLog) {
            $statusLabel = 'FAIL'
            if ($cmd.Success -eq $true) {
                $statusLabel = 'OK'
            }

            $exitLabel = ''
            if ($null -ne $cmd.ExitCode) {
                $exitLabel = ' exit={0}' -f $cmd.ExitCode
            }

            $lines += ('  [{0}{1}] {2}' -f $statusLabel, $exitLabel, $cmd.Command)

            if (-not [string]::IsNullOrWhiteSpace([string]$cmd.Output)) {
                foreach ($outputLine in ([string]$cmd.Output -split "`r?`n")) {
                    $lines += ('    {0}' -f $outputLine)
                }
            }
        }
    }

    $lines += ''
    Add-Content -Path $Script:DiagnosticFile -Value ($lines -join "`r`n") -Encoding UTF8
}

function ConvertTo-DeepPsObject {
    param(
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = New-Object PSObject
        foreach ($key in $InputObject.Keys) {
            $noteKey = [string]$key
            $noteValue = ConvertTo-DeepPsObject -InputObject $InputObject[$key]
            $result | Add-Member -MemberType NoteProperty -Name $noteKey -Value $noteValue
        }
        return $result
    }

    if ($InputObject -is [System.Array]) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $InputObject) {
            [void]$items.Add((ConvertTo-DeepPsObject -InputObject $item))
        }
        return @($items.ToArray())
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $InputObject) {
            [void]$items.Add((ConvertTo-DeepPsObject -InputObject $item))
        }
        return @($items.ToArray())
    }

    return $InputObject
}

function ConvertFrom-AwsCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonText
    )

    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        return $null
    }

    try {
        return ($JsonText | ConvertFrom-Json)
    }
    catch {
        $primaryError = $_.Exception.Message
    }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'System.Web.Script.Serialization.JavaScriptSerializer').Type) {
            Add-Type -AssemblyName System.Web.Extensions
        }

        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 268435456
        $deserialized = $serializer.DeserializeObject($JsonText)
        return (ConvertTo-DeepPsObject -InputObject $deserialized)
    }
    catch {
        throw (New-Object System.InvalidOperationException ("JSON parse failed: {0} | fallback: {1}" -f $primaryError, $_.Exception.Message))
    }
}

function Invoke-AWSCLI {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $commandString = Get-AwsCliCommandString -Arguments $Arguments -Region $Region
    $cliArgs = @($Arguments) + @('--output', 'json', '--region', $Region)

    if (-not $env:AWS_ACCESS_KEY_ID) {
        $profileName = $env:AWS_PROFILE
        if (-not $profileName) {
            $noCredOutput = 'No AWS credentials or profile in environment'
            Add-AuditCliLogEntry -Command $commandString -Success $false -Output $noCredOutput
            Write-AuditDiagnostic `
                -Type 'cli_no_credentials' `
                -Message $noCredOutput `
                -FailedCommands @(@{
                    Command  = $commandString
                    Success  = $false
                    ExitCode = $null
                    Output   = $noCredOutput
                })
            return $null
        }
    }

    if ($env:AWS_ACCESS_KEY_ID) {
        $rawOutput = & aws @cliArgs 2>&1
    }
    else {
        $rawOutput = & aws @cliArgs '--profile' $env:AWS_PROFILE 2>&1
    }

    $exitCode = $LASTEXITCODE

    $stdoutParts = New-Object 'System.Collections.Generic.List[string]'
    $stderrParts = New-Object 'System.Collections.Generic.List[string]'

    if ($null -ne $rawOutput) {
        foreach ($item in @($rawOutput)) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                [void]$stderrParts.Add([string]$item)
            }
            else {
                [void]$stdoutParts.Add([string]$item)
            }
        }
    }

    $outputText = ($stdoutParts -join [Environment]::NewLine).Trim()
    $stderrText = ($stderrParts -join [Environment]::NewLine).Trim()

    $logOutput = $outputText
    if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
        if ([string]::IsNullOrWhiteSpace($logOutput)) {
            $logOutput = $stderrText
        }
        else {
            $logOutput = $stderrText + [Environment]::NewLine + $logOutput
        }
    }

    if ($logOutput.Length -gt 4000) {
        $logOutput = $logOutput.Substring(0, 4000) + '... [truncated]'
    }

    $logEntry = @{
        Command  = $commandString
        Success  = $false
        ExitCode = $exitCode
        Output   = $logOutput
    }

    if ($exitCode -ne 0) {
        Add-AuditCliLogEntry -Command $commandString -Success $false -ExitCode $exitCode -Output $logOutput
        Write-AuditDiagnostic `
            -Type 'cli_failure' `
            -Message ('AWS CLI exited with code {0}' -f $exitCode) `
            -FailedCommands @($logEntry)
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($outputText)) {
        $emptyMessage = 'Empty response body'
        if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
            $emptyMessage = $stderrText
        }

        $logEntry.Output = $emptyMessage
        Add-AuditCliLogEntry -Command $commandString -Success $false -ExitCode $exitCode -Output $logOutput
        Write-AuditDiagnostic `
            -Type 'cli_empty_response' `
            -Message $emptyMessage `
            -FailedCommands @($logEntry)
        return $null
    }

    try {
        $parsed = ConvertFrom-AwsCliJson -JsonText $outputText
        Add-AuditCliLogEntry -Command $commandString -Success $true -ExitCode $exitCode -Output ''
        return $parsed
    }
    catch {
        $jsonError = Get-SafeErrorMessage -ErrorRecord $_ -Fallback 'JSON parse failed'
        if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
            $jsonError = $stderrText + ' | ' + $jsonError
        }

        $logEntry.Output = $jsonError
        if ($logOutput.Length -gt 4000) {
            $logEntry.Output = $logOutput
        }

        Add-AuditCliLogEntry -Command $commandString -Success $false -ExitCode $exitCode -Output $logEntry.Output
        Write-AuditDiagnostic `
            -Type 'cli_json_error' `
            -Message $jsonError `
            -FailedCommands @($logEntry)
        return $null
    }
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

function Resolve-SsoProfileForAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [string]$ConfiguredProfile
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredProfile)) {
        return $ConfiguredProfile
    }

    try {
        $profiles = Get-ProfilesFromConfig
    }
    catch {
        return $null
    }

    foreach ($profile in $profiles) {
        if ([string]$profile.AccountId -eq $AccountId) {
            return [string]$profile.Name
        }
    }

    foreach ($profile in $profiles) {
        if ([string]$profile.Name -eq $AccountName) {
            return [string]$profile.Name
        }
    }

    return $null
}

function Test-SsoProfileSession {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,

        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName
    )

    $identityOutput = & aws sts get-caller-identity --output json --profile $ProfileName 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($identityOutput | Out-String).Trim()
        Write-AuditLog -Message "SSO profile '$ProfileName' failed for $AccountName ($AccountId): $errorText" -Level WARN
        return $false
    }

    $identityText = ($identityOutput | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($identityText)) {
        Write-AuditLog -Message "SSO profile '$ProfileName' returned empty identity for $AccountName ($AccountId)" -Level WARN
        return $false
    }

    $identity = $identityText | ConvertFrom-Json
    if ([string]$identity.Account -ne $AccountId) {
        Write-AuditLog -Message "SSO profile '$ProfileName' maps to account $($identity.Account), expected $AccountId" -Level WARN
        return $false
    }

    $env:AWS_PROFILE = $ProfileName
    Write-AuditLog -Message "Using SSO profile '$ProfileName' for $AccountName ($AccountId)"
    return $true
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
        [string]$RoleArn,

        [string]$SsoProfile,
        [string]$AuthMode = 'sso_profile'
    )

    $sourceProfile = $env:AWS_PROFILE

    Clear-AccountSession

    if ($AuthMode -eq 'sso_profile' -or $AuthMode -eq 'auto') {
        $profileToUse = Resolve-SsoProfileForAccount `
            -AccountId $AccountId `
            -AccountName $AccountName `
            -ConfiguredProfile $SsoProfile

        if (-not $profileToUse -and $sourceProfile) {
            $identityOutput = & aws sts get-caller-identity --output json --profile $sourceProfile 2>&1
            if ($LASTEXITCODE -eq 0) {
                $identityText = ($identityOutput | Out-String).Trim()
                if (-not [string]::IsNullOrWhiteSpace($identityText)) {
                    $identity = $identityText | ConvertFrom-Json
                    if ([string]$identity.Account -eq $AccountId) {
                        $profileToUse = $sourceProfile
                    }
                }
            }
        }

        if ($profileToUse) {
            if (Test-SsoProfileSession -ProfileName $profileToUse -AccountId $AccountId -AccountName $AccountName) {
                return $true
            }
        }

        if ($AuthMode -eq 'sso_profile') {
            Write-AuditLog -Message "No valid SSO profile for $AccountName ($AccountId). Set 'profile' in accounts.json or add sso_account_id in ~/.aws/config." -Level WARN
            return $false
        }
    }

    $sessionName = 'AuditScan-{0}-{1}' -f $AccountId, (Get-Date -Format 'HHmm')
    $assumeArgs = @(
        'sts', 'assume-role',
        '--role-arn', $RoleArn,
        '--role-session-name', $sessionName,
        '--output', 'json'
    )

    if ($sourceProfile) {
        $assumeArgs += @('--profile', $sourceProfile)
    }

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

    if (-not $rawConfig.default_role_name -and -not $rawConfig.default_role_path) {
        throw 'Config missing required field: default_role_name or default_role_path'
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
            if ($rawConfig.default_role_path) {
                $roleArn = 'arn:aws:iam::{0}:role/{1}' -f $entry.id, $rawConfig.default_role_path
            }
            else {
                $roleArn = 'arn:aws:iam::{0}:role/{1}' -f $entry.id, $rawConfig.default_role_name
            }
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

        $ssoProfile = ''
        if ($entry.PSObject.Properties.Name -contains 'profile') {
            $ssoProfile = [string]$entry.profile
        }
        elseif ($entry.PSObject.Properties.Name -contains 'sso_profile') {
            $ssoProfile = [string]$entry.sso_profile
        }

        $accounts += [PSCustomObject]@{
            id          = [string]$entry.id
            name        = [string]$entry.name
            role_arn    = [string]$roleArn
            sso_profile = [string]$ssoProfile
            regions     = @($regions)
            skip        = $skip
            skip_reason = $skipReason
        }
    }

    $authMode = 'sso_profile'
    if ($rawConfig.PSObject.Properties.Name -contains 'auth_mode') {
        if (-not [string]::IsNullOrWhiteSpace([string]$rawConfig.auth_mode)) {
            $authMode = [string]$rawConfig.auth_mode
        }
    }

    return ,@{
        default_role_name = [string]$rawConfig.default_role_name
        default_regions   = @($rawConfig.default_regions)
        auth_mode         = $authMode
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
        $Account,

        [string]$AuthMode = 'sso_profile'
    )

    $result = [PSCustomObject]@{
        AccountId   = $Account.id
        AccountName = $Account.name
        Status      = 'FAILED'
        Identity    = $null
        Error       = $null
    }

    try {
        $sessionOk = Set-AccountSession `
            -AccountId $Account.id `
            -AccountName $Account.name `
            -RoleArn $Account.role_arn `
            -SsoProfile $Account.sso_profile `
            -AuthMode $AuthMode
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

    foreach ($item in @($Results)) {
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

function Get-AuditCliLogSnapshot {
    $snapshot = @()

    foreach ($entry in $Script:CheckCliLog) {
        $snapshot += [PSCustomObject]@{
            command   = [string]$entry.Command
            success   = [bool]$entry.Success
            exit_code = $entry.ExitCode
            output    = [string]$entry.Output
        }
    }

    return $snapshot
}

function New-AuditEvidenceRecord {
    param(
        [Parameter(Mandatory = $true)]
        $Result
    )

    return [PSCustomObject]@{
        control_id        = [string]$Result.ControlId
        region            = [string]$Result.Region
        status            = [string]$Result.Status
        severity          = [string]$Result.Severity
        notes             = [string]$Result.Notes
        timestamp         = [string]$Result.Timestamp
        evidence          = $Result.Evidence
        commands_executed = @(Get-AuditCliLogSnapshot)
    }
}

function Initialize-AccountOutputPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp
    )

    $accountFolder = Join-Path $OutputPath ('{0}_{1}' -f $AccountName, $AccountId)
    $evidencePath = Join-Path $accountFolder 'evidence'
    $accountErrorsPath = Join-Path $accountFolder 'errors'

    foreach ($path in @($accountFolder, $evidencePath, $accountErrorsPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }

    return [PSCustomObject]@{
        AccountFolder  = $accountFolder
        EvidencePath   = $evidencePath
        ErrorsPath     = $accountErrorsPath
        ResultsFile    = (Join-Path $accountFolder ('{0}_{1}.json' -f $Domain, $Timestamp))
        DiagnosticFile = (Join-Path $accountErrorsPath ('AuditDiagnostics_{0}_{1}.log' -f $Domain, $Timestamp))
        EvidenceFile   = (Join-Path $evidencePath ('{0}_{1}_evidence.json' -f $Domain, $Timestamp))
    }
}

function Start-AccountDiagnosticLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DiagnosticFile,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$Auditor
    )

    $header = @(
        'AWS Audit Scanner - account diagnostic log'
        ('Domain    : {0}' -f $Domain)
        ('Account   : {0} ({1})' -f $AccountName, $AccountId)
        ('Started   : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
        ('Auditor   : {0}' -f $Auditor)
        'PowerShell exceptions and failed AWS CLI commands are recorded below.'
        ''
    )
    Set-Content -Path $DiagnosticFile -Value ($header -join "`r`n") -Encoding UTF8
    $Script:DiagnosticFile = $DiagnosticFile
}

function Write-AccountResultsFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResultsFile,

        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp,

        [Parameter(Mandatory = $true)]
        [string]$Auditor,

        $Account,

        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    $outputObject = @{
        metadata = @{
            account_id   = $AccountId
            account_name = $AccountName
            domain       = $Domain
            auditor      = $Auditor
            timestamp    = $Timestamp
            role_arn     = [string]$Account.role_arn
            regions      = @($Account.regions)
        }
        results = @($Results)
    }

    $outputObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $ResultsFile -Encoding UTF8
    Write-AuditLog -Message "Written: $ResultsFile"

    return $ResultsFile
}

function Write-AccountEvidenceFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidenceFile,

        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp,

        [Parameter(Mandatory = $true)]
        [string]$Auditor,

        $Account,

        [Parameter(Mandatory = $true)]
        [array]$EvidenceRecords
    )

    $ssoProfile = ''
    if ($Account.PSObject.Properties.Name -contains 'sso_profile') {
        $ssoProfile = [string]$Account.sso_profile
    }

    $capturedEvidence = @()
    foreach ($record in $EvidenceRecords) {
        $hasEvidence = $false
        if ($null -ne $record.evidence) {
            $hasEvidence = $true
        }

        $hasCommands = $false
        if ($record.commands_executed -and @($record.commands_executed).Count -gt 0) {
            $hasCommands = $true
        }

        if ($hasEvidence -or $hasCommands) {
            $capturedEvidence += $record
        }
    }

    if ($capturedEvidence.Count -eq 0) {
        Write-AuditLog -Message "No captured evidence for $AccountName - skipping evidence file"
        return $null
    }

    $evidenceObject = @{
        metadata = @{
            account_id   = $AccountId
            account_name = $AccountName
            domain       = $Domain
            auditor      = $Auditor
            timestamp    = $Timestamp
            role_arn     = [string]$Account.role_arn
            sso_profile  = $ssoProfile
            regions      = @($Account.regions)
        }
        controls = @($capturedEvidence)
    }

    $evidenceObject | ConvertTo-Json -Depth 15 | Out-File -FilePath $EvidenceFile -Encoding UTF8
    Write-AuditLog -Message "Written: $EvidenceFile"

    return $EvidenceFile
}

# --- Main execution ---

if ($validDomains -notcontains $Domain) {
    Write-Error "Invalid domain '$Domain'. Must be one of: $($validDomains -join ', ')"
    exit 1
}

$logPath = Join-Path $OutputPath 'log'
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
$Script:SessionLogFile = Join-Path $logPath ("AuditSession_{0}.log" -f $timestamp)
$Script:DiagnosticFile = $null
$Script:DiagnosticDomain = $Domain
$writtenAccountFolders = @()

$configSource = 'config'
$defaultRegions = @()
$accounts = @()
$authMode = 'sso_profile'

try {
    $config = Get-AccountsFromConfig -Path $ConfigFile
    $defaultRegions = @($config.default_regions)
    $accounts = @($config.accounts)
    $authMode = [string]$config.auth_mode
}
catch {
    Write-AuditLog -Message (Get-SafeErrorMessage -ErrorRecord $_ -Fallback 'Failed to load accounts config') -Level WARN
    Write-AuditLog -Message 'Falling back to AWS profile discovery from ~/.aws/config' -Level WARN
    $configSource = 'profiles'
    $authMode = 'sso_profile'

    $profiles = Get-ProfilesFromConfig
    $fallbackRoleName = 'CCOE_DataRead'
    $defaultRegions = @('eu-west-1', 'eu-west-2', 'eu-west-3')

    foreach ($profile in $profiles) {
        $roleArn = 'arn:aws:iam::{0}:role/{1}' -f $profile.AccountId, $fallbackRoleName
        $accounts += [PSCustomObject]@{
            id          = [string]$profile.AccountId
            name        = [string]$profile.Name
            role_arn    = $roleArn
            sso_profile = [string]$profile.Name
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

        $connectivity = Test-AccountConnectivity -Account $account -AuthMode $authMode
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

    $accountPaths = Initialize-AccountOutputPaths `
        -OutputPath $OutputPath `
        -AccountName $account.name `
        -AccountId $account.id `
        -Domain $Domain `
        -Timestamp $timestamp

    Start-AccountDiagnosticLog `
        -DiagnosticFile $accountPaths.DiagnosticFile `
        -Domain $Domain `
        -AccountName $account.name `
        -AccountId $account.id `
        -Auditor $Auditor

    $accountEvidenceRecords = New-Object 'System.Collections.Generic.List[object]'
    $accountResults = New-Object 'System.Collections.Generic.List[object]'

    $sessionOk = Set-AccountSession `
        -AccountId $account.id `
        -AccountName $account.name `
        -RoleArn $account.role_arn `
        -SsoProfile $account.sso_profile `
        -AuthMode $authMode
    if (-not $sessionOk) {
        Write-AuditLog -Message "Could not establish session for $($account.name) ($($account.id))" -Level ERROR

        foreach ($region in $account.regions) {
            foreach ($controlId in $domainChecks.Keys) {
                [void]$accountResults.Add((New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'NOT_TESTED' `
                    -Evidence $null `
                    -Notes 'Could not assume role for account'))
            }
        }

        foreach ($failedResult in @($accountResults)) {
            [void]$accountEvidenceRecords.Add((New-AuditEvidenceRecord -Result $failedResult))
        }

        $accountResultArray = @($accountResults.ToArray())

        Write-AccountResultsFile `
            -ResultsFile $accountPaths.ResultsFile `
            -AccountId $account.id `
            -AccountName $account.name `
            -Domain $Domain `
            -Timestamp $timestamp `
            -Auditor $Auditor `
            -Account $account `
            -Results $accountResultArray | Out-Null

        Write-AccountEvidenceFile `
            -EvidenceFile $accountPaths.EvidenceFile `
            -AccountId $account.id `
            -AccountName $account.name `
            -Domain $Domain `
            -Timestamp $timestamp `
            -Auditor $Auditor `
            -Account $account `
            -EvidenceRecords @($accountEvidenceRecords.ToArray()) | Out-Null

        $writtenAccountFolders += $accountPaths.AccountFolder
        $allAccountResults[$account.name] = $accountResultArray
        $summaryRows += Get-SummaryRow -AccountName $account.name -Results $accountResultArray
        Clear-AccountSession
        $Script:DiagnosticFile = $null
        continue
    }

    foreach ($region in $account.regions) {
        Write-Host ('  Region: {0}' -f $region)

        foreach ($controlId in $domainChecks.Keys) {
            $checkBlock = $domainChecks[$controlId]

            if ($SkipControls -contains $controlId) {
                Set-AuditCheckContext `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId

                $skippedResult = New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'NOT_TESTED' `
                    -Evidence $null `
                    -Notes 'Skipped by parameter'

                [void]$accountResults.Add($skippedResult)
                [void]$accountEvidenceRecords.Add((New-AuditEvidenceRecord -Result $skippedResult))
                continue
            }

            Set-AuditCheckContext `
                -AccountId $account.id `
                -AccountName $account.name `
                -Region $region `
                -ControlId $controlId

            $result = $null
            try {
                $result = & $checkBlock -AccountId $account.id -AccountName $account.name -Region $region
            }
            catch {
                $exceptionType = $_.Exception.GetType().FullName
                $stackTrace = $_.ScriptStackTrace
                if ([string]::IsNullOrWhiteSpace($stackTrace)) {
                    $stackTrace = $_.Exception.StackTrace
                }

                $exceptionMessage = Get-SafeErrorMessage -ErrorRecord $_ -Fallback 'Control execution failed'

                Write-AuditDiagnostic `
                    -Type 'powershell_exception' `
                    -Message $exceptionMessage `
                    -ExceptionType $exceptionType `
                    -StackTrace $stackTrace

                Write-AuditLog -Message "Control $controlId exception on $($account.name)/${region}: $exceptionMessage" -Level ERROR

                $result = New-AuditResult `
                    -AccountId $account.id `
                    -AccountName $account.name `
                    -Region $region `
                    -ControlId $controlId `
                    -Status 'PARTIAL' `
                    -Evidence $null `
                    -Notes ("Exception: {0}" -f $exceptionMessage)
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

            [void]$accountResults.Add($result)
            [void]$accountEvidenceRecords.Add((New-AuditEvidenceRecord -Result $result))

            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) {
                Write-Host ('    {0}: {1}' -f $controlId, $result.Status)
            }
        }
    }

    Clear-AccountSession
    $Script:DiagnosticFile = $null

    $accountResultArray = @($accountResults.ToArray())

    Write-AccountResultsFile `
        -ResultsFile $accountPaths.ResultsFile `
        -AccountId $account.id `
        -AccountName $account.name `
        -Domain $Domain `
        -Timestamp $timestamp `
        -Auditor $Auditor `
        -Account $account `
        -Results $accountResultArray | Out-Null

    Write-AccountEvidenceFile `
        -EvidenceFile $accountPaths.EvidenceFile `
        -AccountId $account.id `
        -AccountName $account.name `
        -Domain $Domain `
        -Timestamp $timestamp `
        -Auditor $Auditor `
        -Account $account `
        -EvidenceRecords @($accountEvidenceRecords.ToArray()) | Out-Null

    $writtenAccountFolders += $accountPaths.AccountFolder
    $allAccountResults[$account.name] = $accountResultArray
    $summaryRows += Get-SummaryRow -AccountName $account.name -Results $accountResultArray
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

Write-Host ''
Write-Host ('Output folder : {0}' -f $OutputPath)
Write-Host ('Session log   : {0}' -f $Script:SessionLogFile)

if ($writtenAccountFolders.Count -gt 0) {
    Write-Host 'Account output:'
    foreach ($accountFolder in $writtenAccountFolders) {
        Write-Host ('  {0}' -f $accountFolder)
        Write-Host ('    results  : {0}' -f (Join-Path $accountFolder ('{0}_{1}.json' -f $Domain, $timestamp)))
        Write-Host ('    evidence : {0}' -f (Join-Path $accountFolder ('evidence\{0}_{1}_evidence.json' -f $Domain, $timestamp)))
        Write-Host ('    errors   : {0}' -f (Join-Path $accountFolder ('errors\AuditDiagnostics_{0}_{1}.log' -f $Domain, $timestamp)))
    }
}
