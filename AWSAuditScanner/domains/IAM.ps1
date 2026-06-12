$DomainSeverity = @{
    'IAM-01' = 'P0'
    'IAM-02' = 'P0'
    'IAM-03' = 'P0'
    'IAM-04' = 'P0'
    'IAM-05' = 'P0'
    'IAM-06' = 'P0'
    'IAM-07' = 'P0'
    'IAM-08' = 'P0'
    'IAM-09' = 'P0'
    'IAM-11' = 'P0'
    'IAM-12' = 'P0'
    'IAM-13' = 'P0'
    'IAM-14' = 'P0'
    'IAM-15' = 'P0'
    'IAM-16' = 'P0'
    'IAM-17' = 'P0'
    'IAM-18' = 'P0'
    'IAM-19' = 'P0'
    'IAM-20' = 'P0'
    'IAM-21' = 'P0'
    'IAM-22' = 'P0'
    'IAM-23' = 'P0'
    'IAM-25' = 'P0'
    'IAM-26' = 'P0'
    'IAM-27' = 'P0'
    'IAM-28' = 'P0'
    'IAM-29' = 'P0'
    'IAM-30' = 'P1'
    'IAM-31' = 'P0'
    'IAM-32' = 'P1'
    'IAM-33' = 'P0'
    'IAM-34' = 'P0'
    'IAM-35' = 'P0'
    'IAM-36' = 'P0'
    'IAM-37' = 'P0'
    'IAM-38' = 'P0'
    'IAM-39' = 'P1'
    'IAM-40' = 'P1'
    'IAM-41' = 'P0'
    'IAM-42' = 'P0'
    'IAM-43' = 'P0'
    'IAM-44' = 'P0'
    'IAM-45' = 'P0'
    'IAM-46' = 'P0'
    'IAM-47' = 'P0'
    'IAM-48' = 'P0'
    'IAM-49' = 'P0'
    'IAM-50' = 'P0'
    'IAM-51' = 'P0'
    'IAM-52' = 'P0'
    'IAM-53' = 'P0'
    'IAM-54' = 'P0'
    'IAM-55' = 'P0'
}

function Get-IamGlobalControlGate {
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
        -Notes 'Global IAM control - evaluated in eu-west-1 only'
}

function Get-IamIsoDurationHours {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Duration
    )

    if ([string]::IsNullOrWhiteSpace($Duration)) {
        return 0
    }

    if ($Duration -match '^PT(\d+)H') {
        return [int]$Matches[1]
    }

    return 0
}

function Get-IamAccountSummaryMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'get-account-summary') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'SummaryMap')) {
        return @{}
    }

    return $data.SummaryMap
}

function Get-IamAllUsers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $users = New-AuditList
    $marker = $null

    do {
        $arguments = @('iam', 'list-users', '--max-items', '1000')
        if ($marker) {
            $arguments += @('--marker', $marker)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if (Test-AuditHasProperty -Object $data -PropertyName 'Users') {
            foreach ($user in (Get-AuditCliArray $data.Users)) {
                [void]$users.Add($user)
            }
        }

        $marker = $null
        if ($data.IsTruncated -eq $true) {
            if ((Test-AuditHasProperty -Object $data -PropertyName 'Marker')) {
                if (-not [string]::IsNullOrWhiteSpace([string]$data.Marker)) {
                    $marker = [string]$data.Marker
                }
            }
        }
    } while ($marker)

    return $users.ToArray()
}

function Get-IamAllRoles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $roles = New-AuditList
    $marker = $null

    do {
        $arguments = @('iam', 'list-roles', '--max-items', '1000')
        if ($marker) {
            $arguments += @('--marker', $marker)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if (Test-AuditHasProperty -Object $data -PropertyName 'Roles') {
            foreach ($role in (Get-AuditCliArray $data.Roles)) {
                [void]$roles.Add($role)
            }
        }

        $marker = $null
        if ($data.IsTruncated -eq $true) {
            if ((Test-AuditHasProperty -Object $data -PropertyName 'Marker')) {
                if (-not [string]::IsNullOrWhiteSpace([string]$data.Marker)) {
                    $marker = [string]$data.Marker
                }
            }
        }
    } while ($marker)

    return $roles.ToArray()
}

function Test-IamUserHasConsoleAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'get-login-profile', '--user-name', $UserName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    return $true
}

function Test-IamUserHasMfa {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'list-mfa-devices', '--user-name', $UserName) -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'MFADevices') {
        return ((Get-AuditCollectionCount $data.MFADevices) -gt 0)
    }

    return $false
}

function Test-IamGenericUserName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $lowerName = $UserName.ToLower()
    if ($lowerName -eq 'admin') { return $true }
    if ($lowerName -eq 'shared') { return $true }
    if ($lowerName -eq 'administrator') { return $true }
    if ($lowerName -like 'shared*') { return $true }
    if ($lowerName -like 'service*' -and $lowerName -notlike '*owner*') { return $true }

    return $false
}

function Get-IamUserAccessKeySummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'list-access-keys', '--user-name', $UserName) -Region $Region
    if ($null -eq $data) {
        return $null
    }

    $activeKeys = @()
    if (Test-AuditHasProperty -Object $data -PropertyName 'AccessKeyMetadata') {
        foreach ($key in (Get-AuditCliArray $data.AccessKeyMetadata)) {
            if ($key.Status -eq 'Active') {
                $activeKeys += $key
            }
        }
    }

    return $activeKeys
}

function Test-IamRoleHasAdministratorAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'list-attached-role-policies', '--role-name', $RoleName) -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'AttachedPolicies')) {
        return $false
    }

    foreach ($policy in (Get-AuditCliArray $data.AttachedPolicies)) {
        $policyName = [string]$policy.PolicyName
        $policyArn = [string]$policy.PolicyArn
        if ($policyName -eq 'AdministratorAccess') {
            return $true
        }
        if ($policyArn -like '*:policy/AdministratorAccess') {
            return $true
        }
    }

    return $false
}

function Get-IamRoleTrustPolicyText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'get-role', '--role-name', $RoleName) -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'Role')) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'Role').AssumeRolePolicyDocument) {
        return $null
    }

    $document = [string]$data.Role.AssumeRolePolicyDocument
    return [uri]::UnescapeDataString($document)
}

function Test-IamCrossAccountRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,

        [Parameter(Mandatory = $true)]
        [string]$TrustPolicyText
    )

    if ([string]::IsNullOrWhiteSpace($TrustPolicyText)) {
        return $false
    }

    if ($TrustPolicyText -match 'arn:aws:iam::(\d{12}):') {
        $matchedAccount = $Matches[1]
        if ($matchedAccount -ne $AccountId) {
            return $true
        }
    }

    if ($TrustPolicyText -match '"AWS"\s*:\s*"\*"' ) {
        return $true
    }

    return $false
}

function Test-IamTrustPolicyHasExternalId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TrustPolicyText
    )

    if ([string]::IsNullOrWhiteSpace($TrustPolicyText)) {
        return $false
    }

    if ($TrustPolicyText -match 'ExternalId|sts:ExternalId') {
        return $true
    }

    return $false
}

function Get-IamSsoInstances {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('sso-admin', 'list-instances') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'Instances') {
        return @($data.Instances)
    }

    return @()
}

function Get-IamPermissionSetDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$InstanceArn
    )

    $permissionSets = @()
    $token = $null

    do {
        $arguments = @('sso-admin', 'list-permission-sets', '--instance-arn', $InstanceArn, '--max-results', '100')
        if ($token) {
            $arguments += @('--next-token', $token)
        }

        $listData = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $listData) {
            return $null
        }

        if (Test-AuditHasProperty -Object $listData -PropertyName 'PermissionSets') {
            foreach ($permissionSetArn in (Get-AuditCliArray $listData.PermissionSets)) {
                $describeData = Invoke-AWSCLI -Arguments @(
                    'sso-admin', 'describe-permission-set',
                    '--instance-arn', $InstanceArn,
                    '--permission-set-arn', $permissionSetArn
                ) -Region $Region

                if ($describeData -and $describeData.PermissionSet) {
                    $permissionSets += $describeData.PermissionSet
                }
            }
        }

        $token = $null
        if ((Test-AuditHasProperty -Object $listData -PropertyName 'NextToken')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$listData.NextToken)) {
                $token = [string]$listData.NextToken
            }
        }
    } while ($token)

    return $permissionSets
}

function Test-IamPermissionSetHasAdministratorAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$InstanceArn,

        [Parameter(Mandatory = $true)]
        [string]$PermissionSetArn
    )

    $data = Invoke-AWSCLI -Arguments @(
        'sso-admin', 'list-managed-policies-in-permission-set',
        '--instance-arn', $InstanceArn,
        '--permission-set-arn', $PermissionSetArn
    ) -Region $Region

    if ($null -eq $data) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'AttachedManagedPolicies')) {
        return $false
    }

    foreach ($policy in (Get-AuditCliArray $data.AttachedManagedPolicies)) {
        if ([string]$policy.Name -eq 'AdministratorAccess') {
            return $true
        }
    }

    return $false
}

function Get-IamRolesAnywhereContext {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $anchorData = Invoke-AWSCLI -Arguments @('rolesanywhere', 'list-trust-anchors') -Region $Region
    $profileData = Invoke-AWSCLI -Arguments @('rolesanywhere', 'list-profiles') -Region $Region

    if ($null -eq $anchorData -and $null -eq $profileData) {
        return $null
    }

    $anchors = @()
    if ($anchorData -and $anchorData.TrustAnchors) {
        $anchors = @($anchorData.TrustAnchors)
    }

    $profiles = @()
    if ($profileData -and $profileData.Profiles) {
        $profiles = @($profileData.Profiles)
    }

    return [PSCustomObject]@{
        TrustAnchors = $anchors
        Profiles     = $profiles
        Detected     = (((Get-AuditCollectionCount $anchors) -gt 0) -or ((Get-AuditCollectionCount $profiles) -gt 0))
    }
}

function New-IamRolesAnywhereNotDetectedResult {
    param(
        [string]$AccountId,
        [string]$AccountName,
        [string]$Region,
        [string]$ControlId
    )

    return New-AuditResult `
        -AccountId $AccountId `
        -AccountName $AccountName `
        -Region $Region `
        -ControlId $ControlId `
        -Status 'NOT_TESTED' `
        -Evidence $null `
        -Notes 'IAM Roles Anywhere not detected in this account'
}

function Get-DomainChecks {
    return [ordered]@{
        'IAM-01' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-01'
            if ($gate) { return $gate }

            $summary = Get-IamAccountSummaryMap -Region $Region
            if ($null -eq $summary) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-01'
            }

            $mfaEnabled = $null
            if ((Test-AuditHasProperty -Object $summary -PropertyName 'AccountMFAEnabled')) {
                $mfaEnabled = [int]$summary.AccountMFAEnabled
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-01' `
                -Status 'PARTIAL' `
                -Evidence @{ AccountMFAEnabled = $mfaEnabled } `
                -Notes 'Root last-used date requires credential report. Verify via console or credential report.'
        }

        'IAM-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-02'
            if ($gate) { return $gate }

            $summary = Get-IamAccountSummaryMap -Region $Region
            if ($null -eq $summary) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-02'
            }

            $mfaEnabled = 0
            if ((Test-AuditHasProperty -Object $summary -PropertyName 'AccountMFAEnabled')) {
                $mfaEnabled = [int]$summary.AccountMFAEnabled
            }

            if ($mfaEnabled -eq 1) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-02' `
                    -Status 'PASS' -Evidence @{ AccountMFAEnabled = $mfaEnabled } -Notes 'Root MFA is enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-02' `
                -Status 'FAIL' -Evidence @{ AccountMFAEnabled = $mfaEnabled } -Notes 'Root MFA is not enabled'
        }

        'IAM-03' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-03'
            if ($gate) { return $gate }

            $summary = Get-IamAccountSummaryMap -Region $Region
            if ($null -eq $summary) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-03'
            }

            $keysPresent = 0
            if ((Test-AuditHasProperty -Object $summary -PropertyName 'AccountAccessKeysPresent')) {
                $keysPresent = [int]$summary.AccountAccessKeysPresent
            }

            if ($keysPresent -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-03' `
                    -Status 'PASS' -Evidence @{ AccountAccessKeysPresent = $keysPresent } -Notes 'No root access keys present'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-03' `
                -Status 'FAIL' -Evidence @{ AccountAccessKeysPresent = $keysPresent } -Notes 'Root access keys are present'
        }

        'IAM-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-04'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-04' `
                -Notes 'Verify formal procedure exists for root usage (RFC required + MFA). Check Confluence or DEX.'
        }

        'IAM-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-05'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-05'
            }

            $consoleUserCount = 0
            $consoleUsernames = @()
            $unclearCount = 0

            foreach ($user in $users) {
                $userName = [string]$user.UserName
                $hasConsole = Test-IamUserHasConsoleAccess -Region $Region -UserName $userName
                if ($hasConsole) {
                    $consoleUserCount++
                    if ((Get-AuditCollectionCount $consoleUsernames) -lt 5) {
                        $consoleUsernames += $userName
                    }
                }
            }

            $evidence = @{
                iam_user_count       = (Get-AuditCollectionCount $users)
                console_user_count   = $consoleUserCount
                console_usernames    = @($consoleUsernames)
                unclear_status_count = $unclearCount
            }

            if ($consoleUserCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-05' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Local IAM users with console access exist'
            }

            if ((Get-AuditCollectionCount $users) -gt 0 -and $unclearCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-05' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Users exist but console access status unclear'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-05' `
                -Status 'PASS' -Evidence $evidence -Notes 'No local IAM users with console access detected'
        }

        'IAM-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-06'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-06'
            }

            $consoleUserCount = 0
            $withMfaCount = 0
            $withoutMfaCount = 0
            $usersWithoutMfa = @()

            foreach ($user in $users) {
                $userName = [string]$user.UserName
                if (-not (Test-IamUserHasConsoleAccess -Region $Region -UserName $userName)) {
                    continue
                }

                $consoleUserCount++
                $hasMfa = Test-IamUserHasMfa -Region $Region -UserName $userName
                if ($hasMfa -eq $true) {
                    $withMfaCount++
                }
                else {
                    $withoutMfaCount++
                    if ((Get-AuditCollectionCount $usersWithoutMfa) -lt 5) {
                        $usersWithoutMfa += $userName
                    }
                }
            }

            $evidence = @{
                console_user_count = $consoleUserCount
                with_mfa_count     = $withMfaCount
                without_mfa_count  = $withoutMfaCount
                users_without_mfa  = @($usersWithoutMfa)
            }

            if ($withoutMfaCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-06' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more console users do not have MFA'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-06' `
                -Status 'PASS' -Evidence $evidence -Notes 'All console users have MFA devices'
        }

        'IAM-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07'
            }

            if ((Get-AuditCollectionCount $instances) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07' `
                    -Status 'PARTIAL' -Evidence @{ permission_set_count = 0 } `
                    -Notes 'No Identity Center instance found to assess session duration'
            }

            $durationBuckets = @{}
            $longDurationSets = @()
            $permissionSetCount = 0

            foreach ($instance in $instances) {
                $permissionSets = Get-IamPermissionSetDetails -Region $Region -InstanceArn $instance.InstanceArn
                if ($null -eq $permissionSets) {
                    continue
                }

                foreach ($permissionSet in $permissionSets) {
                    $permissionSetCount++
                    $duration = 'PT1H'
                    if (Test-AuditHasProperty -Object $permissionSet -PropertyName 'SessionDuration') {
                        $duration = [string]$permissionSet.SessionDuration
                    }

                    if (-not $durationBuckets.ContainsKey($duration)) {
                        $durationBuckets[$duration] = 0
                    }
                    $durationBuckets[$duration] = $durationBuckets[$duration] + 1

                    $hours = Get-IamIsoDurationHours -Duration $duration
                    if ($hours -gt 8) {
                        if ((Get-AuditCollectionCount $longDurationSets) -lt 10) {
                            $longDurationSets += [string]$permissionSet.Name
                        }
                    }
                }
            }

            $evidence = @{
                permission_set_count = $permissionSetCount
                duration_buckets     = $durationBuckets
                long_duration_names  = @($longDurationSets)
            }

            if ((Get-AuditCollectionCount $longDurationSets) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more permission sets exceed PT8H session duration'
            }

            if ($permissionSetCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Mixed durations, no documented policy by role level'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-07' `
                -Status 'PASS' -Evidence $evidence -Notes 'All permission sets are at most PT8H'
        }

        'IAM-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-08'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-08'
            }

            $genericNames = @()
            foreach ($user in $users) {
                if (Test-IamGenericUserName -UserName ([string]$user.UserName)) {
                    if ((Get-AuditCollectionCount $genericNames) -lt 10) {
                        $genericNames += [string]$user.UserName
                    }
                }
            }

            $evidence = @{
                user_count    = (Get-AuditCollectionCount $users)
                generic_names = @($genericNames)
            }

            if ((Get-AuditCollectionCount $genericNames) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-08' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Generic or shared IAM usernames found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-08' `
                -Status 'PASS' -Evidence $evidence -Notes 'No generic shared IAM usernames detected'
        }

        'IAM-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09'
            }

            $instances = Get-IamSsoInstances -Region $Region
            $identityCenterActive = ($null -ne $instances -and (Get-AuditCollectionCount $instances) -gt 0)

            $activeKeyCount = 0
            foreach ($user in $users) {
                $keys = Get-IamUserAccessKeySummary -Region $Region -UserName ([string]$user.UserName)
                if ($null -eq $keys) { continue }
                $activeKeyCount += (Get-AuditCollectionCount $keys)
            }

            $evidence = @{
                identity_center_active = $identityCenterActive
                iam_user_count         = (Get-AuditCollectionCount $users)
                active_access_key_count = $activeKeyCount
            }

            if ($activeKeyCount -gt 5 -and -not $identityCenterActive) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Many static access keys found without Identity Center'
            }

            if ($identityCenterActive -and $activeKeyCount -le 5) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Identity Center active with minimal static access keys'
            }

            if ($activeKeyCount -gt 5) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Many users with static access keys for human access'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-09' `
                -Status 'PASS' -Evidence $evidence -Notes 'Human access appears STS-based with limited static keys'
        }

        'IAM-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-11'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-11'
            }

            $adminRoles = @()
            $adminRoleCount = 0
            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                $hasAdmin = Test-IamRoleHasAdministratorAccess -Region $Region -RoleName $roleName
                if ($hasAdmin -eq $true) {
                    $adminRoleCount++
                    if ((Get-AuditCollectionCount $adminRoles) -lt 10) {
                        $adminRoles += $roleName
                    }
                }
            }

            $evidence = @{
                role_count               = (Get-AuditCollectionCount $roles)
                administrator_role_count = $adminRoleCount
                administrator_roles      = @($adminRoles)
            }

            if ($adminRoleCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-11' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Roles with AdministratorAccess found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-11' `
                -Status 'PASS' -Evidence $evidence -Notes 'No AdministratorAccess on non-admin roles detected'
        }

        'IAM-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-12'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-12'
            }

            $adminRoles = @()
            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                if (Test-IamRoleHasAdministratorAccess -Region $Region -RoleName $roleName) {
                    $adminRoles += $roleName
                }
            }

            $evidence = @{
                administrator_role_count = (Get-AuditCollectionCount $adminRoles)
                administrator_roles      = @($adminRoles)
            }

            if ((Get-AuditCollectionCount $adminRoles) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-12' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'AdministratorAccess found on roles outside approved exception list'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-12' `
                -Status 'PASS' -Evidence $evidence -Notes 'No roles with AdministratorAccess managed policy found'
        }

        'IAM-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-13'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-13'
            }

            $delegatedCount = 0
            $withBoundaryCount = 0
            $withoutBoundary = @()

            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                $path = [string]$role.Path
                if ($path -like '/aws-service-role/*') {
                    continue
                }

                $trustText = Get-IamRoleTrustPolicyText -Region $Region -RoleName $roleName
                if (-not $trustText) {
                    continue
                }

                $isDelegated = Test-IamCrossAccountRole -AccountId $AccountId -TrustPolicyText $trustText
                if (-not $isDelegated) {
                    continue
                }

                $delegatedCount++
                $roleData = Invoke-AWSCLI -Arguments @('iam', 'get-role', '--role-name', $roleName) -Region $Region
                if ($roleData -and $roleData.Role -and $roleData.Role.PermissionsBoundary) {
                    $withBoundaryCount++
                }
                else {
                    if ((Get-AuditCollectionCount $withoutBoundary) -lt 10) {
                        $withoutBoundary += $roleName
                    }
                }
            }

            $evidence = @{
                role_count              = (Get-AuditCollectionCount $roles)
                delegated_role_count    = $delegatedCount
                with_boundary_count     = $withBoundaryCount
                without_boundary_roles  = @($withoutBoundary)
            }

            if ((Get-AuditCollectionCount $withoutBoundary) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-13' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Cross-account delegated roles without permission boundary found'
            }

            if ($delegatedCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-13' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Cannot determine which roles are delegated'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-13' `
                -Status 'PASS' -Evidence $evidence -Notes 'Cross-account delegated roles have permission boundaries set'
        }

        'IAM-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-14'
            if ($gate) { return $gate }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-14' `
                -Status 'PARTIAL' -Evidence $null `
                -Notes 'Full policy analysis required. Spot-check critical roles for condition usage.'
        }

        'IAM-15' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-15'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-15'
            }

            $crossAccountCount = 0
            $withExternalIdCount = 0
            $missingExternalId = @()

            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                $trustText = Get-IamRoleTrustPolicyText -Region $Region -RoleName $roleName
                if (-not $trustText) { continue }

                if (-not (Test-IamCrossAccountRole -AccountId $AccountId -TrustPolicyText $trustText)) {
                    continue
                }

                $crossAccountCount++
                if (Test-IamTrustPolicyHasExternalId -TrustPolicyText $trustText) {
                    $withExternalIdCount++
                }
                else {
                    if ((Get-AuditCollectionCount $missingExternalId) -lt 10) {
                        $missingExternalId += $roleName
                    }
                }
            }

            $evidence = @{
                cross_account_role_count = $crossAccountCount
                with_external_id_count   = $withExternalIdCount
                missing_external_id_roles = @($missingExternalId)
            }

            if ($crossAccountCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-15' `
                    -Status 'PASS' -Evidence $evidence -Notes 'No cross-account roles found'
            }

            if ((Get-AuditCollectionCount $missingExternalId) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-15' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Cross-account roles without ExternalId condition found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-15' `
                -Status 'PASS' -Evidence $evidence -Notes 'All cross-account roles have ExternalId condition'
        }

        'IAM-16' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-16'
            if ($gate) { return $gate }

            $data = Invoke-AWSCLI -Arguments @('accessanalyzer', 'list-analyzers') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-16'
            }

            $analyzers = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'analyzers') {
                $analyzers = @($data.analyzers)
            }

            $orgAnalyzers = @()
            $accountAnalyzers = @()
            foreach ($analyzer in $analyzers) {
                $record = @{
                    name   = [string]$analyzer.name
                    type   = [string]$analyzer.type
                    status = [string]$analyzer.status
                }
                if ($analyzer.type -eq 'ORGANIZATION' -and $analyzer.status -eq 'ACTIVE') {
                    $orgAnalyzers += $record
                }
                if ($analyzer.type -eq 'ACCOUNT') {
                    $accountAnalyzers += $record
                }
            }

            $evidence = @{
                analyzer_count         = (Get-AuditCollectionCount $analyzers)
                organization_analyzers = @($orgAnalyzers)
                account_analyzers      = @($accountAnalyzers)
            }

            if ((Get-AuditCollectionCount $orgAnalyzers) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-16' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Organization-level IAM Access Analyzer is active'
            }

            if ((Get-AuditCollectionCount $accountAnalyzers) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-16' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Account-level analyzer only'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-16' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No organization-level analyzer found'
        }

        'IAM-17' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-17'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-17'
            }

            $usersWithKeys = @()
            $totalActiveKeys = 0

            foreach ($user in $users) {
                $userName = [string]$user.UserName
                $keys = Get-IamUserAccessKeySummary -Region $Region -UserName $userName
                if ($null -eq $keys) { continue }
                if ((Get-AuditCollectionCount $keys) -gt 0) {
                    $totalActiveKeys += (Get-AuditCollectionCount $keys)
                    if ((Get-AuditCollectionCount $usersWithKeys) -lt 10) {
                        $usersWithKeys += $userName
                    }
                }
            }

            $evidence = @{
                user_count           = (Get-AuditCollectionCount $users)
                active_key_count     = $totalActiveKeys
                users_with_keys      = @($usersWithKeys)
            }

            if ($totalActiveKeys -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-17' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Active access keys found on IAM users'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-17' `
                -Status 'PASS' -Evidence $evidence -Notes 'No active access keys on IAM users'
        }

        'IAM-18' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-18'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-18'
            }

            $staleKeys = @()
            $activeKeyCount = 0

            foreach ($user in $users) {
                $keys = Get-IamUserAccessKeySummary -Region $Region -UserName ([string]$user.UserName)
                if ($null -eq $keys) { continue }

                foreach ($key in $keys) {
                    $activeKeyCount++
                    $createDate = [datetime]$key.CreateDate
                    $ageDays = ((Get-Date) - $createDate).Days
                    if ($ageDays -gt 90) {
                        if ((Get-AuditCollectionCount $staleKeys) -lt 10) {
                            $staleKeys += @{
                                access_key_id = [string]$key.AccessKeyId
                                user_name     = [string]$user.UserName
                                age_days      = $ageDays
                                create_date   = $createDate.ToString('o')
                            }
                        }
                    }
                }
            }

            $evidence = @{
                active_key_count = $activeKeyCount
                stale_key_count  = (Get-AuditCollectionCount $staleKeys)
                stale_keys       = @($staleKeys)
            }

            if ((Get-AuditCollectionCount $staleKeys) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-18' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Access keys older than 90 days found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-18' `
                -Status 'PASS' -Evidence $evidence -Notes 'All active access keys are within 90 days'
        }

        'IAM-19' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-19'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-19'
            }

            $pipelineAdminRoles = @()
            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                if ($roleName -notmatch 'Deploy|Pipeline|CICD|Script') {
                    continue
                }

                if (Test-IamRoleHasAdministratorAccess -Region $Region -RoleName $roleName) {
                    $pipelineAdminRoles += $roleName
                }
            }

            $evidence = @{
                pipeline_admin_roles = @($pipelineAdminRoles)
            }

            if ((Get-AuditCollectionCount $pipelineAdminRoles) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-19' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Pipeline roles with AdministratorAccess found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-19' `
                -Status 'PASS' -Evidence $evidence -Notes 'No pipeline roles with AdministratorAccess found'
        }

        'IAM-20' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-20'
            if ($gate) { return $gate }

            $data = Invoke-AWSCLI -Arguments @('iam', 'list-open-id-connect-providers') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-20'
            }

            $providers = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'OpenIDConnectProviderList') {
                foreach ($provider in (Get-AuditCliArray $data.OpenIDConnectProviderList)) {
                    if (Test-AuditHasProperty -Object $provider -PropertyName 'Arn') {
                        $providers += [string]$provider.Arn
                    }
                }
            }

            $evidence = @{ oidc_provider_arns = @($providers) }

            if ((Get-AuditCollectionCount $providers) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-20' `
                    -Status 'PASS' -Evidence $evidence -Notes 'OIDC provider configured for pipeline authentication'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-20' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No OIDC providers found'
        }

        'IAM-21' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-21'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-21' `
                -Notes 'Verify periodic access review process exists (frequency, owner, treatment of non-recertified access).'
        }

        'IAM-22' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-22'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-22' `
                -Notes 'Verify offboarding procedure triggers immediate Identity Center disabling. Check ServiceNow/ITSM integration.'
        }

        'IAM-23' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-23'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-23' `
                -Notes 'Verify time-boxed elevation exists for break-glass access. Check CCOScriptAdmin RFC process.'
        }

        'IAM-25' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-25'
            if ($gate) { return $gate }

            $alarmData = Invoke-AWSCLI -Arguments @('cloudwatch', 'describe-alarms') -Region $Region
            $rulesData = Invoke-AWSCLI -Arguments @('events', 'list-rules') -Region $Region

            if ($null -eq $alarmData -and $null -eq $rulesData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-25'
            }

            $matchingAlarms = @()
            if ($alarmData -and $alarmData.MetricAlarms) {
                foreach ($alarm in (Get-AuditCliArray $alarmData.MetricAlarms)) {
                    $alarmName = [string]$alarm.AlarmName
                    $metricName = [string]$alarm.MetricName
                    if ($alarmName -match 'KMS|Key' -or $metricName -match 'ScheduleKeyDeletion|KMS') {
                        $matchingAlarms += $alarmName
                    }
                }
            }

            $matchingRules = @()
            if ($rulesData -and $rulesData.Rules) {
                foreach ($rule in (Get-AuditCliArray $rulesData.Rules)) {
                    $ruleName = [string]$rule.Name
                    $eventPattern = [string]$rule.EventPattern
                    if ($ruleName -match 'KMS|Key' -or $eventPattern -match 'kms|ScheduleKeyDeletion') {
                        $matchingRules += $ruleName
                    }
                }
            }

            $evidence = @{
                matching_alarm_names = @($matchingAlarms)
                matching_rule_names  = @($matchingRules)
            }

            if ((Get-AuditCollectionCount $matchingAlarms) -gt 0 -or (Get-AuditCollectionCount $matchingRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-25' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Alerting on KMS key deletion events found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-25' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No alerting on KMS ScheduleKeyDeletion found'
        }

        'IAM-26' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-26'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-26'
            }

            $contractorUsers = @()
            foreach ($user in $users) {
                $userName = [string]$user.UserName
                if ($userName -match 'external|contractor|vendor') {
                    if ((Get-AuditCollectionCount $contractorUsers) -lt 10) {
                        $contractorUsers += $userName
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-26' `
                -Status 'PARTIAL' `
                -Evidence @{
                    user_count         = (Get-AuditCollectionCount $users)
                    contractor_matches = @($contractorUsers)
                } `
                -Notes 'Verify contractor access managed via ITSM with end date. Check Management account access for no-end-date accounts.'
        }

        'IAM-27' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-27'
            if ($gate) { return $gate }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-27'
            }

            $mixedIdentityUsers = @()
            foreach ($user in $users) {
                $userName = [string]$user.UserName
                $hasConsole = Test-IamUserHasConsoleAccess -Region $Region -UserName $userName
                $keys = Get-IamUserAccessKeySummary -Region $Region -UserName $userName
                $hasKeys = ($null -ne $keys -and (Get-AuditCollectionCount $keys) -gt 0)

                if ($hasConsole -and $hasKeys) {
                    if ((Get-AuditCollectionCount $mixedIdentityUsers) -lt 10) {
                        $mixedIdentityUsers += $userName
                    }
                }
            }

            $evidence = @{
                mixed_identity_count = (Get-AuditCollectionCount $mixedIdentityUsers)
                mixed_identity_users = @($mixedIdentityUsers)
            }

            if ((Get-AuditCollectionCount $mixedIdentityUsers) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-27' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Users with both console and programmatic access found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-27' `
                -Status 'PASS' -Evidence $evidence -Notes 'Clear separation between human and machine identities'
        }

        'IAM-28' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-28'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-28'
            }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-28' `
                -Notes 'Verify formal SSI decision authorizes IAM Roles Anywhere usage.'
        }

        'IAM-29' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-29'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-29'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-29' `
                -Status 'PARTIAL' `
                -Evidence @{
                    trust_anchor_count = (Get-AuditCollectionCount $context.TrustAnchors)
                    profile_count      = (Get-AuditCollectionCount $context.Profiles)
                } `
                -Notes 'Verify external workloads using trust anchors are inventoried.'
        }

        'IAM-30' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-30'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-30'
            }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-30' `
                -Notes 'Verify on-premises workload inventory exists.'
        }

        'IAM-31' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-31'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-31'
            }

            $publicCaCount = 0
            $privateCaCount = 0
            $sourceTypes = @()

            foreach ($anchor in (Get-AuditCliArray $context.TrustAnchors)) {
                $sourceType = [string]$anchor.SourceType
                if ((Get-AuditCollectionCount $sourceTypes) -lt 10) {
                    $sourceTypes += $sourceType
                }
                if ($sourceType -eq 'AWS_ACM_PCA') {
                    $privateCaCount++
                }
                else {
                    $publicCaCount++
                }
            }

            $evidence = @{
                trust_anchor_count = (Get-AuditCollectionCount $context.TrustAnchors)
                private_ca_count   = $privateCaCount
                public_ca_count    = $publicCaCount
                source_types       = @($sourceTypes)
            }

            if ($publicCaCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-31' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Trust anchor uses public CA instead of private CA'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-31' `
                -Status 'PASS' -Evidence $evidence -Notes 'Trust anchors use private CA sources'
        }

        'IAM-32' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-32'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-32'
            }

            $longLifetimeProfiles = @()
            foreach ($profile in (Get-AuditCliArray $context.Profiles)) {
                $duration = 0
                if ($profile.SessionPolicy -and $profile.DurationSeconds) {
                    $duration = [int]$profile.DurationSeconds
                }
                if ((Test-AuditHasProperty -Object $profile -PropertyName 'DurationSeconds')) {
                    $duration = [int]$profile.DurationSeconds
                }

                $days = [math]::Round(($duration / 86400), 2)
                if ($days -gt 90) {
                    if ((Get-AuditCollectionCount $longLifetimeProfiles) -lt 10) {
                        $longLifetimeProfiles += [string]$profile.Name
                    }
                }
            }

            $evidence = @{
                profile_count            = (Get-AuditCollectionCount $context.Profiles)
                long_lifetime_profiles   = @($longLifetimeProfiles)
            }

            if ((Get-AuditCollectionCount $longLifetimeProfiles) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-32' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Profile certificate lifetime exceeds 90 days'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-32' `
                -Status 'PASS' -Evidence $evidence -Notes 'Profile session durations are within 90 days'
        }

        'IAM-33' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-33'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-33'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-33' `
                -Status 'PARTIAL' `
                -Evidence @{ trust_anchor_count = (Get-AuditCollectionCount $context.TrustAnchors) } `
                -Notes 'Verify CRL mechanism exists and propagates in under 10 minutes.'
        }

        'IAM-34' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-34'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-34'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-34' `
                -Status 'PARTIAL' `
                -Evidence @{ profile_count = (Get-AuditCollectionCount $context.Profiles) } `
                -Notes 'Verify private key storage uses HSM or Secrets Manager. CCoE cannot enforce this.'
        }

        'IAM-35' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-35'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-35'
            }

            $roleIds = @()
            $sharedRoleCount = 0
            foreach ($profile in (Get-AuditCliArray $context.Profiles)) {
                $roleArn = [string]$profile.RoleArn
                if ([string]::IsNullOrWhiteSpace($roleArn)) { continue }
                if ($roleIds -contains $roleArn) {
                    $sharedRoleCount++
                }
                else {
                    $roleIds += $roleArn
                }
            }

            $evidence = @{
                profile_count     = (Get-AuditCollectionCount $context.Profiles)
                unique_role_count = (Get-AuditCollectionCount $roleIds)
                shared_role_count = $sharedRoleCount
            }

            if ($sharedRoleCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-35' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Multiple profiles share the same IAM role'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-35' `
                -Status 'PASS' -Evidence $evidence -Notes 'Each profile maps to a dedicated IAM role'
        }

        'IAM-36' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-36'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-36'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-36' `
                -Status 'PARTIAL' `
                -Evidence @{ profile_count = (Get-AuditCollectionCount $context.Profiles) } `
                -Notes 'Workload role permissions at workload discretion. Spot-check via IAM role analysis.'
        }

        'IAM-37' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-37'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-37'
            }

            $profilesWithConditions = 0
            $profilesWithoutConditions = 0
            foreach ($profile in (Get-AuditCliArray $context.Profiles)) {
                $policyText = [string]$profile.SessionPolicy
                if ($policyText -match 'serialNumber|aws:SourceIp|IpAddress') {
                    $profilesWithConditions++
                }
                else {
                    $profilesWithoutConditions++
                }
            }

            $evidence = @{
                profile_count                 = (Get-AuditCollectionCount $context.Profiles)
                profiles_with_conditions      = $profilesWithConditions
                profiles_without_conditions   = $profilesWithoutConditions
            }

            if ($profilesWithoutConditions -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-37' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Profiles missing serial number or IP restrictions'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-37' `
                -Status 'PASS' -Evidence $evidence -Notes 'Profiles include serial number or IP condition checks'
        }

        'IAM-38' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-38'
            if ($gate) { return $gate }

            $context = Get-IamRolesAnywhereContext -Region $Region
            if ($null -eq $context -or -not (Test-AuditHasProperty -Object $context -PropertyName 'Detected')) {
                return New-IamRolesAnywhereNotDetectedResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-38'
            }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-38' `
                -Notes 'Verify offboarding, certificate renewal and incident procedures are documented.'
        }

        'IAM-39' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-39'
            if ($gate) { return $gate }

            $statusData = Invoke-AWSCLI -Arguments @('config', 'describe-configuration-recorder-status') -Region $Region
            $rulesData = Invoke-AWSCLI -Arguments @('config', 'list-config-rules', '--max-results', '100') -Region $Region

            if ($null -eq $statusData -and $null -eq $rulesData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-39'
            }

            $recorderActive = $false
            if ($statusData -and $statusData.ConfigurationRecordersStatus) {
                foreach ($status in (Get-AuditCliArray $statusData.ConfigurationRecordersStatus)) {
                    if ($status.recording -eq $true) {
                        $recorderActive = $true
                        break
                    }
                }
            }

            $iamRules = @()
            if ($rulesData -and $rulesData.ConfigRules) {
                foreach ($rule in (Get-AuditCliArray $rulesData.ConfigRules)) {
                    $ruleName = [string]$rule.ConfigRuleName
                    if ($ruleName -match 'IAM|iam') {
                        $iamRules += $ruleName
                    }
                }
            }

            $evidence = @{
                recorder_active = $recorderActive
                iam_rule_count  = (Get-AuditCollectionCount $iamRules)
                iam_rule_names  = @($iamRules)
            }

            if ($recorderActive -and (Get-AuditCollectionCount $iamRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-39' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Config recorder active with IAM rules'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-39' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No Config recording or no IAM Config rules'
        }

        'IAM-40' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-40'
            if ($gate) { return $gate }

            $roles = Get-IamAllRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-40'
            }

            $sampleNames = @()
            $prefixes = @{}
            $sampleLimit = 50
            $count = 0

            foreach ($role in $roles) {
                if ($count -ge $sampleLimit) { break }
                $roleName = [string]$role.RoleName
                $sampleNames += $roleName
                $prefix = $roleName
                if ($roleName -match '^([^-/_]+)') {
                    $prefix = $Matches[1]
                }
                if (-not $prefixes.ContainsKey($prefix)) {
                    $prefixes[$prefix] = 0
                }
                $prefixes[$prefix] = $prefixes[$prefix] + 1
                $count++
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-40' `
                -Status 'PARTIAL' `
                -Evidence @{
                    sampled_role_count = (Get-AuditCollectionCount $sampleNames)
                    sample_role_names  = @($sampleNames)
                    prefix_counts      = $prefixes
                } `
                -Notes 'Verify naming convention document exists. Spot-check role names against convention.'
        }

        'IAM-41' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-41'
            if ($gate) { return $gate }

            $generateData = Invoke-AWSCLI -Arguments @('iam', 'generate-credential-report') -Region $Region
            if ($null -eq $generateData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-41'
            }

            $state = $null
            if ((Test-AuditHasProperty -Object $generateData -PropertyName 'State')) {
                $state = [string]$generateData.State
            }

            $reportData = Invoke-AWSCLI -Arguments @('iam', 'get-credential-report') -Region $Region
            $generatedDate = $null
            if ($reportData -and $reportData.GeneratedTime) {
                $generatedDate = [string]$reportData.GeneratedTime
            }

            $evidence = @{
                generation_state = $state
                generated_time   = $generatedDate
            }

            if ($reportData) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-41' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Credential report generated successfully'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-41' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Cannot generate credential report'
        }

        'IAM-42' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-42'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-42' `
                -Notes 'Verify formal document defines Identity Center usage: scope, admin procedures, review process.'
        }

        'IAM-43' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43'
            }

            $users = Get-IamAllUsers -Region $Region
            if ($null -eq $users) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43'
            }

            $consoleUserCount = 0
            foreach ($user in $users) {
                if (Test-IamUserHasConsoleAccess -Region $Region -UserName ([string]$user.UserName)) {
                    $consoleUserCount++
                }
            }

            $instanceArn = $null
            if ((Get-AuditCollectionCount $instances) -gt 0) {
                $instanceArn = [string]$instances[0].InstanceArn
            }

            $evidence = @{
                identity_center_instance_arn = $instanceArn
                local_console_user_count     = $consoleUserCount
                iam_user_count               = (Get-AuditCollectionCount $users)
            }

            if ((Get-AuditCollectionCount $instances) -gt 0 -and $consoleUserCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Identity Center active with no local IAM console users'
            }

            if ($consoleUserCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Local IAM users with console access exist'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-43' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Identity Center not active'
        }

        'IAM-44' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-44'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances -or (Get-AuditCollectionCount $instances) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-44' `
                    -Status 'FAIL' -Evidence @{ instance_count = 0 } -Notes 'No Identity Center instance found'
            }

            $instanceArn = [string]$instances[0].InstanceArn
            $describeData = Invoke-AWSCLI -Arguments @('sso-admin', 'describe-instance', '--instance-arn', $instanceArn) -Region $Region
            $appsData = Invoke-AWSCLI -Arguments @('sso-admin', 'list-applications', '--instance-arn', $instanceArn) -Region $Region

            if ($null -eq $describeData -and $null -eq $appsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-44'
            }

            $externalApps = @()
            if ($appsData -and $appsData.Applications) {
                foreach ($app in (Get-AuditCliArray $appsData.Applications)) {
                    $providerArn = [string]$app.ApplicationProviderArn
                    if ($providerArn -and $providerArn -notmatch 'awsapps\.com') {
                        $externalApps += [string]$app.ApplicationArn
                    }
                }
            }

            $identityStoreId = $null
            if ($describeData -and $describeData.Instance -and $describeData.Instance.IdentityStoreId) {
                $identityStoreId = [string]$describeData.Instance.IdentityStoreId
            }

            $evidence = @{
                instance_arn        = $instanceArn
                identity_store_id   = $identityStoreId
                external_app_count  = (Get-AuditCollectionCount $externalApps)
                external_app_arns   = @($externalApps)
            }

            if ((Get-AuditCollectionCount $externalApps) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-44' `
                    -Status 'PASS' -Evidence $evidence -Notes 'External IdP application configured'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-44' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'Internal IAM Identity Center (not externally federated)'
        }

        'IAM-45' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-45'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-45'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-45' `
                -Status 'PARTIAL' `
                -Evidence @{ identity_center_instance_count = (Get-AuditCollectionCount $instances) } `
                -Notes 'MFA enforcement configured in Guardian IdP upstream. Verify MFA=Required in Identity Center auth settings.'
        }

        'IAM-46' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-46'
            if ($gate) { return $gate }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-46' `
                -Status 'PARTIAL' -Evidence $null `
                -Notes 'Verify authentication policy is set to MFA required. Check session duration policy. Guardian constraints noted.'
        }

        'IAM-47' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-47'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances -or (Get-AuditCollectionCount $instances) -eq 0) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-47'
            }

            $sampleNames = @()
            $permissionSetCount = 0
            foreach ($instance in $instances) {
                $permissionSets = Get-IamPermissionSetDetails -Region $Region -InstanceArn $instance.InstanceArn
                if ($null -eq $permissionSets) { continue }
                foreach ($permissionSet in $permissionSets) {
                    $permissionSetCount++
                    if ((Get-AuditCollectionCount $sampleNames) -lt 10 -and $permissionSet.Name) {
                        $sampleNames += [string]$permissionSet.Name
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-47' `
                -Status 'PARTIAL' `
                -Evidence @{
                    permission_set_count = $permissionSetCount
                    sample_names         = @($sampleNames)
                } `
                -Notes 'Verify permission set naming convention and governance process exists.'
        }

        'IAM-48' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-48'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances -or (Get-AuditCollectionCount $instances) -eq 0) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-48'
            }

            $adminPermissionSets = @()
            foreach ($instance in $instances) {
                $permissionSets = Get-IamPermissionSetDetails -Region $Region -InstanceArn $instance.InstanceArn
                if ($null -eq $permissionSets) { continue }

                foreach ($permissionSet in $permissionSets) {
                    if (Test-IamPermissionSetHasAdministratorAccess -Region $Region -InstanceArn $instance.InstanceArn -PermissionSetArn $permissionSet.PermissionSetArn) {
                        if ((Get-AuditCollectionCount $adminPermissionSets) -lt 10) {
                            $adminPermissionSets += [string]$permissionSet.Name
                        }
                    }
                }
            }

            $evidence = @{
                administrator_permission_sets = @($adminPermissionSets)
            }

            if ((Get-AuditCollectionCount $adminPermissionSets) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-48' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Permission Sets with AdministratorAccess found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-48' `
                -Status 'PASS' -Evidence $evidence -Notes 'No AdministratorAccess on standard Permission Sets'
        }

        'IAM-49' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-49'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-49'
            }

            $sampleNames = @()
            foreach ($instance in $instances) {
                $permissionSets = Get-IamPermissionSetDetails -Region $Region -InstanceArn $instance.InstanceArn
                if ($null -eq $permissionSets) { continue }
                foreach ($permissionSet in $permissionSets) {
                    if ((Get-AuditCollectionCount $sampleNames) -lt 20 -and $permissionSet.Name) {
                        $sampleNames += [string]$permissionSet.Name
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-49' `
                -Status 'PARTIAL' `
                -Evidence @{ sample_permission_set_names = @($sampleNames) } `
                -Notes 'Verify separate Permission Sets exist for admin, security, ops, readonly, devops roles.'
        }

        'IAM-50' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-50'
            if ($gate) { return $gate }

            $instances = Get-IamSsoInstances -Region $Region
            if ($null -eq $instances) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-50'
            }

            $durationBuckets = @{}
            $longDurationSets = @()
            $permissionSetCount = 0

            foreach ($instance in $instances) {
                $permissionSets = Get-IamPermissionSetDetails -Region $Region -InstanceArn $instance.InstanceArn
                if ($null -eq $permissionSets) { continue }

                foreach ($permissionSet in $permissionSets) {
                    $permissionSetCount++
                    $duration = 'PT1H'
                    if (Test-AuditHasProperty -Object $permissionSet -PropertyName 'SessionDuration') {
                        $duration = [string]$permissionSet.SessionDuration
                    }

                    if (-not $durationBuckets.ContainsKey($duration)) {
                        $durationBuckets[$duration] = 0
                    }
                    $durationBuckets[$duration] = $durationBuckets[$duration] + 1

                    if ((Get-IamIsoDurationHours -Duration $duration) -gt 8) {
                        if ((Get-AuditCollectionCount $longDurationSets) -lt 10) {
                            $longDurationSets += [string]$permissionSet.Name
                        }
                    }
                }
            }

            $evidence = @{
                permission_set_count = $permissionSetCount
                duration_buckets     = $durationBuckets
                long_duration_names  = @($longDurationSets)
            }

            if ((Get-AuditCollectionCount $longDurationSets) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-50' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Permission Sets exceed PT8H session duration'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-50' `
                -Status 'PASS' -Evidence $evidence -Notes 'All Permission Sets are at most PT8H'
        }

        'IAM-51' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-51'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-51' `
                -Notes 'Verify ITSM integration with Identity Center for automated provisioning.'
        }

        'IAM-52' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-52'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-52' `
                -Notes 'Verify offboarding triggers immediate Identity Center account disable. Check LDAP sync (Aldab Sync) behavior.'
        }

        'IAM-53' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-53'
            if ($gate) { return $gate }

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-53' `
                -Notes 'Verify periodic review of Identity Center assignments exists. Check frequency and documentation.'
        }

        'IAM-54' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-54'
            if ($gate) { return $gate }

            $endTime = (Get-Date).ToUniversalTime().ToString('o')
            $startTime = (Get-Date).AddDays(-7).ToUniversalTime().ToString('o')

            $data = Invoke-AWSCLI -Arguments @(
                'cloudtrail', 'lookup-events',
                '--lookup-attributes', 'AttributeKey=EventSource,AttributeValue=sso.amazonaws.com',
                '--start-time', $startTime,
                '--end-time', $endTime,
                '--max-results', '50'
            ) -Region $Region

            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-54'
            }

            $eventCount = 0
            if (Test-AuditHasProperty -Object $data -PropertyName 'Events') {
                $eventCount = (Get-AuditCollectionCount $data.Events)
            }

            $evidence = @{ sso_event_count_last_7_days = $eventCount }

            if ($eventCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-54' `
                    -Status 'PASS' -Evidence $evidence -Notes 'SSO events visible in CloudTrail'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-54' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No SSO events in CloudTrail'
        }

        'IAM-55' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $gate = Get-IamGlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-55'
            if ($gate) { return $gate }

            $rulesData = Invoke-AWSCLI -Arguments @('events', 'list-rules') -Region $Region
            if ($null -eq $rulesData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-55'
            }

            $ssoRules = @()
            if (Test-AuditHasProperty -Object $rulesData -PropertyName 'Rules') {
                foreach ($rule in (Get-AuditCliArray $rulesData.Rules)) {
                    $ruleName = [string]$rule.Name
                    $eventPattern = [string]$rule.EventPattern
                    if ($eventPattern -match 'sso\.amazonaws\.com|CreateUser|PutInlinePolicyToPermissionSet' -or $ruleName -match 'SSO|IdentityCenter|IAM') {
                        $ssoRules += $ruleName
                    }
                }
            }

            $evidence = @{ sso_rule_names = @($ssoRules) }

            if ((Get-AuditCollectionCount $ssoRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-55' `
                    -Status 'PASS' -Evidence $evidence -Notes 'EventBridge rules exist on critical IAM or SSO events'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'IAM-55' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No SSO-specific alerting rules found'
        }
    }
}
