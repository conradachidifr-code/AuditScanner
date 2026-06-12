$DomainSeverity = @{
    'ORG-01' = 'P0'
    'ORG-02' = 'P0'
    'ORG-03' = 'P0'
    'ORG-06' = 'P0'
    'ORG-07' = 'P0'
    'ORG-08' = 'P1'
    'ORG-09' = 'P0'
    'ORG-10' = 'P2'
    'ORG-11' = 'P2'
    'ORG-13' = 'P0'
    'ORG-14' = 'P0'
    'ORG-15' = 'P1'
    'ORG-16' = 'P0'
    'ORG-17' = 'P2'
    'ORG-18' = 'P0'
    'ORG-19' = 'P0'
}

function Get-OrgScpSummaries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('organizations', 'list-policies', '--filter', 'SERVICE_CONTROL_POLICY') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'Policies') {
        return @($data.Policies)
    }

    return @()
}

function Get-OrgPolicyDocumentText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    $data = Invoke-AWSCLI -Arguments @('organizations', 'describe-policy', '--policy-id', $PolicyId) -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'Policy')) {
        return $null
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'Policy').Content) {
        return $null
    }

    return [string]$data.Policy.Content
}

function Get-OrgScpDocuments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $scps = Get-OrgScpSummaries -Region $Region
    if ($null -eq $scps) {
        return $null
    }

    $documents = @()
    $unreadableCount = 0

    foreach ($scp in $scps) {
        if (-not (Test-AuditHasProperty -Object $scp -PropertyName 'Id')) {
            continue
        }

        $content = Get-OrgPolicyDocumentText -Region $Region -PolicyId $scp.Id
        if ($null -eq $content) {
            $unreadableCount++
            $documents += [PSCustomObject]@{
                Id          = [string]$scp.Id
                Name        = [string]$scp.Name
                Content     = $null
                IsReadable  = $false
            }
            continue
        }

        $documents += [PSCustomObject]@{
            Id          = [string]$scp.Id
            Name        = [string]$scp.Name
            Content     = $content
            IsReadable  = $true
        }
    }

    return [PSCustomObject]@{
        ScpCount         = (Get-AuditCollectionCount $scps)
        Documents        = @($documents)
        UnreadableCount  = $unreadableCount
    }
}

function Test-OrgPersonalEmail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress
    )

    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return $true
    }

    $personalDomains = @(
        'gmail.com',
        'googlemail.com',
        'hotmail.com',
        'outlook.com',
        'live.com',
        'yahoo.com',
        'icloud.com',
        'proton.me',
        'protonmail.com',
        'aol.com'
    )

    $lowerEmail = $EmailAddress.ToLower()
    foreach ($domain in $personalDomains) {
        if ($lowerEmail -like ('*@{0}' -f $domain)) {
            return $true
        }
    }

    return $false
}

function Get-OrgIamRoles {
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
        if (Test-AuditHasProperty -Object $data -PropertyName 'Marker') {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.Marker)) {
                $isTruncated = $true
                if (Test-AuditHasProperty -Object $data -PropertyName 'IsTruncated') {
                    $isTruncated = ($data.IsTruncated -eq $true)
                }
                if ($isTruncated) {
                    $marker = [string]$data.Marker
                }
            }
        }
    } while ($marker)

    return $roles.ToArray()
}

function Test-OrgRoleAttachedPolicyMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$RoleName,

        [Parameter(Mandatory = $true)]
        [string[]]$PolicyPatterns
    )

    $data = Invoke-AWSCLI -Arguments @('iam', 'list-attached-role-policies', '--role-name', $RoleName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'AttachedPolicies')) {
        return $false
    }

    foreach ($policy in (Get-AuditCliArray $data.AttachedPolicies)) {
        $policyName = [string]$policy.PolicyName
        $policyArn = [string]$policy.PolicyArn

        foreach ($pattern in $PolicyPatterns) {
            if ($policyName -like ('*{0}*' -f $pattern)) {
                return $true
            }
            if ($policyArn -like ('*{0}*' -f $pattern)) {
                return $true
            }
        }
    }

    return $false
}

function Get-DomainChecks {
    return [ordered]@{
        'ORG-01' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-01'
            if ($gate) {
                return $gate
            }

            $scpData = Get-OrgScpDocuments -Region $Region
            if ($null -eq $scpData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-01'
            }

            if ($scpData.ScpCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-01' `
                    -Status 'FAIL' `
                    -Evidence @{ scp_count = 0; deny_statement_count = 0; scp_names = @() } `
                    -Notes 'No deny SCPs found'
            }

            $denyStatementCount = 0
            $matchingPolicyNames = @()

            foreach ($document in (Get-AuditCliArray $scpData.Documents)) {
                if (-not (Test-AuditHasProperty -Object $document -PropertyName 'IsReadable')) {
                    continue
                }

                $content = [string]$document.Content
                $hasDeny = ($content -match '"Effect"\s*:\s*"Deny"')
                $coversGuardDuty = ($content -match 'guardduty:')
                $coversCloudTrail = ($content -match 'cloudtrail:')
                $coversConfig = ($content -match 'config:')

                if ($hasDeny -and ($coversGuardDuty -or $coversCloudTrail -or $coversConfig)) {
                    $denyStatementCount++
                    if (Test-AuditHasProperty -Object $document -PropertyName 'Name') {
                        $matchingPolicyNames += [string]$document.Name
                    }
                }
            }

            $evidence = @{
                scp_count            = $scpData.ScpCount
                deny_statement_count = $denyStatementCount
                scp_names            = @($matchingPolicyNames)
                unreadable_count     = $scpData.UnreadableCount
            }

            if ($denyStatementCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-01' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'SCPs exist with Deny statements on GuardDuty, CloudTrail, or Config'
            }

            if ($scpData.UnreadableCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-01' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'SCPs exist but content not readable'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-01' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No deny SCPs found'
        }

        'ORG-02' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-02'
            if ($gate) {
                return $gate
            }

            $scpData = Get-OrgScpDocuments -Region $Region
            if ($null -eq $scpData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-02'
            }

            $denyActionsFound = @()

            foreach ($document in (Get-AuditCliArray $scpData.Documents)) {
                if (-not (Test-AuditHasProperty -Object $document -PropertyName 'IsReadable')) {
                    continue
                }

                $content = [string]$document.Content
                if ($content -match 'guardduty:DeleteDetector') {
                    $denyActionsFound += 'guardduty:DeleteDetector'
                }
                if ($content -match 'cloudtrail:DeleteTrail') {
                    $denyActionsFound += 'cloudtrail:DeleteTrail'
                }
                if ($content -match 'config:DeleteConfigRule') {
                    $denyActionsFound += 'config:DeleteConfigRule'
                }
            }

            $uniqueActions = @()
            foreach ($action in $denyActionsFound) {
                if ($uniqueActions -notcontains $action) {
                    $uniqueActions += $action
                }
            }

            $evidence = @{
                deny_actions_found = @($uniqueActions)
                scp_count          = $scpData.ScpCount
            }

            $hasGuardDutyOrCloudTrailDeny = $false
            if ($uniqueActions -contains 'guardduty:DeleteDetector') {
                $hasGuardDutyOrCloudTrailDeny = $true
            }
            if ($uniqueActions -contains 'cloudtrail:DeleteTrail') {
                $hasGuardDutyOrCloudTrailDeny = $true
            }

            if ($hasGuardDutyOrCloudTrailDeny) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-02' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'At least one SCP denies deletion of GuardDuty or CloudTrail'
            }

            if ($scpData.UnreadableCount -gt 0 -and $scpData.ScpCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-02' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'SCPs exist but content not readable'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-02' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No such denial found'
        }

        'ORG-03' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-03'
            if ($gate) {
                return $gate
            }

            $scpData = Get-OrgScpDocuments -Region $Region
            if ($null -eq $scpData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-03'
            }

            $matchedPolicyNames = @()
            $regionValues = @()

            foreach ($document in (Get-AuditCliArray $scpData.Documents)) {
                if (-not (Test-AuditHasProperty -Object $document -PropertyName 'IsReadable')) {
                    continue
                }

                $content = [string]$document.Content
                if ($content -notmatch 'aws:RequestedRegion') {
                    continue
                }

                if (Test-AuditHasProperty -Object $document -PropertyName 'Name') {
                    $matchedPolicyNames += [string]$document.Name
                }

                $matches = [regex]::Matches($content, '"(eu-[a-z0-9-]+|us-[a-z0-9-]+|ap-[a-z0-9-]+|ca-[a-z0-9-]+|sa-[a-z0-9-]+|af-[a-z0-9-]+|me-[a-z0-9-]+)"')
                foreach ($match in $matches) {
                    $regionValue = $match.Groups[1].Value
                    if ($regionValues -notcontains $regionValue) {
                        $regionValues += $regionValue
                    }
                }
            }

            $evidence = @{
                scp_count          = $scpData.ScpCount
                policy_names       = @($matchedPolicyNames)
                regions_referenced = @($regionValues)
            }

            if ((Get-AuditCollectionCount $matchedPolicyNames) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-03' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'Region restriction SCP exists'
            }

            if ($scpData.UnreadableCount -gt 0 -and $scpData.ScpCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-03' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'SCPs exist but content not readable'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-03' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No region restriction'
        }

        'ORG-06' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-06' `
                -Status 'PARTIAL' `
                -Evidence $null `
                -Notes 'Verify account vending machine exists. Check Service Catalog products.'
        }

        'ORG-07' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-07'
            if ($gate) {
                return $gate
            }

            $guardDutyData = Invoke-AWSCLI -Arguments @('guardduty', 'list-organization-admin-accounts') -Region $Region
            $delegatedData = Invoke-AWSCLI -Arguments @('organizations', 'list-delegated-administrators') -Region $Region

            if ($null -eq $guardDutyData -and $null -eq $delegatedData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-07'
            }

            $guardDutyAdminAccounts = @()
            if ($guardDutyData -and $guardDutyData.AdminAccounts) {
                foreach ($adminAccount in (Get-AuditCliArray $guardDutyData.AdminAccounts)) {
                    $guardDutyAdminAccounts += @{
                        account_id   = [string]$adminAccount.AccountId
                        admin_status = [string]$adminAccount.AdminStatus
                    }
                }
            }

            $delegatedAdmins = @()
            if ($delegatedData -and $delegatedData.DelegatedAdministrators) {
                foreach ($delegatedAdmin in (Get-AuditCliArray $delegatedData.DelegatedAdministrators)) {
                    $delegatedAdmins += @{
                        account_id         = [string]$delegatedAdmin.Id
                        service_principals = @($delegatedAdmin.ServicePrincipal)
                    }
                }
            }

            $guardDutyDelegated = ((Get-AuditCollectionCount $guardDutyAdminAccounts) -gt 0)
            if (-not $guardDutyDelegated -and (Get-AuditCollectionCount $delegatedAdmins) -gt 0) {
                foreach ($delegatedAdmin in $delegatedAdmins) {
                    foreach ($principal in (Get-AuditCliArray $delegatedAdmin.service_principals)) {
                        if ($principal -like '*guardduty*') {
                            $guardDutyDelegated = $true
                            break
                        }
                    }
                }
            }

            $evidence = @{
                guardduty_admin_accounts = @($guardDutyAdminAccounts)
                delegated_administrators = @($delegatedAdmins)
            }

            if ($guardDutyDelegated) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-07' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'GuardDuty delegated admin configured'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-07' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No delegated admin for GuardDuty'
        }

        'ORG-08' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-08' `
                -Notes 'Verify log-archive account exists in isolated OU. Check access restrictions.'
        }

        'ORG-09' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $identityData = Invoke-AWSCLI -Arguments @('sts', 'get-caller-identity') -Region $Region
            if ($null -eq $identityData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-09'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-09' `
                -Status 'PARTIAL' `
                -Evidence @{
                    account  = [string]$identityData.Account
                    arn      = [string]$identityData.Arn
                    user_id  = [string]$identityData.UserId
                } `
                -Notes 'Verify Security account hosts: GuardDuty admin, CloudTrail bucket, Config aggregator.'
        }

        'ORG-10' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $data = Invoke-AWSCLI -Arguments @('budgets', 'describe-budgets', '--account-id', $AccountId) -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-10'
            }

            $budgets = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'Budgets') {
                $budgets = @($data.Budgets)
            }

            $budgetsWithAlerts = @()
            foreach ($budget in $budgets) {
                $alertThresholds = @()
                if (Test-AuditHasProperty -Object $budget -PropertyName 'NotificationsWithSubscribers') {
                    foreach ($notification in (Get-AuditCliArray $budget.NotificationsWithSubscribers)) {
                        if (Test-AuditHasProperty -Object $notification -PropertyName 'Notification') {
                            if ($notification.Notification.Threshold) {
                                $alertThresholds += [string]$notification.Notification.Threshold
                            }
                        }
                    }
                }

                if ((Get-AuditCollectionCount $alertThresholds) -gt 0) {
                    $budgetName = [string]$budget.BudgetName
                    $budgetsWithAlerts += @{
                        budget_name       = $budgetName
                        alert_thresholds  = @($alertThresholds)
                    }
                }
            }

            $evidence = @{
                budget_count             = (Get-AuditCollectionCount $budgets)
                budgets_with_alerts      = @($budgetsWithAlerts)
                budgets_with_alert_count = (Get-AuditCollectionCount $budgetsWithAlerts)
            }

            if ((Get-AuditCollectionCount $budgetsWithAlerts) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-10' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'At least one budget with alert configured'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-10' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No budgets or no alerts'
        }

        'ORG-11' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-11' `
                -Status 'PARTIAL' `
                -Evidence $null `
                -Notes 'Verify quota monitoring exists for GuardDuty, Lambda, CloudTrail.'
        }

        'ORG-13' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-13' `
                -Notes 'Verify IAM, Route53, CloudFront governance defined at org level. Check SCP coverage for us-east-1.'
        }

        'ORG-14' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-14'
            if ($gate) {
                return $gate
            }

            $roles = Get-OrgIamRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-14'
            }

            $matchingRoles = @()
            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                if ($roleName -notmatch 'Audit|ReadOnly|SecurityAudit') {
                    continue
                }

                $hasAuditPolicy = Test-OrgRoleAttachedPolicyMatch -Region $Region -RoleName $roleName -PolicyPatterns @('ReadOnly', 'SecurityAudit')
                if (-not $hasAuditPolicy) {
                    continue
                }

                $matchingRoles += @{
                    role_name = $roleName
                    role_arn  = [string]$role.Arn
                }
            }

            $evidence = @{
                matching_role_count = (Get-AuditCollectionCount $matchingRoles)
                roles               = @($matchingRoles)
            }

            if ((Get-AuditCollectionCount $matchingRoles) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-14' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'Audit role found with ReadOnly or SecurityAudit managed policy'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-14' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No audit-specific role found'
        }

        'ORG-15' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-15'
            if ($gate) {
                return $gate
            }

            $roles = Get-OrgIamRoles -Region $Region
            if ($null -eq $roles) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-15'
            }

            $breakGlassRoles = @()
            foreach ($role in $roles) {
                $roleName = [string]$role.RoleName
                if ($roleName -match 'BreakGlass|Emergency') {
                    $breakGlassRoles += @{
                        role_name = $roleName
                        role_arn  = [string]$role.Arn
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-15' `
                -Status 'PARTIAL' `
                -Evidence @{
                    break_glass_role_count = (Get-AuditCollectionCount $breakGlassRoles)
                    roles                  = @($breakGlassRoles)
                } `
                -Notes 'Verify break-glass procedure exists with activation log, RSSI notification.'
        }

        'ORG-16' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-16'
            if ($gate) {
                return $gate
            }

            $scpData = Get-OrgScpDocuments -Region $Region
            if ($null -eq $scpData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-16'
            }

            $policyNames = @()
            foreach ($document in (Get-AuditCliArray $scpData.Documents)) {
                if (Test-AuditHasProperty -Object $document -PropertyName 'Name') {
                    $policyNames += [string]$document.Name
                }
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-16' `
                -Status 'PARTIAL' `
                -Evidence @{
                    scp_count   = $scpData.ScpCount
                    scp_names   = @($policyNames)
                    unreadable  = $scpData.UnreadableCount
                } `
                -Notes 'Verify service catalog / allowed services list exists.'
        }

        'ORG-17' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-17' `
                -Notes 'Verify IaC modules are versioned via GitLab tags/releases.'
        }

        'ORG-18' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $securityContactData = Invoke-AWSCLI -Arguments @('account', 'get-alternate-contact', '--alternate-contact-type', 'SECURITY') -Region $Region
            $billingContactData = Invoke-AWSCLI -Arguments @('account', 'get-alternate-contact', '--alternate-contact-type', 'BILLING') -Region $Region

            if ($null -eq $securityContactData -and $null -eq $billingContactData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'ORG-18'
            }

            $securityEmail = $null
            $securityName = $null
            if ($securityContactData -and $securityContactData.AlternateContact) {
                $securityEmail = [string]$securityContactData.AlternateContact.EmailAddress
                $securityName = [string]$securityContactData.AlternateContact.Name
            }

            $billingEmail = $null
            if ($billingContactData -and $billingContactData.AlternateContact) {
                $billingEmail = [string]$billingContactData.AlternateContact.EmailAddress
            }

            $evidence = @{
                security_contact = @{
                    configured = (-not [string]::IsNullOrWhiteSpace($securityEmail))
                    email      = $securityEmail
                    name       = $securityName
                }
                billing_contact = @{
                    configured = (-not [string]::IsNullOrWhiteSpace($billingEmail))
                    email      = $billingEmail
                }
            }

            if ([string]::IsNullOrWhiteSpace($securityEmail)) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-18' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'No SECURITY contact configured'
            }

            if (Test-OrgPersonalEmail -EmailAddress $securityEmail) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'ORG-18' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'SECURITY contact uses a personal email address'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-18' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'SECURITY alternate contact configured with non-personal email'
        }

        'ORG-19' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'ORG-19' `
                -Notes 'Verify SCP documentation exists with owner per SCP and exception process.'
        }
    }
}
