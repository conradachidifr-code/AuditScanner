$DomainSeverity = @{
    'INC-01' = 'P0'
    'INC-02' = 'P0'
    'INC-03' = 'P0'
    'INC-04' = 'P0'
    'INC-05' = 'P1'
    'INC-06' = 'P0'
    'INC-07' = 'P0'
    'INC-08' = 'P0'
    'INC-09' = 'P1'
    'INC-10' = 'P0'
    'INC-11' = 'P0'
    'INC-12' = 'P0'
    'INC-13' = 'P0'
    'INC-14' = 'P0'
    'INC-15' = 'P0'
}

function Get-IncOrganizationRoots {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('organizations', 'list-roots') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'Roots') {
        return @($data.Roots)
    }

    return @()
}

function Get-IncOrganizationalUnits {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ParentId
    )

    $units = New-AuditList
    $token = $null

    do {
        $arguments = @('organizations', 'list-organizational-units-for-parent', '--parent-id', $ParentId)
        if ($token) {
            $arguments += @('--next-token', $token)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if (Test-AuditHasProperty -Object $data -PropertyName 'OrganizationalUnits') {
            foreach ($unit in (Get-AuditCliArray $data.OrganizationalUnits)) {
                [void]$units.Add($unit)
            }
        }

        $token = $null
        if ((Test-AuditHasProperty -Object $data -PropertyName 'NextToken')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.NextToken)) {
                $token = [string]$data.NextToken
            }
        }
    } while ($token)

    return $units.ToArray()
}

function Test-IncQuarantineOuName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $lowerName = $Name.ToLower()
    if ($lowerName -match 'quarantine|isolate|isolation|containment|sandbox-incident|incident') {
        return $true
    }

    return $false
}

function Test-IncCloudTrailActive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $trailData = Invoke-AWSCLI -Arguments @('cloudtrail', 'describe-trails', '--include-shadow-trails') -Region $Region
    if ($null -eq $trailData) {
        return $false
    }

    if (-not (Test-AuditHasProperty -Object $trailData -PropertyName 'trailList')) {
        return $false
    }

    foreach ($trail in (Get-AuditCliArray $trailData.trailList)) {
        if (-not (Test-AuditHasProperty -Object $trail -PropertyName 'Name')) {
            continue
        }

        $statusData = Invoke-AWSCLI -Arguments @('cloudtrail', 'get-trail-status', '--name', $trail.Name) -Region $Region
        if ($null -eq $statusData) {
            continue
        }

        if ((Test-AuditHasProperty -Object $statusData -PropertyName 'IsLogging') -and ($statusData.IsLogging -eq $true)) {
            return $true
        }
    }

    return $false
}

function Get-DomainChecks {
    $checks = [ordered]@{}

    $checks['INC-01'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-01' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify cloud incident management policy exists and is current.'
    }

    $checks['INC-02'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-02' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify RACI for cloud incidents: CCoE vs SOC vs metiers vs RSSI.'
    }

    $checks['INC-03'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $data = Invoke-AWSCLI -Arguments @('events', 'list-rules') -Region $Region
        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03'
        }

        $guardDutyRules = @()
        $cloudTrailRules = @()
        $configRules = @()

        if (Test-AuditHasProperty -Object $data -PropertyName 'Rules') {
            foreach ($rule in (Get-AuditCliArray $data.Rules)) {
                $ruleName = [string]$rule.Name
                $eventPattern = [string](Get-AuditPropertyValue $rule -PropertyNames @('EventPattern'))
                $scheduleExpression = [string](Get-AuditPropertyValue $rule -PropertyNames @('ScheduleExpression'))
                $combined = ($ruleName + ' ' + $eventPattern + ' ' + $scheduleExpression)

                if ($combined -match 'guardduty|aws\.guardduty') {
                    $guardDutyRules += $ruleName
                }
                if ($combined -match 'cloudtrail|aws\.cloudtrail') {
                    $cloudTrailRules += $ruleName
                }
                if ($combined -match 'config|aws\.config|ComplianceChangeNotification') {
                    $configRules += $ruleName
                }
            }
        }

        $evidence = @{
            guardduty_rules     = @($guardDutyRules)
            cloudtrail_rules    = @($cloudTrailRules)
            config_rules        = @($configRules)
            incident_rule_count = (Get-AuditCollectionCount $guardDutyRules) + (Get-AuditCollectionCount $cloudTrailRules) + (Get-AuditCollectionCount $configRules)
        }

        if ((Get-AuditCollectionCount $guardDutyRules) -gt 0 -or (Get-AuditCollectionCount $cloudTrailRules) -gt 0 -or (Get-AuditCollectionCount $configRules) -gt 0) {
            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03' `
                -Status 'PASS' -Evidence $evidence `
                -Notes 'EventBridge rules found for GuardDuty, CloudTrail, or Config incident events'
        }

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03' `
            -Status 'FAIL' -Evidence $evidence -Notes 'No incident detection EventBridge rules found'
    }

    $checks['INC-04'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-04' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify incident severity matrix exists for cloud incidents.'
    }

    $checks['INC-05'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-05' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify playbooks exist for: compromised account, data breach, DDoS, ransomware. Check DEX or SOC space.'
    }

    $checks['INC-06'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06'
        if ($gate) {
            return $gate
        }

        $roots = Get-IncOrganizationRoots -Region $Region
        if ($null -eq $roots) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06'
        }

        if ((Get-AuditCollectionCount $roots) -eq 0) {
            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06' `
                -Status 'FAIL' -Evidence @{ root_count = 0 } -Notes 'No organization roots found'
        }

        $allOuNames = @()
        $quarantineOus = @()

        foreach ($root in $roots) {
            if (-not (Test-AuditHasProperty -Object $root -PropertyName 'Id')) {
                continue
            }

            $units = Get-IncOrganizationalUnits -Region $Region -ParentId $root.Id
            if ($null -eq $units) {
                continue
            }

            foreach ($unit in $units) {
                $ouName = [string]$unit.Name
                $allOuNames += $ouName
                if (Test-IncQuarantineOuName -Name $ouName) {
                    $quarantineOus += @{
                        id   = [string]$unit.Id
                        name = $ouName
                    }
                }
            }
        }

        $evidence = @{
            ou_count       = (Get-AuditCollectionCount $allOuNames)
            ou_names       = @($allOuNames)
            quarantine_ous = @($quarantineOus)
        }

        if ((Get-AuditCollectionCount $quarantineOus) -gt 0) {
            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06' `
                -Status 'PASS' -Evidence $evidence -Notes 'Quarantine OU found in organization structure'
        }

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06' `
            -Status 'FAIL' -Evidence $evidence -Notes 'No quarantine OU found'
    }

    $checks['INC-07'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-07' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify isolation security group or quarantine SCP exists for compromised resources.'
    }

    $checks['INC-08'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-08' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify rapid revocation: Identity Center access revokable within minutes.'
    }

    $checks['INC-09'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-09' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify forensics procedure: evidence preservation, chain of custody.'
    }

    $checks['INC-10'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-10' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify on-call rotation exists with escalation path.'
    }

    $checks['INC-11'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-11' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify crisis communication plan for internal and external stakeholders.'
    }

    $checks['INC-12'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-12' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Known: AWS Support managed by separate EDF group. Verify escalation process.'
    }

    $checks['INC-13'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-13' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify tabletop or live exercises have been performed.'
    }

    $checks['INC-14'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-14' `
            -Status 'NOT_TESTED' -Evidence $null `
            -Notes 'Verify RETEX exists for August 2023 SSH incident. Check FEX documentation.'
    }

    $checks['INC-15'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $endTime = (Get-Date).ToUniversalTime().ToString('o')
        $startTime = (Get-Date).AddDays(-30).ToUniversalTime().ToString('o')

        $data = Invoke-AWSCLI -Arguments @(
            'cloudtrail', 'lookup-events',
            '--lookup-attributes', 'AttributeKey=EventName,AttributeValue=AssumeRole',
            '--start-time', $startTime,
            '--end-time', $endTime,
            '--max-results', '50'
        ) -Region $Region

        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15'
        }

        $assumeRoleCount = 0
        $breakGlassCount = 0

        if (Test-AuditHasProperty -Object $data -PropertyName 'Events') {
            $assumeRoleCount = (Get-AuditCollectionCount $data.Events)
            foreach ($event in (Get-AuditCliArray $data.Events)) {
                $eventText = [string]$event.CloudTrailEvent
                if ($eventText -match 'BreakGlass|Emergency|CCOScriptAdmin') {
                    $breakGlassCount++
                }
            }
        }

        $cloudTrailActive = Test-IncCloudTrailActive -Region $Region
        $evidence = @{
            assume_role_event_count = $assumeRoleCount
            break_glass_event_count = $breakGlassCount
            cloudtrail_active       = $cloudTrailActive
        }

        if ($breakGlassCount -gt 0) {
            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
                -Status 'PASS' -Evidence $evidence -Notes 'Break-glass AssumeRole activity logged in CloudTrail'
        }

        if ($cloudTrailActive) {
            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
                -Status 'PARTIAL' -Evidence $evidence `
                -Notes 'CloudTrail active but no break-glass AssumeRole events found in sample'
        }

        return New-AuditResult `
            -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
            -Status 'FAIL' -Evidence $evidence -Notes 'No active CloudTrail logging detected'
    }

    return $checks
}
