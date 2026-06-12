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

function Get-IncScpPolicyDocuments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $listData = Invoke-AWSCLI -Arguments @('organizations', 'list-policies', '--filter', 'SERVICE_CONTROL_POLICY') -Region $Region
    if ($null -eq $listData) {
        return $null
    }

    $documents = @()
    if (-not (Test-AuditHasProperty -Object $listData -PropertyName 'Policies')) {
        return @()
    }

    foreach ($policy in (Get-AuditCliArray $listData.Policies)) {
        if (-not (Test-AuditHasProperty -Object $policy -PropertyName 'Id')) {
            continue
        }

        $describeData = Invoke-AWSCLI -Arguments @('organizations', 'describe-policy', '--policy-id', $policy.Id) -Region $Region
        if ($null -eq $describeData -or -not (Test-AuditHasProperty -Object $describeData -PropertyName 'Policy')) {
            continue
        }

        $content = $null
        if ($describeData.Policy.Content) {
            $content = [uri]::UnescapeDataString([string]$describeData.Policy.Content)
        }

        $documents += [PSCustomObject]@{
            Id      = [string]$policy.Id
            Name    = [string]$policy.Name
            Content = $content
        }
    }

    return $documents
}

function Test-IncQuarantineScp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $true)]
        [string]$PolicyContent
    )

    $nameMatch = (Test-IncQuarantineOuName -Name $PolicyName)
    $contentMatch = $false

    if ($PolicyContent -match 'quarantine|deny-all|DenyAll|"Effect"\s*:\s*"Deny"') {
        if ($PolicyContent -match '"Action"\s*:\s*"\*"') {
            $contentMatch = $true
        }
    }

    return ($nameMatch -or $contentMatch)
}

function Get-DomainChecks {
    return [ordered]@{
        'INC-01' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-01' `
                -Notes 'Verify cloud incident management policy exists and is current.'
        }

        'INC-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-02' `
                -Notes 'Verify RACI for cloud incidents: CCoE vs SOC vs métiers vs RSSI.'
        }

        'INC-03' = {
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
                guardduty_rules  = @($guardDutyRules)
                cloudtrail_rules = @($cloudTrailRules)
                config_rules     = @($configRules)
            }

            if ((Get-AuditCollectionCount $guardDutyRules) -gt 0 -and (Get-AuditCollectionCount $cloudTrailRules) -gt 0 -and (Get-AuditCollectionCount $configRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03' `
                    -Status 'PASS' -Evidence $evidence -Notes 'EventBridge rules cover GuardDuty, CloudTrail, and Config events'
            }

            if ((Get-AuditCollectionCount $guardDutyRules) -gt 0 -or (Get-AuditCollectionCount $cloudTrailRules) -gt 0 -or (Get-AuditCollectionCount $configRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Some incident detection rules exist but not all required sources are covered'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-03' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No incident detection EventBridge rules found'
        }

        'INC-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-04' `
                -Notes 'Verify incident severity matrix exists for cloud incidents.'
        }

        'INC-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-05' `
                -Notes 'Verify playbooks exist for: compromised account, data breach, DDoS, ransomware.'
        }

        'INC-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

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
                ou_count        = (Get-AuditCollectionCount $allOuNames)
                ou_names        = @($allOuNames)
                quarantine_ous  = @($quarantineOus)
            }

            if ((Get-AuditCollectionCount $quarantineOus) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Bouton rouge procedure confirmed with REX August 2023.'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-06' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No quarantine OU found'
        }

        'INC-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $sgData = Invoke-AWSCLI -Arguments @('ec2', 'describe-security-groups') -Region $Region
            $isolationGroups = @()

            if ($sgData -and $sgData.SecurityGroups) {
                foreach ($sg in (Get-AuditCliArray $sgData.SecurityGroups)) {
                    $groupName = [string]$sg.GroupName
                    $description = [string]$sg.Description
                    $combined = ($groupName + ' ' + $description).ToLower()
                    if ($combined -match 'quarantine|isolate|isolation|containment|deny-all|incident') {
                        $isolationGroups += @{
                            group_id   = [string]$sg.GroupId
                            group_name = $groupName
                        }
                    }
                }
            }

            $quarantineScps = @()
            $scpDocuments = Get-IncScpPolicyDocuments -Region $Region
            if ($null -ne $scpDocuments) {
                foreach ($document in $scpDocuments) {
                    if (Test-IncQuarantineScp -PolicyName $document.Name -PolicyContent ([string]$document.Content)) {
                        $quarantineScps += @{
                            policy_id   = $document.Id
                            policy_name = $document.Name
                        }
                    }
                }
            }

            $evidence = @{
                isolation_security_groups = @($isolationGroups)
                quarantine_scps           = @($quarantineScps)
            }

            if ((Get-AuditCollectionCount $isolationGroups) -gt 0 -or (Get-AuditCollectionCount $quarantineScps) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-07' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Isolation security group or quarantine SCP detected'
            }

            if ($null -eq $sgData -and $null -eq $scpDocuments) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-07'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-07' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No isolation security group or quarantine SCP found'
        }

        'INC-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-08' `
                -Status 'PARTIAL' -Evidence $null `
                -Notes 'Verify rapid revocation: Identity Center access revokable within minutes.'
        }

        'INC-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('s3api', 'list-buckets') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-09'
            }

            $forensicsBuckets = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'Buckets') {
                foreach ($bucket in (Get-AuditCliArray $data.Buckets)) {
                    $bucketName = [string]$bucket.Name
                    $lowerName = $bucketName.ToLower()
                    if ($lowerName -match 'forensic|forensics|evidence|chain-of-custody|incident') {
                        $forensicsBuckets += $bucketName
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-09' `
                -Status 'NOT_TESTED' `
                -Evidence @{
                    forensics_bucket_count = (Get-AuditCollectionCount $forensicsBuckets)
                    forensics_buckets      = @($forensicsBuckets)
                } `
                -Notes 'Verify forensics procedure: evidence preservation, chain of custody.'
        }

        'INC-10' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-10' `
                -Notes 'Verify on-call rotation exists with escalation path.'
        }

        'INC-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-11' `
                -Notes 'Verify crisis communication plan for internal and external stakeholders.'
        }

        'INC-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-12' `
                -Notes 'Known: AWS Support managed by separate EDF group. Verify escalation process.'
        }

        'INC-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-13' `
                -Notes 'Verify tabletop or live exercises have been performed.'
        }

        'INC-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-14' `
                -Notes 'Verify RETEX exists for August 2023 SSH incident. Check FEX documentation.'
        }

        'INC-15' = {
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
                    if ($eventText -match 'BreakGlass|Emergency|Incident|Quarantine') {
                        $breakGlassCount++
                    }
                }
            }

            $evidence = @{
                assume_role_event_count  = $assumeRoleCount
                break_glass_event_count  = $breakGlassCount
            }

            if ($breakGlassCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Break-glass role activity logged in CloudTrail'
            }

            if ($assumeRoleCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Cannot distinguish incident response from normal ops'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'INC-15' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No AssumeRole events found in CloudTrail sample'
        }
    }
}
