$DomainSeverity = @{
    'GOV-02' = 'P0'
    'GOV-03' = 'P0'
    'GOV-04' = 'P0'
    'GOV-05' = 'P0'
    'GOV-06' = 'P0'
    'GOV-07' = 'P1'
    'GOV-08' = 'P2'
    'GOV-09' = 'P0'
    'GOV-11' = 'P0'
    'GOV-12' = 'P0'
    'GOV-13' = 'P1'
    'GOV-15' = 'P0'
    'GOV-16' = 'P1'
    'GOV-17' = 'P0'
    'GOV-18' = 'P0'
    'GOV-20' = 'P0'
}

function Get-GovScpSummaries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('organizations', 'list-policies', '--filter', 'SERVICE_CONTROL_POLICY') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if ($data.Policies) {
        return @($data.Policies)
    }

    return @()
}

function Get-GovPolicyDocumentText {
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

    if (-not $data.Policy) {
        return $null
    }

    if (-not $data.Policy.Content) {
        return $null
    }

    return [string]$data.Policy.Content
}

function Get-GovTaggedResourceStats {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $resources = @()
    $paginationToken = $null

    do {
        $arguments = @('resourcegroupstaggingapi', 'get-resources')
        if ($paginationToken) {
            $arguments += @('--pagination-token', $paginationToken)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if ($data.ResourceTagMappingList) {
            $resources += @($data.ResourceTagMappingList)
        }

        $paginationToken = $null
        if ($data.PSObject.Properties.Name -contains 'PaginationToken') {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.PaginationToken)) {
                $paginationToken = [string]$data.PaginationToken
            }
        }
    } while ($paginationToken)

    $totalCount = $resources.Count
    $ownerTaggedCount = 0

    foreach ($resource in $resources) {
        $hasOwnerTag = $false
        if ($resource.Tags) {
            foreach ($tag in $resource.Tags) {
                if ($tag.Key -eq 'Owner' -or $tag.Key -eq 'owner') {
                    if (-not [string]::IsNullOrWhiteSpace([string]$tag.Value)) {
                        $hasOwnerTag = $true
                        break
                    }
                }
            }
        }

        if ($hasOwnerTag) {
            $ownerTaggedCount++
        }
    }

    $percentWithOwner = 0
    if ($totalCount -gt 0) {
        $percentWithOwner = [math]::Round((($ownerTaggedCount / $totalCount) * 100), 2)
    }

    return @{
        total_resources       = $totalCount
        resources_with_owner  = $ownerTaggedCount
        percent_with_owner    = $percentWithOwner
    }
}

function Get-DomainChecks {
    return [ordered]@{
        'GOV-02' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-02' `
                -Notes 'Verify RACI matrix exists covering AWS/CCoE/Clients per domain. Check DEX/DAT documentation.'
        }

        'GOV-03' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-03' `
                -Notes 'Verify RACI Build/Run/Sec document exists and is current. Check Confluence.'
        }

        'GOV-04' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-04' `
                -Notes 'Verify RSIS policies exist covering IAM, network, logging, data, backups, CI/CD. Check Confluence.'
        }

        'GOV-05' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-05'
            if ($gate) {
                return $gate
            }

            $scps = Get-GovScpSummaries -Region $Region
            if ($null -eq $scps) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-05'
            }

            $policyNames = @()
            foreach ($policy in $scps) {
                if ($policy.Name) {
                    $policyNames += [string]$policy.Name
                }
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-05' `
                -Status 'PARTIAL' `
                -Evidence @{
                    scp_count    = $scps.Count
                    policy_names = @($policyNames)
                } `
                -Notes 'Verify derogation process and JIRA FED registry during workshop.'
        }

        'GOV-06' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $data = Invoke-AWSCLI -Arguments @(
                'cloudtrail', 'lookup-events',
                '--lookup-attributes', 'AttributeKey=EventName,AttributeValue=UpdateTrail',
                '--max-results', '50'
            ) -Region $Region

            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-06'
            }

            $eventCount = 0
            if ($data.Events) {
                $eventCount = @($data.Events).Count
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-06' `
                -Status 'PARTIAL' `
                -Evidence @{ update_trail_event_count = $eventCount } `
                -Notes 'RFC/CAB process must be verified during workshop.'
        }

        'GOV-07' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $stats = Get-GovTaggedResourceStats -Region $Region
            if ($null -eq $stats) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-07'
            }

            $evidence = @{
                total_resources      = $stats.total_resources
                resources_with_owner = $stats.resources_with_owner
                percent_with_owner   = $stats.percent_with_owner
            }

            if ($stats.total_resources -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-07' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'No taggable resources returned for inventory assessment'
            }

            if ($stats.percent_with_owner -gt 80) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-07' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'More than 80% of resources have an Owner tag'
            }

            if ($stats.percent_with_owner -lt 50) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-07' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'Less than 50% of resources have an Owner tag'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-07' `
                -Status 'PARTIAL' `
                -Evidence $evidence `
                -Notes 'Between 50% and 80% of resources have an Owner tag'
        }

        'GOV-08' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-08'
            if ($gate) {
                return $gate
            }

            $tagPolicyData = Invoke-AWSCLI -Arguments @('organizations', 'list-policies', '--filter', 'TAG_POLICY') -Region $Region
            if ($null -eq $tagPolicyData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-08'
            }

            $tagPolicies = @()
            if ($tagPolicyData.Policies) {
                $tagPolicies = @($tagPolicyData.Policies)
            }

            $tagPolicyNames = @()
            foreach ($policy in $tagPolicies) {
                $policyDetail = Invoke-AWSCLI -Arguments @('organizations', 'describe-policy', '--policy-id', $policy.Id) -Region $Region
                if ($policyDetail -and $policyDetail.Policy -and $policyDetail.Policy.Name) {
                    $tagPolicyNames += [string]$policyDetail.Policy.Name
                }
                elseif ($policy.Name) {
                    $tagPolicyNames += [string]$policy.Name
                }
            }

            if ($tagPolicyNames.Count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-08' `
                    -Status 'PASS' `
                    -Evidence @{
                        tag_policy_count = $tagPolicyNames.Count
                        policy_names     = @($tagPolicyNames)
                    } `
                    -Notes 'Tag policy exists at organization level'
            }

            $scps = Get-GovScpSummaries -Region $Region
            if ($null -eq $scps) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-08'
            }

            $tagRelatedScpCount = 0
            foreach ($scp in $scps) {
                if (-not $scp.Id) {
                    continue
                }

                $content = Get-GovPolicyDocumentText -Region $Region -PolicyId $scp.Id
                if ($null -eq $content) {
                    continue
                }

                if ($content -match 'aws:TagKeys|aws:RequestTag|aws:ResourceTag|tag') {
                    $tagRelatedScpCount++
                }
            }

            if ($tagRelatedScpCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-08' `
                    -Status 'PARTIAL' `
                    -Evidence @{
                        tag_policy_count      = 0
                        tag_related_scp_count = $tagRelatedScpCount
                        scp_count             = $scps.Count
                    } `
                    -Notes 'Tags exist via SCP but no formal tag policy'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-08' `
                -Status 'FAIL' `
                -Evidence @{
                    tag_policy_count      = 0
                    tag_related_scp_count = 0
                    scp_count             = $scps.Count
                } `
                -Notes 'No tag governance found'
        }

        'GOV-09' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-09' `
                -Notes 'Verify risk analysis document exists for AWS socle. Ask for last review date.'
        }

        'GOV-11' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-11'
            if ($gate) {
                return $gate
            }

            $scps = Get-GovScpSummaries -Region $Region
            if ($null -eq $scps) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-11'
            }

            if ($scps.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-11' `
                    -Status 'FAIL' `
                    -Evidence @{ scp_count = 0; targets = @() } `
                    -Notes 'No SCPs found'
            }

            $targetsEvidence = @()
            $hasRootOrOuTarget = $false

            foreach ($scp in $scps) {
                if (-not $scp.Id) {
                    continue
                }

                $targetData = Invoke-AWSCLI -Arguments @('organizations', 'list-targets-for-policy', '--policy-id', $scp.Id) -Region $Region
                if ($null -eq $targetData) {
                    continue
                }

                if (-not $targetData.Targets) {
                    continue
                }

                foreach ($target in $targetData.Targets) {
                    $targetType = $null
                    if ($target.PSObject.Properties.Name -contains 'Type') {
                        $targetType = [string]$target.Type
                    }

                    $targetRecord = @{
                        policy_id   = [string]$scp.Id
                        policy_name = [string]$scp.Name
                        target_id   = [string]$target.TargetId
                        target_type = $targetType
                        target_name = [string]$target.Name
                    }
                    $targetsEvidence += $targetRecord

                    if ($targetType -eq 'ROOT' -or $targetType -eq 'ORGANIZATIONAL_UNIT') {
                        $hasRootOrOuTarget = $true
                    }
                }
            }

            if ($hasRootOrOuTarget) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-11' `
                    -Status 'PASS' `
                    -Evidence @{
                        scp_count = $scps.Count
                        targets   = @($targetsEvidence)
                    } `
                    -Notes 'SCPs exist targeting OU root or management'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-11' `
                -Status 'FAIL' `
                -Evidence @{
                    scp_count = $scps.Count
                    targets   = @($targetsEvidence)
                } `
                -Notes 'No SCP targets found on OU root or organizational units'
        }

        'GOV-12' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-12'
            if ($gate) {
                return $gate
            }

            $scps = Get-GovScpSummaries -Region $Region
            if ($null -eq $scps) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-12'
            }

            if ($scps.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-12' `
                    -Status 'FAIL' `
                    -Evidence @{ scp_count = 0; region_restricted_scp_count = 0 } `
                    -Notes 'No region restriction found in any SCP'
            }

            $regionRestrictedCount = 0
            $unreadablePolicyCount = 0
            $matchedPolicyNames = @()

            foreach ($scp in $scps) {
                if (-not $scp.Id) {
                    continue
                }

                $content = Get-GovPolicyDocumentText -Region $Region -PolicyId $scp.Id
                if ($null -eq $content) {
                    $unreadablePolicyCount++
                    continue
                }

                if ($content -match 'aws:RequestedRegion') {
                    $regionRestrictedCount++
                    if ($scp.Name) {
                        $matchedPolicyNames += [string]$scp.Name
                    }
                }
            }

            if ($regionRestrictedCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-12' `
                    -Status 'PASS' `
                    -Evidence @{
                        scp_count                   = $scps.Count
                        region_restricted_scp_count = $regionRestrictedCount
                        policy_names                = @($matchedPolicyNames)
                    } `
                    -Notes 'At least one SCP contains region restriction condition'
            }

            if ($unreadablePolicyCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-12' `
                    -Status 'PARTIAL' `
                    -Evidence @{
                        scp_count                   = $scps.Count
                        region_restricted_scp_count = 0
                        unreadable_policy_count     = $unreadablePolicyCount
                    } `
                    -Notes 'Cannot read SCP content'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-12' `
                -Status 'FAIL' `
                -Evidence @{
                    scp_count                   = $scps.Count
                    region_restricted_scp_count = 0
                } `
                -Notes 'No region restriction found in any SCP'
        }

        'GOV-13' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-13' `
                -Notes 'Verify RTO/RPO defined per critical component in SIPedia/PCA. Check DIMA objectives.'
        }

        'GOV-15' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-15' `
                -Notes 'Verify security KPI dashboard exists (Wiz/Security Hub). Check review cadence.'
        }

        'GOV-16' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $deprecatedRuntimes = @('nodejs12.x', 'nodejs10.x', 'python2.7', 'ruby2.5')
            $data = Invoke-AWSCLI -Arguments @('lambda', 'list-functions', '--max-items', '1000') -Region $Region

            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-16'
            }

            $functions = @()
            if ($data.Functions) {
                $functions = @($data.Functions)
            }

            $runtimeSummary = @{}
            $deprecatedFunctions = @()

            foreach ($function in $functions) {
                $runtime = 'unknown'
                if ($function.Runtime) {
                    $runtime = [string]$function.Runtime
                }

                if (-not $runtimeSummary.ContainsKey($runtime)) {
                    $runtimeSummary[$runtime] = 0
                }
                $runtimeSummary[$runtime] = $runtimeSummary[$runtime] + 1

                if ($deprecatedRuntimes -contains $runtime) {
                    $functionName = ''
                    if ($function.FunctionName) {
                        $functionName = [string]$function.FunctionName
                    }

                    $deprecatedFunctions += @{
                        name    = $functionName
                        runtime = $runtime
                    }
                }
            }

            $evidence = @{
                function_count        = $functions.Count
                runtimes              = $runtimeSummary
                deprecated_functions  = @($deprecatedFunctions)
            }

            if ($deprecatedFunctions.Count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-16' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'Lambda functions with EOL runtimes found'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-16' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'No EOL Lambda runtimes found'
        }

        'GOV-17' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-17' `
                -Notes 'Verify technical debt backlog exists on Confluence. Check last update date and owner.'
        }

        'GOV-18' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $trailData = Invoke-AWSCLI -Arguments @('cloudtrail', 'describe-trails') -Region $Region
            if ($null -eq $trailData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'GOV-18'
            }

            $trailCount = 0
            $activeTrailCount = 0
            if ($trailData.trailList) {
                $trailCount = @($trailData.trailList).Count

                foreach ($trail in $trailData.trailList) {
                    if (-not $trail.Name) {
                        continue
                    }

                    $statusData = Invoke-AWSCLI -Arguments @('cloudtrail', 'get-trail-status', '--name', $trail.Name) -Region $Region
                    if ($null -eq $statusData) {
                        continue
                    }

                    if ($statusData.IsLogging) {
                        $activeTrailCount++
                    }
                }
            }

            $cloudTrailActive = ($activeTrailCount -gt 0)

            $recorderData = Invoke-AWSCLI -Arguments @('config', 'describe-configuration-recorders') -Region $Region
            $configRecorderActive = $false
            $recorderCount = 0

            if ($null -ne $recorderData) {
                if ($recorderData.ConfigurationRecorders) {
                    $recorders = @($recorderData.ConfigurationRecorders)
                    $recorderCount = $recorders.Count

                    if ($recorderCount -gt 0) {
                        $recorderNames = @()
                        foreach ($recorder in $recorders) {
                            if ($recorder.Name) {
                                $recorderNames += [string]$recorder.Name
                            }
                        }

                        if ($recorderNames.Count -gt 0) {
                            $statusArgs = @('config', 'describe-configuration-recorder-status')
                            foreach ($recorderName in $recorderNames) {
                                $statusArgs += @('--configuration-recorder-names', $recorderName)
                            }

                            $recorderStatusData = Invoke-AWSCLI -Arguments $statusArgs -Region $Region
                            if ($null -ne $recorderStatusData) {
                                if ($recorderStatusData.ConfigurationRecordersStatus) {
                                    foreach ($recorderStatus in $recorderStatusData.ConfigurationRecordersStatus) {
                                        if ($recorderStatus.recording -eq $true) {
                                            $configRecorderActive = $true
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            $evidence = @{
                trail_count          = $trailCount
                active_trail_count   = $activeTrailCount
                cloudtrail_active    = $cloudTrailActive
                recorder_count       = $recorderCount
                config_recorder_active = $configRecorderActive
            }

            if ($cloudTrailActive -and $configRecorderActive) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-18' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'CloudTrail active and Config recorder active'
            }

            if ($cloudTrailActive -or $configRecorderActive) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'GOV-18' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'Only one of CloudTrail or Config recorder is active'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-18' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'Neither CloudTrail nor Config recorder is active'
        }

        'GOV-20' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'GOV-20' `
                -Notes 'Verify incident RACI for cloud incidents exists. Check INC domain playbooks.'
        }
    }
}
