$DomainSeverity = @{
    'WRK-02' = 'P0'
    'WRK-03' = 'P0'
    'WRK-04' = 'P0'
    'WRK-05' = 'P0'
    'WRK-06' = 'P0'
    'WRK-07' = 'P1'
    'WRK-08' = 'P0'
    'WRK-09' = 'P0'
    'WRK-10' = 'P0'
    'WRK-11' = 'P2'
    'WRK-12' = 'P2'
    'WRK-13' = 'P0'
    'WRK-14' = 'P0'
    'WRK-15' = 'P1'
    'WRK-16' = 'P0'
    'WRK-17' = 'P0'
    'WRK-18' = 'P0'
    'WRK-19' = 'P0'
    'WRK-20' = 'P0'
    'WRK-21' = 'P0'
    'WRK-22' = 'P0'
    'WRK-23' = 'P0'
    'WRK-24' = 'P0'
    'WRK-25' = 'P2'
    'WRK-26' = 'P0'
}

$Script:WrkEolRuntimes = @('nodejs12.x', 'nodejs10.x', 'nodejs8.10', 'python2.7', 'ruby2.5')

function Get-WrkTaggedResourceSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $resources = @()
    $paginationToken = $null
    $serviceTypes = @{}

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

    foreach ($resource in $resources) {
        $arn = [string]$resource.ResourceARN
        if ($arn -match 'arn:aws:([^:]+):') {
            $service = $Matches[1]
            if (-not $serviceTypes.ContainsKey($service)) {
                $serviceTypes[$service] = 0
            }
            $serviceTypes[$service] = $serviceTypes[$service] + 1
        }
    }

    return @{
        resource_count = $resources.Count
        service_types  = $serviceTypes
    }
}

function Get-WrkSsmStringParameterCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ssm', 'describe-parameters') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    $stringCount = 0
    if ($data.Parameters) {
        foreach ($parameter in $data.Parameters) {
            if ([string]$parameter.Type -eq 'String') {
                $stringCount++
            }
        }
    }

    return $stringCount
}

function Get-WrkActiveAccessKeyCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $userData = Invoke-AWSCLI -Arguments @('iam', 'list-users', '--max-items', '1000') -Region $Region
    if ($null -eq $userData) {
        return $null
    }

    $activeKeyCount = 0
    if ($userData.Users) {
        foreach ($user in $userData.Users) {
            $keyData = Invoke-AWSCLI -Arguments @('iam', 'list-access-keys', '--user-name', $user.UserName) -Region $Region
            if ($null -eq $keyData -or -not $keyData.AccessKeyMetadata) {
                continue
            }

            foreach ($key in $keyData.AccessKeyMetadata) {
                if ($key.Status -eq 'Active') {
                    $activeKeyCount++
                }
            }
        }
    }

    return $activeKeyCount
}

function Test-WrkPolicyAllowsPublicPrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyText
    )

    if ([string]::IsNullOrWhiteSpace($PolicyText)) {
        return $false
    }

    if ($PolicyText -match '"Principal"\s*:\s*"\*"' -and $PolicyText -match '"Effect"\s*:\s*"Allow"') {
        return $true
    }

    return $false
}

function Get-WrkLambdaFunctions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $functions = @()
    $marker = $null

    do {
        $arguments = @('lambda', 'list-functions', '--max-items', '1000')
        if ($marker) {
            $arguments += @('--marker', $marker)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if ($data.Functions) {
            $functions += @($data.Functions)
        }

        $marker = $null
        if ($data.PSObject.Properties.Name -contains 'NextMarker') {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.NextMarker)) {
                $marker = [string]$data.NextMarker
            }
        }
    } while ($marker)

    return $functions
}

function Get-DomainChecks {
    return [ordered]@{
        'WRK-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $summary = Get-WrkTaggedResourceSummary -Region $Region
            if ($null -eq $summary) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-02'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-02' `
                -Status 'PARTIAL' `
                -Evidence @{
                    resource_count = $summary.resource_count
                    service_types  = $summary.service_types
                } `
                -Notes 'Inventory completeness depends on tagging compliance.'
        }

        'WRK-03' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('iam', 'list-roles', '--max-items', '1000') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-03'
            }

            $workloadRoles = @()
            $roleCount = 0
            if ($data.Roles) {
                $roleCount = @($data.Roles).Count
                foreach ($role in $data.Roles) {
                    $roleName = [string]$role.RoleName
                    if ($roleName -match 'workload|app|svc|service|lambda|ecs|eks') {
                        if ($workloadRoles.Count -lt 10) {
                            $workloadRoles += $roleName
                        }
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-03' `
                -Status 'PARTIAL' `
                -Evidence @{
                    role_count     = $roleCount
                    workload_roles = @($workloadRoles)
                } `
                -Notes 'Verify each Lambda, ECS task, EC2 instance profile is dedicated.'
        }

        'WRK-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $stringCount = Get-WrkSsmStringParameterCount -Region $Region
            $keyCount = Get-WrkActiveAccessKeyCount -Region $Region

            if ($null -eq $stringCount -and $null -eq $keyCount) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-04'
            }

            if ($null -eq $stringCount) { $stringCount = 0 }
            if ($null -eq $keyCount) { $keyCount = 0 }

            $evidence = @{
                ssm_string_parameter_count = $stringCount
                active_access_key_count    = $keyCount
            }

            if ($stringCount -gt 0 -or $keyCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-04' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'String SSM parameters or service account access keys exist'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-04' `
                -Status 'PASS' -Evidence $evidence -Notes 'No String SSM parameters or active access keys found'
        }

        'WRK-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
            if ($null -eq $rdsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05'
            }

            $publicDbCount = 0
            $privateDbCount = 0
            $publicDbs = @()

            if ($rdsData.DBInstances) {
                foreach ($instance in $rdsData.DBInstances) {
                    if ($instance.PubliclyAccessible -eq $true) {
                        $publicDbCount++
                        if ($publicDbs.Count -lt 5) {
                            $publicDbs += [string]$instance.DBInstanceIdentifier
                        }
                    }
                    else {
                        $privateDbCount++
                    }
                }
            }

            $openSearchPublicCount = 0
            $domainData = Invoke-AWSCLI -Arguments @('opensearch', 'list-domain-names') -Region $Region
            if ($domainData -and $domainData.DomainNames) {
                foreach ($domainEntry in $domainData.DomainNames) {
                    $domainName = [string]$domainEntry.DomainName
                    $describeData = Invoke-AWSCLI -Arguments @('opensearch', 'describe-domain', '--domain-name', $domainName) -Region $Region
                    if ($null -eq $describeData -or -not $describeData.DomainStatus) {
                        continue
                    }

                    $vpcOptions = $describeData.DomainStatus.VPCOptions
                    if (-not $vpcOptions -or -not $vpcOptions.SubnetIds) {
                        $openSearchPublicCount++
                    }
                }
            }

            $evidence = @{
                public_rds_count      = $publicDbCount
                private_rds_count     = $privateDbCount
                public_rds_instances  = @($publicDbs)
                public_opensearch_count = $openSearchPublicCount
            }

            if ($publicDbCount -gt 0 -or $openSearchPublicCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Publicly accessible managed data services found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05' `
                -Status 'PASS' -Evidence $evidence -Notes 'No publicly accessible databases detected'
        }

        'WRK-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $functions = Get-WrkLambdaFunctions -Region $Region
            if ($null -eq $functions) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06'
            }

            if ($functions.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' `
                    -Status 'PARTIAL' -Evidence @{ lambda_count = 0 } -Notes 'No Lambda functions found in region'
            }

            $withVpc = 0
            $withoutVpc = 0

            foreach ($function in $functions) {
                $configData = Invoke-AWSCLI -Arguments @('lambda', 'get-function-configuration', '--function-name', $function.FunctionName) -Region $Region
                $hasVpc = $false

                if ($configData -and $configData.VpcConfig -and $configData.VpcConfig.SubnetIds) {
                    if (@($configData.VpcConfig.SubnetIds).Count -gt 0) {
                        $hasVpc = $true
                    }
                }

                if ($hasVpc) {
                    $withVpc++
                }
                else {
                    $withoutVpc++
                }
            }

            $evidence = @{
                lambda_count    = $functions.Count
                with_vpc_count  = $withVpc
                without_vpc_count = $withoutVpc
            }

            if ($withVpc -gt 0 -and $withoutVpc -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All Lambda functions use VPC configuration'
            }

            if ($withVpc -gt 0 -and $withoutVpc -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Some Lambda functions lack VPC configuration'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'No Lambda functions configured with VPC access'
        }

        'WRK-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-07' `
                -Notes 'Verify IAM role policies for workloads follow least privilege.'
        }

        'WRK-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-08' `
                -Notes 'Verify Macie active for workload S3 buckets. Link to DET-16/17.'
        }

        'WRK-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('cloudwatch', 'describe-alarms') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09'
            }

            $matchingAlarms = @()
            $allAlarms = @()
            if ($data.MetricAlarms) {
                $allAlarms = @($data.MetricAlarms)
            }

            foreach ($alarm in $allAlarms) {
                $alarmName = [string]$alarm.AlarmName
                $metricName = [string]$alarm.MetricName
                $namespace = [string]$alarm.Namespace
                $combined = ($alarmName + ' ' + $metricName + ' ' + $namespace)

                if ($combined -match 'Error|Errors|Failed|Failure|Lambda|ECS|EKS') {
                    if ($matchingAlarms.Count -lt 10) {
                        $matchingAlarms += $alarmName
                    }
                }
            }

            $evidence = @{
                alarm_count      = $allAlarms.Count
                matching_alarms  = @($matchingAlarms)
            }

            if ($matchingAlarms.Count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09' `
                    -Status 'PASS' -Evidence $evidence -Notes 'CloudWatch alarms exist for workload error monitoring'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No workload error alarms detected'
        }

        'WRK-10' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-10' `
                -Notes 'Verify Lambda, ECS, EKS events flow to QRadar via EventBridge.'
        }

        'WRK-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-11' `
                -Status 'PARTIAL' -Evidence $null `
                -Notes 'Verify service quotas and Lambda concurrency limits configured.'
        }

        'WRK-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-12' `
                -Notes 'Verify anomaly detection for service usage.'
        }

        'WRK-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-13' `
                -Notes 'Verify service dependency map in DAT/SIPedia.'
        }

        'WRK-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-14' `
                -Notes 'Verify runbooks for Lambda, ECS, EKS, RDS in DEX.'
        }

        'WRK-15' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $functions = Get-WrkLambdaFunctions -Region $Region
            if ($null -eq $functions) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-15'
            }

            $staleCount = 0
            $staleFunctions = @()
            $cutoff = (Get-Date).AddMonths(-12)

            foreach ($function in $functions) {
                if (-not $function.LastModified) {
                    continue
                }

                $lastModified = [datetime]$function.LastModified
                if ($lastModified -lt $cutoff) {
                    $staleCount++
                    if ($staleFunctions.Count -lt 10) {
                        $staleFunctions += [string]$function.FunctionName
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-15' `
                -Status 'PARTIAL' `
                -Evidence @{
                    lambda_count   = $functions.Count
                    stale_count    = $staleCount
                    stale_functions = @($staleFunctions)
                } `
                -Notes 'Flag Lambdas not modified in 12+ months for review.'
        }

        'WRK-16' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $functions = Get-WrkLambdaFunctions -Region $Region
            if ($null -eq $functions) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16'
            }

            $runtimeSummary = @{}
            $eolFunctions = @()

            foreach ($function in $functions) {
                $runtime = 'unknown'
                if ($function.Runtime) {
                    $runtime = [string]$function.Runtime
                }

                if (-not $runtimeSummary.ContainsKey($runtime)) {
                    $runtimeSummary[$runtime] = 0
                }
                $runtimeSummary[$runtime] = $runtimeSummary[$runtime] + 1

                if ($Script:WrkEolRuntimes -contains $runtime) {
                    if ($eolFunctions.Count -lt 10) {
                        $eolFunctions += @{
                            name    = [string]$function.FunctionName
                            runtime = $runtime
                        }
                    }
                }
            }

            $evidence = @{
                function_count   = $functions.Count
                runtimes         = $runtimeSummary
                eol_functions    = @($eolFunctions)
            }

            if ($eolFunctions.Count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Lambda functions using EOL runtimes found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16' `
                -Status 'PASS' -Evidence $evidence -Notes 'No EOL Lambda runtimes found'
        }

        'WRK-17' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('ecs', 'list-task-definitions', '--status', 'ACTIVE', '--max-items', '100') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17'
            }

            $taskDefs = @()
            if ($listData.taskDefinitionArns) {
                $taskDefs = @($listData.taskDefinitionArns)
            }

            if ($taskDefs.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' `
                    -Status 'PARTIAL' -Evidence @{ task_definition_count = 0 } -Notes 'No active ECS task definitions found'
            }

            $withRole = 0
            $withoutRole = 0
            $missingRoleDefs = @()

            foreach ($taskDefArn in $taskDefs) {
                $describeData = Invoke-AWSCLI -Arguments @('ecs', 'describe-task-definition', '--task-definition', $taskDefArn) -Region $Region
                if ($null -eq $describeData -or -not $describeData.taskDefinition) {
                    continue
                }

                if ($describeData.taskDefinition.taskRoleArn) {
                    $withRole++
                }
                else {
                    $withoutRole++
                    if ($missingRoleDefs.Count -lt 5) {
                        $missingRoleDefs += [string]$describeData.taskDefinition.family
                    }
                }
            }

            $evidence = @{
                task_definition_count = $taskDefs.Count
                with_task_role_count  = $withRole
                without_task_role_count = $withoutRole
                missing_role_families = @($missingRoleDefs)
            }

            if ($withoutRole -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'ECS task definitions without TaskRoleArn found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' `
                -Status 'PASS' -Evidence $evidence -Notes 'All ECS task definitions have TaskRoleArn set'
        }

        'WRK-18' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $repoData = Invoke-AWSCLI -Arguments @('ecr', 'describe-repositories', '--max-results', '1000') -Region $Region
            $registryData = Invoke-AWSCLI -Arguments @('ecr', 'describe-registry') -Region $Region

            if ($null -eq $repoData -and $null -eq $registryData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18'
            }

            $repoCount = 0
            if ($repoData -and $repoData.repositories) {
                $repoCount = @($repoData.repositories).Count
            }

            $scanOnPush = $false
            if ($registryData -and $registryData.scanningConfiguration) {
                if ($registryData.scanningConfiguration.scanOnPush -eq $true) {
                    $scanOnPush = $true
                }
            }

            $evidence = @{
                repository_count = $repoCount
                scan_on_push     = $scanOnPush
            }

            if ($repoCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No ECR repositories found in region'
            }

            if ($scanOnPush) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' `
                    -Status 'PASS' -Evidence $evidence -Notes 'ECR scan on push enabled at registry level'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' `
                -Status 'FAIL' -Evidence $evidence -Notes 'ECR scan on push is not enabled'
        }

        'WRK-19' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('eks', 'list-clusters') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19'
            }

            $clusters = @()
            if ($listData.clusters) {
                $clusters = @($listData.clusters)
            }

            if ($clusters.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' `
                    -Status 'PARTIAL' -Evidence @{ cluster_count = 0 } -Notes 'No EKS clusters found in region'
            }

            $clusterEvidence = @()
            $failingClusters = 0

            foreach ($clusterName in $clusters) {
                $describeData = Invoke-AWSCLI -Arguments @('eks', 'describe-cluster', '--name', $clusterName) -Region $Region
                if ($null -eq $describeData -or -not $describeData.cluster) {
                    continue
                }

                $vpcConfig = $describeData.cluster.resourcesVpcConfig
                $publicAccess = $false
                $openPublic = $false
                $publicCidrs = @()

                if ($vpcConfig) {
                    if ($vpcConfig.endpointPublicAccess -eq $true) {
                        $publicAccess = $true
                    }
                    if ($vpcConfig.publicAccessCidrs) {
                        $publicCidrs = @($vpcConfig.publicAccessCidrs)
                        foreach ($cidr in $publicCidrs) {
                            if ([string]$cidr -eq '0.0.0.0/0') {
                                $openPublic = $true
                            }
                        }
                    }
                }

                $clusterEvidence += @{
                    cluster_name           = $clusterName
                    endpoint_public_access = $publicAccess
                    public_access_cidrs    = @($publicCidrs)
                }

                if ($publicAccess -and $openPublic) {
                    $failingClusters++
                }
            }

            $evidence = @{
                cluster_count     = $clusters.Count
                failing_clusters  = $failingClusters
                clusters          = @($clusterEvidence)
            }

            if ($failingClusters -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'EKS cluster public endpoint allows 0.0.0.0/0'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' `
                -Status 'PASS' -Evidence $evidence -Notes 'EKS cluster endpoint access is restricted'
        }

        'WRK-20' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('eks', 'list-clusters') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20'
            }

            $clusters = @()
            if ($listData.clusters) {
                $clusters = @($listData.clusters)
            }

            if ($clusters.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' `
                    -Status 'PARTIAL' -Evidence @{ cluster_count = 0 } -Notes 'No EKS clusters found in region'
            }

            $requiredTypes = @('api', 'audit', 'authenticator')
            $clusterEvidence = @()
            $failingClusters = 0

            foreach ($clusterName in $clusters) {
                $describeData = Invoke-AWSCLI -Arguments @('eks', 'describe-cluster', '--name', $clusterName) -Region $Region
                if ($null -eq $describeData -or -not $describeData.cluster) {
                    continue
                }

                $enabledTypes = @()
                if ($describeData.cluster.logging -and $describeData.cluster.logging.clusterLogging) {
                    foreach ($logEntry in $describeData.cluster.logging.clusterLogging) {
                        if ($logEntry.enabled -eq $true -and $logEntry.types) {
                            foreach ($logType in $logEntry.types) {
                                if ($enabledTypes -notcontains $logType) {
                                    $enabledTypes += [string]$logType
                                }
                            }
                        }
                    }
                }

                $clusterOk = $true
                foreach ($required in $requiredTypes) {
                    if ($enabledTypes -notcontains $required) {
                        $clusterOk = $false
                    }
                }

                if (-not $clusterOk) {
                    $failingClusters++
                }

                $clusterEvidence += @{
                    cluster_name  = $clusterName
                    enabled_types = @($enabledTypes)
                }
            }

            $evidence = @{
                cluster_count    = $clusters.Count
                failing_clusters = $failingClusters
                clusters         = @($clusterEvidence)
            }

            if ($failingClusters -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more EKS clusters missing required control plane logs'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' `
                -Status 'PASS' -Evidence $evidence -Notes 'EKS control plane logging enabled for api, audit, and authenticator'
        }

        'WRK-21' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
            if ($null -eq $rdsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21'
            }

            $publicCount = 0
            $privateCount = 0
            $publicInstances = @()

            if ($rdsData.DBInstances) {
                foreach ($instance in $rdsData.DBInstances) {
                    if ($instance.PubliclyAccessible -eq $true) {
                        $publicCount++
                        if ($publicInstances.Count -lt 5) {
                            $publicInstances += [string]$instance.DBInstanceIdentifier
                        }
                    }
                    else {
                        $privateCount++
                    }
                }
            }

            $evidence = @{
                public_count    = $publicCount
                private_count   = $privateCount
                public_instances = @($publicInstances)
            }

            if ($publicCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Publicly accessible RDS instances found'
            }

            if ($privateCount -eq 0 -and $publicCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No RDS instances found in region'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' `
                -Status 'PASS' -Evidence $evidence -Notes 'All RDS instances are not publicly accessible'
        }

        'WRK-22' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $publicQueueCount = 0
            $queueCount = 0
            $publicTopicCount = 0
            $topicCount = 0

            $sqsData = Invoke-AWSCLI -Arguments @('sqs', 'list-queues') -Region $Region
            if ($sqsData -and $sqsData.QueueUrls) {
                foreach ($queueUrl in $sqsData.QueueUrls) {
                    $queueCount++
                    $attrData = Invoke-AWSCLI -Arguments @('sqs', 'get-queue-attributes', '--queue-url', $queueUrl, '--attribute-names', 'Policy') -Region $Region
                    if ($attrData -and $attrData.Attributes -and $attrData.Attributes.Policy) {
                        if (Test-WrkPolicyAllowsPublicPrincipal -PolicyText ([string]$attrData.Attributes.Policy)) {
                            $publicQueueCount++
                        }
                    }
                }
            }

            $snsData = Invoke-AWSCLI -Arguments @('sns', 'list-topics') -Region $Region
            if ($snsData -and $snsData.Topics) {
                foreach ($topic in $snsData.Topics) {
                    if (-not $topic.TopicArn) {
                        continue
                    }

                    $topicCount++
                    $attrData = Invoke-AWSCLI -Arguments @('sns', 'get-topic-attributes', '--topic-arn', $topic.TopicArn) -Region $Region
                    if ($attrData -and $attrData.Attributes -and $attrData.Attributes.Policy) {
                        if (Test-WrkPolicyAllowsPublicPrincipal -PolicyText ([string]$attrData.Attributes.Policy)) {
                            $publicTopicCount++
                        }
                    }
                }
            }

            if ($null -eq $sqsData -and $null -eq $snsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-22'
            }

            $evidence = @{
                queue_count        = $queueCount
                public_queue_count = $publicQueueCount
                topic_count        = $topicCount
                public_topic_count = $publicTopicCount
            }

            if ($publicQueueCount -gt 0 -or $publicTopicCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-22' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Public SQS or SNS access policies found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-22' `
                -Status 'PASS' -Evidence $evidence -Notes 'No public SQS or SNS policies detected'
        }

        'WRK-23' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $encryptedQueues = 0
            $unencryptedQueues = 0
            $encryptedTopics = 0
            $unencryptedTopics = 0

            $sqsData = Invoke-AWSCLI -Arguments @('sqs', 'list-queues') -Region $Region
            if ($sqsData -and $sqsData.QueueUrls) {
                foreach ($queueUrl in $sqsData.QueueUrls) {
                    $attrData = Invoke-AWSCLI -Arguments @(
                        'sqs', 'get-queue-attributes', '--queue-url', $queueUrl,
                        '--attribute-names', 'KmsMasterKeyId', 'SqsManagedSseEnabled'
                    ) -Region $Region

                    $encrypted = $false
                    if ($attrData -and $attrData.Attributes) {
                        if ($attrData.Attributes.KmsMasterKeyId) {
                            $encrypted = $true
                        }
                        if ($attrData.Attributes.SqsManagedSseEnabled -eq 'true') {
                            $encrypted = $true
                        }
                    }

                    if ($encrypted) {
                        $encryptedQueues++
                    }
                    else {
                        $unencryptedQueues++
                    }
                }
            }

            $snsData = Invoke-AWSCLI -Arguments @('sns', 'list-topics') -Region $Region
            if ($snsData -and $snsData.Topics) {
                foreach ($topic in $snsData.Topics) {
                    if (-not $topic.TopicArn) {
                        continue
                    }

                    $attrData = Invoke-AWSCLI -Arguments @('sns', 'get-topic-attributes', '--topic-arn', $topic.TopicArn) -Region $Region
                    $encrypted = $false
                    if ($attrData -and $attrData.Attributes -and $attrData.Attributes.KmsMasterKeyId) {
                        $encrypted = $true
                    }

                    if ($encrypted) {
                        $encryptedTopics++
                    }
                    else {
                        $unencryptedTopics++
                    }
                }
            }

            if ($null -eq $sqsData -and $null -eq $snsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23'
            }

            $totalQueues = $encryptedQueues + $unencryptedQueues
            $totalTopics = $encryptedTopics + $unencryptedTopics

            $evidence = @{
                queue_count           = $totalQueues
                encrypted_queue_count = $encryptedQueues
                topic_count           = $totalTopics
                encrypted_topic_count = $encryptedTopics
            }

            if ($totalQueues -eq 0 -and $totalTopics -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No SQS queues or SNS topics found in region'
            }

            if ($unencryptedQueues -eq 0 -and $unencryptedTopics -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All queues and topics are encrypted'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more queues or topics are not encrypted'
        }

        'WRK-24' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $apiData = Invoke-AWSCLI -Arguments @('apigateway', 'get-rest-apis') -Region $Region
            if ($null -eq $apiData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24'
            }

            $apis = @()
            if ($apiData.items) {
                $apis = @($apiData.items)
            }

            if ($apis.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' `
                    -Status 'PARTIAL' -Evidence @{ api_count = 0 } -Notes 'No REST APIs found in region'
            }

            $unauthenticatedMethods = 0
            $methodCount = 0

            foreach ($api in $apis) {
                if (-not $api.id) {
                    continue
                }

                $resourceData = Invoke-AWSCLI -Arguments @('apigateway', 'get-resources', '--rest-api-id', $api.id) -Region $Region
                if ($null -eq $resourceData -or -not $resourceData.items) {
                    continue
                }

                foreach ($resource in $resourceData.items) {
                    if (-not $resource.resourceMethods) {
                        continue
                    }

                    foreach ($methodName in $resource.resourceMethods.PSObject.Properties.Name) {
                        $methodCount++
                        $methodData = Invoke-AWSCLI -Arguments @(
                            'apigateway', 'get-method',
                            '--rest-api-id', $api.id,
                            '--resource-id', $resource.id,
                            '--http-method', $methodName
                        ) -Region $Region

                        if ($methodData -and $methodData.authorizationType -eq 'NONE') {
                            $unauthenticatedMethods++
                        }
                    }
                }
            }

            $evidence = @{
                api_count                   = $apis.Count
                method_count                = $methodCount
                unauthenticated_method_count = $unauthenticatedMethods
            }

            if ($unauthenticatedMethods -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Unauthenticated API Gateway methods found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' `
                -Status 'PASS' -Evidence $evidence -Notes 'No API methods with authorizationType NONE found'
        }

        'WRK-25' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $apiData = Invoke-AWSCLI -Arguments @('apigateway', 'get-rest-apis') -Region $Region
            if ($null -eq $apiData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25'
            }

            $apis = @()
            if ($apiData.items) {
                $apis = @($apiData.items)
            }

            if ($apis.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25' `
                    -Status 'PARTIAL' -Evidence @{ api_count = 0 } -Notes 'No REST APIs found in region'
            }

            $stageCount = 0
            $stagesWithThrottling = 0

            foreach ($api in $apis) {
                if (-not $api.id) {
                    continue
                }

                $stageData = Invoke-AWSCLI -Arguments @('apigateway', 'get-stages', '--rest-api-id', $api.id) -Region $Region
                if ($null -eq $stageData -or -not $stageData.item) {
                    continue
                }

                foreach ($stage in $stageData.item) {
                    $stageCount++
                    $hasThrottling = $false

                    if ($stage.methodSettings) {
                        foreach ($settingName in $stage.methodSettings.PSObject.Properties.Name) {
                            $setting = $stage.methodSettings.$settingName
                            if ($setting.throttlingBurstLimit -or $setting.throttlingRateLimit) {
                                $hasThrottling = $true
                                break
                            }
                        }
                    }

                    if ($stage.defaultRouteSettings) {
                        if ($stage.defaultRouteSettings.throttlingBurstLimit -or $stage.defaultRouteSettings.throttlingRateLimit) {
                            $hasThrottling = $true
                        }
                    }

                    if ($hasThrottling) {
                        $stagesWithThrottling++
                    }
                }
            }

            $evidence = @{
                api_count                 = $apis.Count
                stage_count               = $stageCount
                stages_with_throttling    = $stagesWithThrottling
            }

            if ($stageCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No API stages found'
            }

            if ($stagesWithThrottling -eq $stageCount) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All API stages have throttling configured'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more API stages lack throttling configuration'
        }

        'WRK-26' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('cognito-idp', 'list-user-pools', '--max-results', '10') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26'
            }

            $pools = @()
            if ($listData.UserPools) {
                $pools = @($listData.UserPools)
            }

            if ($pools.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' `
                    -Status 'PARTIAL' -Evidence @{ user_pool_count = 0 } -Notes 'No Cognito user pools found in region'
            }

            $poolEvidence = @()
            $failingPools = 0

            foreach ($pool in $pools) {
                if (-not $pool.Id) {
                    continue
                }

                $describeData = Invoke-AWSCLI -Arguments @('cognito-idp', 'describe-user-pool', '--user-pool-id', $pool.Id) -Region $Region
                $mfaConfig = 'OFF'
                if ($describeData -and $describeData.UserPool -and $describeData.UserPool.MfaConfiguration) {
                    $mfaConfig = [string]$describeData.UserPool.MfaConfiguration
                }

                $poolEvidence += @{
                    pool_id = [string]$pool.Id
                    pool_name = [string]$pool.Name
                    mfa_configuration = $mfaConfig
                }

                if ($mfaConfig -eq 'OFF') {
                    $failingPools++
                }
            }

            $evidence = @{
                user_pool_count = $pools.Count
                failing_pools   = $failingPools
                pools           = @($poolEvidence)
            }

            if ($failingPools -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more Cognito user pools have MFA disabled'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' `
                -Status 'PASS' -Evidence $evidence -Notes 'Cognito user pools have MFA enabled'
        }
    }
}
