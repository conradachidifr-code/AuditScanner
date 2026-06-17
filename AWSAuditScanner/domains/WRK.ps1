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

    $resources = New-AuditList
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

        if (Test-AuditHasProperty -Object $data -PropertyName 'ResourceTagMappingList') {
            foreach ($resource in (Get-AuditCliArray $data.ResourceTagMappingList)) {
                [void]$resources.Add($resource)
            }
        }

        $paginationToken = $null
        if ((Test-AuditHasProperty -Object $data -PropertyName 'PaginationToken')) {
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
        resource_count = (Get-AuditCollectionCount $resources)
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
    if (Test-AuditHasProperty -Object $data -PropertyName 'Parameters') {
        foreach ($parameter in (Get-AuditCliArray $data.Parameters)) {
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
    if (Test-AuditHasProperty -Object $userData -PropertyName 'Users') {
        foreach ($user in (Get-AuditCliArray $userData.Users)) {
            $keyData = Invoke-AWSCLI -Arguments @('iam', 'list-access-keys', '--user-name', $user.UserName) -Region $Region
            if ($null -eq $keyData -or -not (Test-AuditHasProperty -Object $keyData -PropertyName 'AccessKeyMetadata')) {
                continue
            }

            foreach ($key in (Get-AuditCliArray $keyData.AccessKeyMetadata)) {
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

    $functions = New-AuditList
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

        if (Test-AuditHasProperty -Object $data -PropertyName 'Functions') {
            foreach ($function in (Get-AuditCliArray $data.Functions)) {
                [void]$functions.Add($function)
            }
        }

        $marker = $null
        if ((Test-AuditHasProperty -Object $data -PropertyName 'NextMarker')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.NextMarker)) {
                $marker = [string]$data.NextMarker
            }
        }
    } while ($marker)

    return $functions.ToArray()
}


function Get-WrkWorkshopNotes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlId
    )

    $notesByControl = @{
        'WRK-02' = 'Verify workload resource inventory completeness and tagging coverage.'
        'WRK-03' = 'Verify each Lambda, ECS task, and EC2 instance profile uses a dedicated IAM role.'
        'WRK-07' = 'Verify IAM role policies for workloads follow least privilege.'
        'WRK-08' = 'Verify Macie is active for workload S3 buckets. Link to DET-16/17.'
        'WRK-10' = 'Verify Lambda, ECS, and EKS events flow to QRadar via EventBridge.'
        'WRK-11' = 'Verify service quotas and Lambda concurrency limits are configured.'
        'WRK-12' = 'Verify anomaly detection for service usage.'
        'WRK-13' = 'Verify service dependency map exists in DAT/SIPedia.'
        'WRK-14' = 'Verify runbooks for Lambda, ECS, EKS, and RDS in DEX.'
        'WRK-25' = 'Verify API Gateway throttling and WAF protection for public APIs.'
    }

    if (-not $notesByControl.ContainsKey($ControlId)) {
        throw "Missing workshop notes for control $ControlId"
    }

    return $notesByControl[$ControlId]
}

function Get-DomainChecks {
    $checks = [ordered]@{}

    $checks['WRK-02'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-02' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-02')
    }

    $checks['WRK-03'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-03' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-03')
    }

    $checks['WRK-04'] = {
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
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-04' -Status 'FAIL' -Evidence $evidence -Notes 'String SSM parameters or active IAM access keys found (possible static secrets in plaintext)'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-04' -Status 'PASS' -Evidence $evidence -Notes 'No String SSM parameters or active access keys found'
    }

    $checks['WRK-05'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
        if ($null -eq $rdsData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05'
        }

        $publicDbCount = 0
        $privateDbCount = 0
        $publicDbs = @()

        if (Test-AuditHasProperty -Object $rdsData -PropertyName 'DBInstances') {
            foreach ($instance in (Get-AuditCliArray $rdsData.DBInstances)) {
                $isPublic = $false
                if (Test-AuditHasProperty -Object $instance -PropertyName 'PubliclyAccessible') {
                    $isPublic = ($instance.PubliclyAccessible -eq $true)
                }

                if ($isPublic) {
                    $publicDbCount++
                    if ((Get-AuditCollectionCount $publicDbs) -lt 5) {
                        $publicDbs += [string](Get-AuditPropertyValue $instance -PropertyNames @('DBInstanceIdentifier'))
                    }
                }
                else {
                    $privateDbCount++
                }
            }
        }

        $evidence = @{
            public_rds_count     = $publicDbCount
            private_rds_count    = $privateDbCount
            public_rds_instances = @($publicDbs)
        }

        if ($publicDbCount -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05' -Status 'FAIL' -Evidence $evidence -Notes 'Publicly accessible RDS instances found'
        }

        if ($privateDbCount -eq 0 -and $publicDbCount -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05' -Status 'PARTIAL' -Evidence $evidence -Notes 'No RDS instances found in region'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-05' -Status 'PASS' -Evidence $evidence -Notes 'No publicly accessible RDS instances found'
    }

    $checks['WRK-06'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $functions = Get-WrkLambdaFunctions -Region $Region
        if ($null -eq $functions) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06'
        }

        if ((Get-AuditCollectionCount $functions) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' -Status 'PARTIAL' -Evidence @{ lambda_count = 0 } -Notes 'No Lambda functions found in region'
        }

        $withVpc = 0
        $withoutVpc = 0

        foreach ($function in $functions) {
            $functionName = [string](Get-AuditPropertyValue $function -PropertyNames @('FunctionName'))
            $configData = Invoke-AWSCLI -Arguments @('lambda', 'get-function-configuration', '--function-name', $functionName) -Region $Region
            $hasVpc = $false

            if ($configData -and (Test-AuditHasProperty -Object $configData -PropertyName 'VpcConfig')) {
                $vpcId = [string](Get-AuditPropertyValue $configData.VpcConfig -PropertyNames @('VpcId'))
                if (-not [string]::IsNullOrWhiteSpace($vpcId)) {
                    $hasVpc = $true
                }
            }

            if ($hasVpc) { $withVpc++ } else { $withoutVpc++ }
        }

        $evidence = @{
            lambda_count      = (Get-AuditCollectionCount $functions)
            with_vpc_count    = $withVpc
            without_vpc_count = $withoutVpc
        }

        if ($withVpc -gt 0 -and $withoutVpc -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' -Status 'PASS' -Evidence $evidence -Notes 'All Lambda functions have VpcConfig.VpcId set'
        }

        if ($withVpc -gt 0 -and $withoutVpc -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' -Status 'PARTIAL' -Evidence $evidence -Notes 'Some Lambda functions lack VPC configuration'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-06' -Status 'PARTIAL' -Evidence $evidence -Notes 'No Lambda functions configured with VPC access'
    }

    $checks['WRK-07'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-07' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-07')
    }

    $checks['WRK-08'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-08' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-08')
    }

    $checks['WRK-09'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $data = Invoke-AWSCLI -Arguments @('cloudwatch', 'describe-alarms') -Region $Region
        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09'
        }

        $matchingAlarms = @()
        $allAlarms = @()
        if (Test-AuditHasProperty -Object $data -PropertyName 'MetricAlarms') {
            $allAlarms = @(Get-AuditCliArray $data.MetricAlarms)
        }

        foreach ($alarm in $allAlarms) {
            $alarmName = [string](Get-AuditPropertyValue $alarm -PropertyNames @('AlarmName'))
            $metricName = [string](Get-AuditPropertyValue $alarm -PropertyNames @('MetricName'))
            $namespace = [string](Get-AuditPropertyValue $alarm -PropertyNames @('Namespace'))
            $combined = ($alarmName + ' ' + $metricName + ' ' + $namespace)

            if ($combined -match 'Error|Errors|Failed|Failure|Lambda|ECS|EKS') {
                if ((Get-AuditCollectionCount $matchingAlarms) -lt 10) {
                    $matchingAlarms += $alarmName
                }
            }
        }

        $evidence = @{
            alarm_count     = (Get-AuditCollectionCount $allAlarms)
            matching_alarms = @($matchingAlarms)
        }

        if ((Get-AuditCollectionCount $matchingAlarms) -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09' -Status 'PASS' -Evidence $evidence -Notes 'CloudWatch alarms exist for workload error monitoring'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-09' -Status 'FAIL' -Evidence $evidence -Notes 'No workload error alarms detected'
    }

    $checks['WRK-10'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-10' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-10')
    }

    $checks['WRK-11'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-11' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-11')
    }

    $checks['WRK-12'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-12' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-12')
    }

    $checks['WRK-13'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-13' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-13')
    }

    $checks['WRK-14'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-14' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-14')
    }

    $checks['WRK-15'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $functions = Get-WrkLambdaFunctions -Region $Region
        if ($null -eq $functions) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-15'
        }

        $staleCount = 0
        $staleFunctions = @()
        $cutoff = (Get-Date).AddMonths(-12)

        foreach ($function in $functions) {
            if (-not (Test-AuditHasProperty -Object $function -PropertyName 'LastModified')) { continue }
            $lastModified = [datetime]$function.LastModified
            if ($lastModified -lt $cutoff) {
                $staleCount++
                if ((Get-AuditCollectionCount $staleFunctions) -lt 10) {
                    $staleFunctions += [string](Get-AuditPropertyValue $function -PropertyNames @('FunctionName'))
                }
            }
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-15' -Status 'PARTIAL' -Evidence @{
            lambda_count    = (Get-AuditCollectionCount $functions)
            stale_count     = $staleCount
            stale_functions = @($staleFunctions)
        } -Notes 'Flag Lambdas not modified in 12+ months for review.'
    }

    $checks['WRK-16'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $functions = Get-WrkLambdaFunctions -Region $Region
        if ($null -eq $functions) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16'
        }

        $runtimeSummary = @{}
        $eolFunctions = @()

        foreach ($function in $functions) {
            $runtime = 'unknown'
            if (Test-AuditHasProperty -Object $function -PropertyName 'Runtime') {
                $runtime = [string]$function.Runtime
            }

            if (-not $runtimeSummary.ContainsKey($runtime)) { $runtimeSummary[$runtime] = 0 }
            $runtimeSummary[$runtime] = $runtimeSummary[$runtime] + 1

            if ($Script:WrkEolRuntimes -contains $runtime) {
                if ((Get-AuditCollectionCount $eolFunctions) -lt 10) {
                    $eolFunctions += @{
                        name    = [string](Get-AuditPropertyValue $function -PropertyNames @('FunctionName'))
                        runtime = $runtime
                    }
                }
            }
        }

        $evidence = @{
            function_count = (Get-AuditCollectionCount $functions)
            runtimes       = $runtimeSummary
            eol_functions  = @($eolFunctions)
        }

        if ((Get-AuditCollectionCount $eolFunctions) -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16' -Status 'FAIL' -Evidence $evidence -Notes 'Lambda functions using EOL runtimes found'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-16' -Status 'PASS' -Evidence $evidence -Notes 'No EOL Lambda runtimes found'
    }

    $checks['WRK-17'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $listData = Invoke-AWSCLI -Arguments @('ecs', 'list-task-definitions', '--status', 'ACTIVE', '--max-items', '100') -Region $Region
        if ($null -eq $listData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17'
        }

        $taskDefs = @()
        if (Test-AuditHasProperty -Object $listData -PropertyName 'taskDefinitionArns') {
            $taskDefs = @(Get-AuditCliArray $listData.taskDefinitionArns)
        }

        if ((Get-AuditCollectionCount $taskDefs) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' -Status 'PARTIAL' -Evidence @{ task_definition_count = 0 } -Notes 'No active ECS task definitions found'
        }

        $withRole = 0
        $withoutRole = 0
        $missingRoleDefs = @()

        foreach ($taskDefArn in $taskDefs) {
            $describeData = Invoke-AWSCLI -Arguments @('ecs', 'describe-task-definition', '--task-definition', $taskDefArn) -Region $Region
            if ($null -eq $describeData -or -not (Test-AuditHasProperty -Object $describeData -PropertyName 'taskDefinition')) { continue }

            $taskRoleArn = [string](Get-AuditPropertyValue $describeData.taskDefinition -PropertyNames @('taskRoleArn'))
            if (-not [string]::IsNullOrWhiteSpace($taskRoleArn)) {
                $withRole++
            }
            else {
                $withoutRole++
                if ((Get-AuditCollectionCount $missingRoleDefs) -lt 5) {
                    $missingRoleDefs += [string](Get-AuditPropertyValue $describeData.taskDefinition -PropertyNames @('family'))
                }
            }
        }

        $evidence = @{
            task_definition_count   = (Get-AuditCollectionCount $taskDefs)
            with_task_role_count    = $withRole
            without_task_role_count = $withoutRole
            missing_role_families   = @($missingRoleDefs)
        }

        if ($withoutRole -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' -Status 'FAIL' -Evidence $evidence -Notes 'ECS task definitions without TaskRoleArn found'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-17' -Status 'PASS' -Evidence $evidence -Notes 'All ECS task definitions have TaskRoleArn set'
    }

    $checks['WRK-18'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $repoData = Invoke-AWSCLI -Arguments @('ecr', 'describe-repositories', '--max-results', '1000') -Region $Region
        $registryData = Invoke-AWSCLI -Arguments @('ecr', 'describe-registry') -Region $Region

        if ($null -eq $repoData -and $null -eq $registryData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18'
        }

        $repoCount = 0
        if ($repoData -and (Test-AuditHasProperty -Object $repoData -PropertyName 'repositories')) {
            $repoCount = (Get-AuditCollectionCount (Get-AuditCliArray $repoData.repositories))
        }

        $scanOnPush = $false
        if ($registryData -and (Test-AuditHasProperty -Object $registryData -PropertyName 'scanningConfiguration')) {
            $scanOnPush = ($registryData.scanningConfiguration.scanOnPush -eq $true)
        }

        $evidence = @{ repository_count = $repoCount; scan_on_push = $scanOnPush }

        if ($repoCount -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' -Status 'PARTIAL' -Evidence $evidence -Notes 'No ECR repositories found in region'
        }

        if ($scanOnPush) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' -Status 'PASS' -Evidence $evidence -Notes 'ECR scan on push enabled at registry level'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-18' -Status 'FAIL' -Evidence $evidence -Notes 'ECR scan on push is not enabled'
    }

    $checks['WRK-19'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $listData = Invoke-AWSCLI -Arguments @('eks', 'list-clusters') -Region $Region
        if ($null -eq $listData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19'
        }

        $clusters = @()
        if (Test-AuditHasProperty -Object $listData -PropertyName 'clusters') {
            $clusters = @(Get-AuditCliArray $listData.clusters)
        }

        if ((Get-AuditCollectionCount $clusters) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' -Status 'PARTIAL' -Evidence @{ cluster_count = 0 } -Notes 'No EKS clusters found in region'
        }

        $clusterEvidence = @()
        $failingClusters = 0

        foreach ($clusterName in $clusters) {
            $describeData = Invoke-AWSCLI -Arguments @('eks', 'describe-cluster', '--name', $clusterName) -Region $Region
            if ($null -eq $describeData -or -not (Test-AuditHasProperty -Object $describeData -PropertyName 'cluster')) { continue }

            $vpcConfig = $describeData.cluster.resourcesVpcConfig
            $publicAccess = $false
            $openPublic = $false
            $publicCidrs = @()

            if ($vpcConfig) {
                if ((Test-AuditHasProperty -Object $vpcConfig -PropertyName 'endpointPublicAccess') -and ($vpcConfig.endpointPublicAccess -eq $true)) {
                    $publicAccess = $true
                }
                if (Test-AuditHasProperty -Object $vpcConfig -PropertyName 'publicAccessCidrs') {
                    $publicCidrs = @(Get-AuditCliArray $vpcConfig.publicAccessCidrs)
                    foreach ($cidr in $publicCidrs) {
                        if ([string]$cidr -eq '0.0.0.0/0') { $openPublic = $true }
                    }
                }
            }

            $clusterEvidence += @{
                cluster_name           = [string]$clusterName
                endpoint_public_access = $publicAccess
                public_access_cidrs    = @($publicCidrs)
            }

            if ($publicAccess -and $openPublic) { $failingClusters++ }
        }

        $evidence = @{
            cluster_count    = (Get-AuditCollectionCount $clusters)
            failing_clusters = $failingClusters
            clusters         = @($clusterEvidence)
        }

        if ($failingClusters -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' -Status 'FAIL' -Evidence $evidence -Notes 'EKS cluster public endpoint allows 0.0.0.0/0'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-19' -Status 'PASS' -Evidence $evidence -Notes 'EKS cluster endpoint access is restricted'
    }

    $checks['WRK-20'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $listData = Invoke-AWSCLI -Arguments @('eks', 'list-clusters') -Region $Region
        if ($null -eq $listData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20'
        }

        $clusters = @()
        if (Test-AuditHasProperty -Object $listData -PropertyName 'clusters') {
            $clusters = @(Get-AuditCliArray $listData.clusters)
        }

        if ((Get-AuditCollectionCount $clusters) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' -Status 'PARTIAL' -Evidence @{ cluster_count = 0 } -Notes 'No EKS clusters found in region'
        }

        $requiredTypes = @('api', 'audit', 'authenticator')
        $clusterEvidence = @()
        $failingClusters = 0

        foreach ($clusterName in $clusters) {
            $describeData = Invoke-AWSCLI -Arguments @('eks', 'describe-cluster', '--name', $clusterName) -Region $Region
            if ($null -eq $describeData -or -not (Test-AuditHasProperty -Object $describeData -PropertyName 'cluster')) { continue }

            $enabledTypes = @()
            if (Test-AuditHasProperty -Object $describeData.cluster -PropertyName 'logging') {
                $logging = $describeData.cluster.logging
                if ($logging -and (Test-AuditHasProperty -Object $logging -PropertyName 'clusterLogging')) {
                    foreach ($logEntry in (Get-AuditCliArray $logging.clusterLogging)) {
                        if ((Test-AuditHasProperty -Object $logEntry -PropertyName 'enabled') -and ($logEntry.enabled -eq $true) -and (Test-AuditHasProperty -Object $logEntry -PropertyName 'types')) {
                            foreach ($logType in (Get-AuditCliArray $logEntry.types)) {
                                if ($enabledTypes -notcontains $logType) { $enabledTypes += [string]$logType }
                            }
                        }
                    }
                }
            }

            $clusterOk = $true
            foreach ($required in $requiredTypes) {
                if ($enabledTypes -notcontains $required) { $clusterOk = $false }
            }

            if (-not $clusterOk) { $failingClusters++ }

            $clusterEvidence += @{ cluster_name = [string]$clusterName; enabled_types = @($enabledTypes) }
        }

        $evidence = @{
            cluster_count    = (Get-AuditCollectionCount $clusters)
            failing_clusters = $failingClusters
            clusters         = @($clusterEvidence)
        }

        if ($failingClusters -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' -Status 'FAIL' -Evidence $evidence -Notes 'One or more EKS clusters missing required control plane logs'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-20' -Status 'PASS' -Evidence $evidence -Notes 'EKS control plane logging enabled for api, audit, and authenticator'
    }

    $checks['WRK-21'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
        if ($null -eq $rdsData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21'
        }

        $publicCount = 0
        $privateCount = 0
        $publicInstances = @()

        if (Test-AuditHasProperty -Object $rdsData -PropertyName 'DBInstances') {
            foreach ($instance in (Get-AuditCliArray $rdsData.DBInstances)) {
                $isPublic = $false
                if (Test-AuditHasProperty -Object $instance -PropertyName 'PubliclyAccessible') {
                    $isPublic = ($instance.PubliclyAccessible -eq $true)
                }

                if ($isPublic) {
                    $publicCount++
                    if ((Get-AuditCollectionCount $publicInstances) -lt 5) {
                        $publicInstances += [string](Get-AuditPropertyValue $instance -PropertyNames @('DBInstanceIdentifier'))
                    }
                }
                else { $privateCount++ }
            }
        }

        $evidence = @{ public_count = $publicCount; private_count = $privateCount; public_instances = @($publicInstances) }

        if ($publicCount -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' -Status 'FAIL' -Evidence $evidence -Notes 'Publicly accessible RDS instances found'
        }

        if ($privateCount -eq 0 -and $publicCount -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' -Status 'PARTIAL' -Evidence $evidence -Notes 'No RDS instances found in region'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-21' -Status 'PASS' -Evidence $evidence -Notes 'All RDS instances are not publicly accessible'
    }

    $checks['WRK-22'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $publicQueueCount = 0
        $queueCount = 0
        $publicTopicCount = 0
        $topicCount = 0

        $sqsData = Invoke-AWSCLI -Arguments @('sqs', 'list-queues') -Region $Region
        if ($sqsData -and (Test-AuditHasProperty -Object $sqsData -PropertyName 'QueueUrls')) {
            foreach ($queueUrl in (Get-AuditCliArray $sqsData.QueueUrls)) {
                $queueCount++
                $attrData = Invoke-AWSCLI -Arguments @('sqs', 'get-queue-attributes', '--queue-url', $queueUrl, '--attribute-names', 'Policy') -Region $Region
                if ($attrData -and (Test-AuditHasProperty -Object $attrData -PropertyName 'Attributes') -and $attrData.Attributes.Policy) {
                    if (Test-WrkPolicyAllowsPublicPrincipal -PolicyText ([string]$attrData.Attributes.Policy)) { $publicQueueCount++ }
                }
            }
        }

        $snsData = Invoke-AWSCLI -Arguments @('sns', 'list-topics') -Region $Region
        if ($snsData -and (Test-AuditHasProperty -Object $snsData -PropertyName 'Topics')) {
            foreach ($topic in (Get-AuditCliArray $snsData.Topics)) {
                $topicArn = [string](Get-AuditPropertyValue $topic -PropertyNames @('TopicArn'))
                if ([string]::IsNullOrWhiteSpace($topicArn)) { continue }
                $topicCount++
                $attrData = Invoke-AWSCLI -Arguments @('sns', 'get-topic-attributes', '--topic-arn', $topicArn) -Region $Region
                if ($attrData -and (Test-AuditHasProperty -Object $attrData -PropertyName 'Attributes') -and $attrData.Attributes.Policy) {
                    if (Test-WrkPolicyAllowsPublicPrincipal -PolicyText ([string]$attrData.Attributes.Policy)) { $publicTopicCount++ }
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
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-22' -Status 'FAIL' -Evidence $evidence -Notes 'Public SQS or SNS access policies found'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-22' -Status 'PASS' -Evidence $evidence -Notes 'No public SQS or SNS policies detected'
    }

    $checks['WRK-23'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $encryptedQueues = 0
        $unencryptedQueues = 0
        $encryptedTopics = 0
        $unencryptedTopics = 0

        $sqsData = Invoke-AWSCLI -Arguments @('sqs', 'list-queues') -Region $Region
        if ($sqsData -and (Test-AuditHasProperty -Object $sqsData -PropertyName 'QueueUrls')) {
            foreach ($queueUrl in (Get-AuditCliArray $sqsData.QueueUrls)) {
                $attrData = Invoke-AWSCLI -Arguments @('sqs', 'get-queue-attributes', '--queue-url', $queueUrl, '--attribute-names', 'KmsMasterKeyId', 'SqsManagedSseEnabled') -Region $Region
                $encrypted = $false
                if ($attrData -and (Test-AuditHasProperty -Object $attrData -PropertyName 'Attributes')) {
                    if ($attrData.Attributes.KmsMasterKeyId) { $encrypted = $true }
                    if ([string]$attrData.Attributes.SqsManagedSseEnabled -eq 'true') { $encrypted = $true }
                }
                if ($encrypted) { $encryptedQueues++ } else { $unencryptedQueues++ }
            }
        }

        $snsData = Invoke-AWSCLI -Arguments @('sns', 'list-topics') -Region $Region
        if ($snsData -and (Test-AuditHasProperty -Object $snsData -PropertyName 'Topics')) {
            foreach ($topic in (Get-AuditCliArray $snsData.Topics)) {
                $topicArn = [string](Get-AuditPropertyValue $topic -PropertyNames @('TopicArn'))
                if ([string]::IsNullOrWhiteSpace($topicArn)) { continue }
                $attrData = Invoke-AWSCLI -Arguments @('sns', 'get-topic-attributes', '--topic-arn', $topicArn) -Region $Region
                $encrypted = $false
                if ($attrData -and (Test-AuditHasProperty -Object $attrData -PropertyName 'Attributes') -and $attrData.Attributes.KmsMasterKeyId) {
                    $encrypted = $true
                }
                if ($encrypted) { $encryptedTopics++ } else { $unencryptedTopics++ }
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
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' -Status 'PARTIAL' -Evidence $evidence -Notes 'No SQS queues or SNS topics found in region'
        }

        if ($unencryptedQueues -eq 0 -and $unencryptedTopics -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' -Status 'PASS' -Evidence $evidence -Notes 'All queues and topics are encrypted'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-23' -Status 'FAIL' -Evidence $evidence -Notes 'One or more queues or topics are not encrypted'
    }

    $checks['WRK-24'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $apiData = Invoke-AWSCLI -Arguments @('apigateway', 'get-rest-apis') -Region $Region
        if ($null -eq $apiData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24'
        }

        $apis = @()
        if (Test-AuditHasProperty -Object $apiData -PropertyName 'items') {
            $apis = @(Get-AuditCliArray $apiData.items)
        }

        if ((Get-AuditCollectionCount $apis) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' -Status 'PARTIAL' -Evidence @{ api_count = 0 } -Notes 'No REST APIs found in region'
        }

        $unauthenticatedMethods = 0
        $methodCount = 0

        foreach ($api in $apis) {
            $apiId = [string](Get-AuditPropertyValue $api -PropertyNames @('id', 'Id'))
            if ([string]::IsNullOrWhiteSpace($apiId)) { continue }

            $resourceData = Invoke-AWSCLI -Arguments @('apigateway', 'get-resources', '--rest-api-id', $apiId) -Region $Region
            if ($null -eq $resourceData -or -not (Test-AuditHasProperty -Object $resourceData -PropertyName 'items')) { continue }

            foreach ($resource in (Get-AuditCliArray $resourceData.items)) {
                if (-not (Test-AuditHasProperty -Object $resource -PropertyName 'resourceMethods')) { continue }

                $methodNames = @()
                $resourceMethods = $resource.resourceMethods
                if ($null -ne $resourceMethods) {
                    $methodNames = @($resourceMethods.PSObject.Properties.Name)
                }

                foreach ($methodName in $methodNames) {
                    $methodCount++
                    $resourceId = [string](Get-AuditPropertyValue $resource -PropertyNames @('id', 'Id'))
                    $methodData = Invoke-AWSCLI -Arguments @('apigateway', 'get-method', '--rest-api-id', $apiId, '--resource-id', $resourceId, '--http-method', $methodName) -Region $Region
                    $authType = [string](Get-AuditPropertyValue $methodData -PropertyNames @('authorizationType'))
                    if ($authType -eq 'NONE') { $unauthenticatedMethods++ }
                }
            }
        }

        $evidence = @{
            api_count                    = (Get-AuditCollectionCount $apis)
            method_count                 = $methodCount
            unauthenticated_method_count = $unauthenticatedMethods
        }

        if ($unauthenticatedMethods -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' -Status 'FAIL' -Evidence $evidence -Notes 'Unauthenticated API Gateway methods found (authorizationType NONE)'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-24' -Status 'PASS' -Evidence $evidence -Notes 'No API methods with authorizationType NONE found'
    }

    $checks['WRK-25'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-25' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-WrkWorkshopNotes -ControlId 'WRK-25')
    }

    $checks['WRK-26'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $listData = Invoke-AWSCLI -Arguments @('cognito-idp', 'list-user-pools', '--max-results', '10') -Region $Region
        if ($null -eq $listData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26'
        }

        $pools = @()
        if (Test-AuditHasProperty -Object $listData -PropertyName 'UserPools') {
            $pools = @(Get-AuditCliArray $listData.UserPools)
        }

        if ((Get-AuditCollectionCount $pools) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' -Status 'PARTIAL' -Evidence @{ user_pool_count = 0 } -Notes 'No Cognito user pools found in region'
        }

        $poolEvidence = @()
        $failingPools = 0

        foreach ($pool in $pools) {
            $poolId = [string](Get-AuditPropertyValue $pool -PropertyNames @('Id'))
            if ([string]::IsNullOrWhiteSpace($poolId)) { continue }

            $describeData = Invoke-AWSCLI -Arguments @('cognito-idp', 'describe-user-pool', '--user-pool-id', $poolId) -Region $Region
            $mfaConfig = 'OFF'
            if ($describeData -and (Test-AuditHasProperty -Object $describeData -PropertyName 'UserPool')) {
                $mfaConfig = [string](Get-AuditPropertyValue $describeData.UserPool -PropertyNames @('MfaConfiguration'))
                if ([string]::IsNullOrWhiteSpace($mfaConfig)) { $mfaConfig = 'OFF' }
            }

            $poolEvidence += @{
                pool_id           = $poolId
                pool_name         = [string](Get-AuditPropertyValue $pool -PropertyNames @('Name'))
                mfa_configuration = $mfaConfig
            }

            if ($mfaConfig -eq 'OFF') { $failingPools++ }
        }

        $evidence = @{
            user_pool_count = (Get-AuditCollectionCount $pools)
            failing_pools   = $failingPools
            pools           = @($poolEvidence)
        }

        if ($failingPools -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' -Status 'FAIL' -Evidence $evidence -Notes 'One or more Cognito user pools have MFA disabled'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'WRK-26' -Status 'PASS' -Evidence $evidence -Notes 'Cognito user pools have MFA enabled'
    }

    if ($checks.Count -ne 25) {
        throw ('Get-DomainChecks expected 25 controls (WRK-02..WRK-26) but defined {0}' -f $checks.Count)
    }

    return $checks
}
