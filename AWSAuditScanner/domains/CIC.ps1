$DomainSeverity = @{
    'CIC-01' = 'P0'
    'CIC-02' = 'P0'
    'CIC-03' = 'P0'
    'CIC-04' = 'P0'
    'CIC-06' = 'P0'
    'CIC-07' = 'P0'
    'CIC-08' = 'P1'
    'CIC-09' = 'P0'
    'CIC-10' = 'P1'
    'CIC-11' = 'P1'
    'CIC-12' = 'P1'
    'CIC-13' = 'P0'
    'CIC-14' = 'P0'
    'CIC-15' = 'P0'
    'CIC-16' = 'P1'
    'CIC-17' = 'P0'
    'CIC-18' = 'P1'
    'CIC-19' = 'P0'
}

function Get-CicS3BucketNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'list-buckets') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    $bucketNames = @()
    if (Test-AuditHasProperty -Object $data -PropertyName 'Buckets') {
        foreach ($bucket in (Get-AuditCliArray $data.Buckets)) {
            if (Test-AuditHasProperty -Object $bucket -PropertyName 'Name') {
                $bucketNames += [string]$bucket.Name
            }
        }
    }

    return $bucketNames
}

function Test-CicS3BucketEncrypted {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-encryption', '--bucket', $BucketName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    return ($null -ne $data.ServerSideEncryptionConfiguration)
}

function Test-CicS3BucketPublicAccessBlocked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'get-public-access-block', '--bucket', $BucketName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'PublicAccessBlockConfiguration')) {
        return $false
    }

    $config = $data.PublicAccessBlockConfiguration
    return (($config.BlockPublicAcls -eq $true) -and
            ($config.IgnorePublicAcls -eq $true) -and
            ($config.BlockPublicPolicy -eq $true) -and
            ($config.RestrictPublicBuckets -eq $true))
}

function Test-CicS3BucketVersioningEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-versioning', '--bucket', $BucketName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    if ((Test-AuditHasProperty -Object $data -PropertyName 'Status')) {
        return ([string]$data.Status -eq 'Enabled')
    }

    return $false
}

function Get-CicSsmStringParameterCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ssm', 'describe-parameters') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    $stringCount = 0
    $secureStringCount = 0

    if (Test-AuditHasProperty -Object $data -PropertyName 'Parameters') {
        foreach ($parameter in (Get-AuditCliArray $data.Parameters)) {
            $paramType = [string]$parameter.Type
            if ($paramType -eq 'String') {
                $stringCount++
            }
            if ($paramType -eq 'SecureString') {
                $secureStringCount++
            }
        }
    }

    return @{
        string_count        = $stringCount
        secure_string_count = $secureStringCount
    }
}

function Get-CicActiveAccessKeyCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $userData = Invoke-AWSCLI -Arguments @('iam', 'list-users', '--max-items', '1000') -Region $Region
    if ($null -eq $userData) {
        return $null
    }

    $activeKeyCount = 0
    $usersWithKeys = @()

    if (Test-AuditHasProperty -Object $userData -PropertyName 'Users') {
        foreach ($user in (Get-AuditCliArray $userData.Users)) {
            $userName = [string]$user.UserName
            $keyData = Invoke-AWSCLI -Arguments @('iam', 'list-access-keys', '--user-name', $userName) -Region $Region
            if ($null -eq $keyData) {
                continue
            }

            if (-not (Test-AuditHasProperty -Object $keyData -PropertyName 'AccessKeyMetadata')) {
                continue
            }

            foreach ($key in (Get-AuditCliArray $keyData.AccessKeyMetadata)) {
                if ($key.Status -eq 'Active') {
                    $activeKeyCount++
                    if ((Get-AuditCollectionCount $usersWithKeys) -lt 5) {
                        $usersWithKeys += $userName
                    }
                }
            }
        }
    }

    return @{
        active_access_key_count = $activeKeyCount
        users_with_keys         = @($usersWithKeys)
    }
}

function Get-CicCloudFormationStackCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @(
        'cloudformation', 'list-stacks',
        '--stack-status-filter', 'CREATE_COMPLETE', 'UPDATE_COMPLETE'
    ) -Region $Region

    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'StackSummaries') {
        return (Get-AuditCollectionCount $data.StackSummaries)
    }

    return 0
}


function Get-CicWorkshopNotes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlId
    )

    $notesByControl = @{
        'CIC-01' = 'Verify IaC-only deployment. No untracked console-created resources.'
        'CIC-02' = 'Verify IaC repos versioned via GitLab tags/releases.'
        'CIC-03' = 'Verify merge request process with peer review. Check GitLab branch protection.'
        'CIC-04' = 'Verify separate pipeline definitions for prod vs non-prod.'
        'CIC-07' = 'Verify Checkov/KICS integrated in GitLab CI pipeline.'
        'CIC-08' = 'GitLab Ultimate enforcement planned October 2026. Verify current status.'
        'CIC-11' = 'Verify rollback procedure exists and has been tested.'
        'CIC-13' = 'Verify GitLab repo access controls and merge rights.'
        'CIC-14' = 'Verify main/master branches protected in GitLab.'
        'CIC-15' = 'Manual console changes allowed but tracked via CloudTrail. Verify IaC enforcement policy.'
        'CIC-16' = 'Verify test stage in pipeline (Checkov, KICS, cfn-lint).'
        'CIC-18' = 'Verify periodic review and cleanup of unused GitLab pipelines.'
    }

    if (-not $notesByControl.ContainsKey($ControlId)) {
        throw "Missing workshop notes for control $ControlId"
    }

    return $notesByControl[$ControlId]
}

function Get-DomainChecks {
    $checks = [ordered]@{}

    $checks['CIC-01'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-01' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-01')
    }

    $checks['CIC-02'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-02' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-02')
    }

    $checks['CIC-03'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-03' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-03')
    }

    $checks['CIC-04'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-04' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-04')
    }

    $checks['CIC-06'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $ssmStats = Get-CicSsmStringParameterCount -Region $Region
        $keyStats = Get-CicActiveAccessKeyCount -Region $Region

        if ($null -eq $ssmStats -and $null -eq $keyStats) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-06'
        }

        $stringParamCount = 0
        if ($ssmStats) { $stringParamCount = [int]$ssmStats.string_count }

        $activeKeyCount = 0
        $usersWithKeys = @()
        if ($keyStats) {
            $activeKeyCount = [int]$keyStats.active_access_key_count
            if ($keyStats.users_with_keys) { $usersWithKeys = @($keyStats.users_with_keys) }
        }

        $evidence = @{
            ssm_string_parameter_count = $stringParamCount
            active_access_key_count    = $activeKeyCount
            users_with_keys            = @($usersWithKeys)
        }

        if ($stringParamCount -gt 0 -or $activeKeyCount -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-06' -Status 'FAIL' -Evidence $evidence -Notes 'String SSM parameters or pipeline IAM access keys found'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-06' -Status 'PASS' -Evidence $evidence -Notes 'No String SSM parameters or active IAM access keys found'
    }

    $checks['CIC-07'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-07' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-07')
    }

    $checks['CIC-08'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-08' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-08')
    }

    $checks['CIC-09'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $bucketNames = Get-CicS3BucketNames -Region $Region
        if ($null -eq $bucketNames) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-09'
        }

        $stateBuckets = @()
        foreach ($bucketName in $bucketNames) {
            if ($bucketName.ToLower() -match 'terraform|tfstate') {
                $stateBuckets += $bucketName
            }
        }

        if ((Get-AuditCollectionCount $stateBuckets) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-09' -Status 'PARTIAL' -Evidence @{ state_bucket_count = 0 } -Notes 'No Terraform state bucket found by naming (may use CloudFormation)'
        }

        $bucketEvidence = @()
        $allPass = $true

        foreach ($bucketName in $stateBuckets) {
            $encrypted = Test-CicS3BucketEncrypted -Region $Region -BucketName $bucketName
            $private = Test-CicS3BucketPublicAccessBlocked -Region $Region -BucketName $bucketName
            $versioned = Test-CicS3BucketVersioningEnabled -Region $Region -BucketName $bucketName

            $bucketEvidence += @{
                bucket_name    = $bucketName
                encrypted      = $encrypted
                public_blocked = $private
                versioning     = $versioned
            }

            if (-not ($encrypted -and $private -and $versioned)) { $allPass = $false }
        }

        $evidence = @{
            state_bucket_count = (Get-AuditCollectionCount $stateBuckets)
            buckets            = @($bucketEvidence)
        }

        if ($allPass) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-09' -Status 'PASS' -Evidence $evidence -Notes 'Terraform state bucket encrypted, private, and versioned'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-09' -Status 'FAIL' -Evidence $evidence -Notes 'Terraform state bucket missing encryption, public access blocks, or versioning'
    }

    $checks['CIC-10'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $endTime = (Get-Date).ToUniversalTime().ToString('o')
        $startTime = (Get-Date).AddDays(-30).ToUniversalTime().ToString('o')

        $data = Invoke-AWSCLI -Arguments @(
            'cloudtrail', 'lookup-events',
            '--lookup-attributes', 'AttributeKey=EventSource,AttributeValue=cloudformation.amazonaws.com',
            '--start-time', $startTime,
            '--end-time', $endTime,
            '--max-results', '50'
        ) -Region $Region

        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-10'
        }

        $eventCount = 0
        $lastEventTime = $null
        if (Test-AuditHasProperty -Object $data -PropertyName 'Events') {
            $events = @(Get-AuditCliArray $data.Events)
            $eventCount = (Get-AuditCollectionCount $events)
            if ($eventCount -gt 0) {
                $lastEventTime = [string](Get-AuditPropertyValue $events[0] -PropertyNames @('EventTime'))
            }
        }

        $evidence = @{
            cloudformation_event_count_last_30_days = $eventCount
            last_event_time                         = $lastEventTime
        }

        if ($eventCount -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-10' -Status 'PASS' -Evidence $evidence -Notes 'CloudFormation events visible in CloudTrail'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-10' -Status 'FAIL' -Evidence $evidence -Notes 'No CloudFormation events found in CloudTrail sample'
    }

    $checks['CIC-11'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-11' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-11')
    }

    $checks['CIC-12'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $statusData = Invoke-AWSCLI -Arguments @('config', 'describe-configuration-recorder-status') -Region $Region
        if ($null -eq $statusData) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-12'
        }

        $recorderActive = $false
        $recorderNames = @()

        if (Test-AuditHasProperty -Object $statusData -PropertyName 'ConfigurationRecordersStatus') {
            foreach ($status in (Get-AuditCliArray $statusData.ConfigurationRecordersStatus)) {
                $name = [string](Get-AuditPropertyValue $status -PropertyNames @('name'))
                if (-not [string]::IsNullOrWhiteSpace($name)) { $recorderNames += $name }
                if ((Test-AuditHasProperty -Object $status -PropertyName 'recording') -and ($status.recording -eq $true)) {
                    $recorderActive = $true
                }
            }
        }

        $evidence = @{ recorder_active = $recorderActive; recorder_names = @($recorderNames) }

        if ($recorderActive) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-12' -Status 'PASS' -Evidence $evidence -Notes 'AWS Config recorder is active'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-12' -Status 'FAIL' -Evidence $evidence -Notes 'AWS Config recorder is not active'
    }

    $checks['CIC-13'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-13' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-13')
    }

    $checks['CIC-14'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-14' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-14')
    }

    $checks['CIC-15'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-15' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-15')
    }

    $checks['CIC-16'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-16' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-16')
    }

    $checks['CIC-17'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $data = Invoke-AWSCLI -Arguments @('logs', 'describe-log-groups') -Region $Region
        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-17'
        }

        $pipelineGroups = @()
        $groupsWithoutRetention = @()

        if (Test-AuditHasProperty -Object $data -PropertyName 'logGroups') {
            foreach ($logGroup in (Get-AuditCliArray $data.logGroups)) {
                $name = [string](Get-AuditPropertyValue $logGroup -PropertyNames @('logGroupName'))
                $lowerName = $name.ToLower()
                if ($lowerName -notmatch 'pipeline|codebuild|codepipeline') { continue }

                $retention = $null
                if (Test-AuditHasProperty -Object $logGroup -PropertyName 'retentionInDays') {
                    $retention = $logGroup.retentionInDays
                }

                $pipelineGroups += @{ log_group_name = $name; retention_in_days = $retention }

                if ($null -eq $retention) {
                    if ((Get-AuditCollectionCount $groupsWithoutRetention) -lt 5) { $groupsWithoutRetention += $name }
                }
            }
        }

        $evidence = @{
            pipeline_log_group_count = (Get-AuditCollectionCount $pipelineGroups)
            pipeline_log_groups      = @($pipelineGroups)
            groups_without_retention = @($groupsWithoutRetention)
        }

        if ((Get-AuditCollectionCount $pipelineGroups) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-17' -Status 'FAIL' -Evidence $evidence -Notes 'No pipeline-related CloudWatch log groups found'
        }

        if ((Get-AuditCollectionCount $groupsWithoutRetention) -eq 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-17' -Status 'PASS' -Evidence $evidence -Notes 'Pipeline log groups found with retention configured'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-17' -Status 'FAIL' -Evidence $evidence -Notes 'Pipeline log groups found without retention configured'
    }

    $checks['CIC-18'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)
        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-18' -Status 'NOT_TESTED' -Evidence $null -Notes (Get-CicWorkshopNotes -ControlId 'CIC-18')
    }

    $checks['CIC-19'] = {
        param([string]$AccountId, [string]$AccountName, [string]$Region)

        $endTime = (Get-Date).ToUniversalTime().ToString('o')
        $startTime = (Get-Date).AddDays(-30).ToUniversalTime().ToString('o')

        $data = Invoke-AWSCLI -Arguments @(
            'cloudtrail', 'lookup-events',
            '--lookup-attributes', 'AttributeKey=EventSource,AttributeValue=codepipeline.amazonaws.com',
            '--start-time', $startTime,
            '--end-time', $endTime,
            '--max-results', '50'
        ) -Region $Region

        if ($null -eq $data) {
            return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-19'
        }

        $eventCount = 0
        if (Test-AuditHasProperty -Object $data -PropertyName 'Events') {
            $eventCount = (Get-AuditCollectionCount (Get-AuditCliArray $data.Events))
        }

        $evidence = @{ pipeline_event_count_last_30_days = $eventCount }

        if ($eventCount -gt 0) {
            return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-19' -Status 'PASS' -Evidence $evidence -Notes 'CodePipeline events visible in CloudTrail'
        }

        return New-AuditResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'CIC-19' -Status 'FAIL' -Evidence $evidence -Notes 'No CodePipeline events found in CloudTrail sample'
    }

    if ($checks.Count -ne 18) {
        throw ('Get-DomainChecks expected 18 controls (CIC-01..CIC-19, no CIC-05) but defined {0}' -f $checks.Count)
    }

    return $checks
}
