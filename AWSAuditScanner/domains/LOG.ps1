$DomainSeverity = @{
    'LOG-01' = 'P0'
    'LOG-02' = 'P0'
    'LOG-03' = 'P0'
    'LOG-04' = 'P1'
    'LOG-05' = 'P1'
    'LOG-06' = 'P1'
    'LOG-07' = 'P1'
    'LOG-08' = 'P1'
    'LOG-09' = 'P2'
    'LOG-10' = 'P1'
    'LOG-11' = 'P1'
    'LOG-12' = 'P0'
    'LOG-13' = 'P1'
    'LOG-14' = 'P0'
    'LOG-15' = 'P1'
    'LOG-16' = 'P1'
    'LOG-17' = 'P1'
    'LOG-18' = 'P1'
    'LOG-19' = 'P1'
    'LOG-20' = 'P2'
    'LOG-21' = 'P1'
    'LOG-22' = 'P1'
}

function Get-LogCloudTrails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('cloudtrail', 'describe-trails', '--include-shadow-trails') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-AuditHasProperty -Object $data -PropertyName 'trailList') {
        return (Get-AuditCliArray $data.trailList)
    }

    return @()
}

function Get-LogTrailStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$TrailName
    )

    return Invoke-AWSCLI -Arguments @('cloudtrail', 'get-trail-status', '--name', $TrailName) -Region $Region
}

function Get-LogOrganizationTrail {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Trails
    )

    foreach ($trail in $Trails) {
        if ($trail.IsOrganizationTrail -eq $true) {
            return $trail
        }
    }

    return $null
}

function Get-LogTrailIdentifier {
    param(
        [Parameter(Mandatory = $true)]
        $Trail
    )

    if (Test-AuditHasProperty -Object $Trail -PropertyName 'TrailARN') {
        return [string]$Trail.TrailARN
    }

    if (Test-AuditHasProperty -Object $Trail -PropertyName 'Name') {
        return [string]$Trail.Name
    }

    return $null
}

function Get-LogCloudTrailLogGroupName {
    param(
        [Parameter(Mandatory = $true)]
        $Trail
    )

    if (-not (Test-AuditHasProperty -Object $Trail -PropertyName 'CloudWatchLogsLogGroupArn')) {
        return $null
    }

    $arn = [string]$Trail.CloudWatchLogsLogGroupArn
    if ($arn -match 'log-group:([^:*]+)') {
        return $Matches[1]
    }

    return $null
}

function Test-LogS3BucketSseKms {
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

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'ServerSideEncryptionConfiguration')) {
        return $false
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'ServerSideEncryptionConfiguration').Rules) {
        return $false
    }

    foreach ($rule in $data.ServerSideEncryptionConfiguration.Rules) {
        if (Test-AuditHasProperty -Object $rule -PropertyName 'ApplyServerSideEncryptionByDefault') {
            $algorithm = [string]$rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
            if ($algorithm -eq 'aws:kms') {
                return $true
            }
        }
    }

    return $false
}

function Test-LogS3BucketPublicAccessBlocked {
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

function Test-LogS3BucketVersioningEnabled {
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

function Test-LogBucketPolicyPublicRead {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-policy', '--bucket', $BucketName) -Region $Region
    if ($null -eq $data) {
        return $false
    }

    if (-not (Test-AuditHasProperty -Object $data -PropertyName 'Policy')) {
        return $false
    }

    $policyText = [string]$data.Policy
    if ($policyText -match '"Principal"\s*:\s*"\*"' -and $policyText -match 's3:GetObject' -and $policyText -match '"Effect"\s*:\s*"Allow"') {
        return $true
    }

    return $false
}

function Get-LogCisMetricPatternDefinitions {
    return @(
        @{ Id = 'CIS-3.1'; Match = 'UnauthorizedOperation|AccessDenied\*|\$\.errorCode' }
        @{ Id = 'CIS-3.2'; Match = 'ConsoleLogin|MFAUsed' }
        @{ Id = 'CIS-3.3'; Match = 'Root|\$\.userIdentity\.type' }
        @{ Id = 'CIS-3.4'; Match = 'PutGroupPolicy|PutRolePolicy|PutUserPolicy|AttachGroupPolicy|AttachRolePolicy|AttachUserPolicy|DeleteGroupPolicy|DeleteRolePolicy|DeleteUserPolicy|DetachGroupPolicy|DetachRolePolicy|DetachUserPolicy' }
        @{ Id = 'CIS-3.5'; Match = 'CreateTrail|UpdateTrail|DeleteTrail|StartLogging|StopLogging' }
        @{ Id = 'CIS-3.6'; Match = 'ConsoleLogin|Failed authentication|errorMessage' }
        @{ Id = 'CIS-3.7'; Match = 'DisableKey|ScheduleKeyDeletion' }
        @{ Id = 'CIS-3.8'; Match = 'PutBucketPolicy|DeleteBucketPolicy|PutBucketAcl|PutObjectAcl' }
        @{ Id = 'CIS-3.9'; Match = 'PutConfigurationRecorder|DeleteDeliveryChannel|StopConfigurationRecorder' }
        @{ Id = 'CIS-3.10'; Match = 'AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress|RevokeSecurityGroupIngress|RevokeSecurityGroupEgress|CreateSecurityGroup|DeleteSecurityGroup' }
        @{ Id = 'CIS-3.11'; Match = 'CreateNetworkAcl|DeleteNetworkAcl|CreateNetworkAclEntry|DeleteNetworkAclEntry|ReplaceNetworkAclEntry' }
        @{ Id = 'CIS-3.12'; Match = 'CreateCustomerGateway|DeleteCustomerGateway|AttachInternetGateway|CreateInternetGateway|DeleteInternetGateway|DetachInternetGateway' }
        @{ Id = 'CIS-3.13'; Match = 'CreateRoute|DeleteRoute|ReplaceRoute|AssociateRouteTable|DisassociateRouteTable' }
        @{ Id = 'CIS-3.14'; Match = 'CreateVpc|DeleteVpc|ModifyVpcAttribute' }
    )
}

function Get-LogCisMetricFilterAssessment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$LogGroupName
    )

    $filterData = Invoke-AWSCLI -Arguments @('logs', 'describe-metric-filters', '--log-group-name', $LogGroupName) -Region $Region
    if ($null -eq $filterData) {
        return $null
    }

    $filterPatterns = @()
    if (Test-AuditHasProperty -Object $filterData -PropertyName 'metricFilters') {
        foreach ($filter in (Get-AuditCliArray $filterData.metricFilters)) {
            if (Test-AuditHasProperty -Object $filter -PropertyName 'filterPattern') {
                $filterPatterns += [string]$filter.filterPattern
            }
        }
    }

    $definitions = Get-LogCisMetricPatternDefinitions
    $matched = @()
    $missing = @()

    foreach ($definition in $definitions) {
        $found = $false
        foreach ($pattern in $filterPatterns) {
            if ($pattern -match $definition.Match) {
                $found = $true
                break
            }
        }

        if ($found) {
            $matched += $definition.Id
        }
        else {
            $missing += $definition.Id
        }
    }

    return @{
        matched_patterns = @($matched)
        missing_patterns   = @($missing)
        matched_count      = (Get-AuditCollectionCount $matched)
        missing_count      = (Get-AuditCollectionCount $missing)
        filter_count       = (Get-AuditCollectionCount $filterPatterns)
    }
}

function Get-DomainChecks {
    return [ordered]@{
        'LOG-01' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-01'
            }

            if ((Get-AuditCollectionCount $trails) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-01' `
                    -Status 'FAIL' -Evidence @{ trail_count = 0 } -Notes 'No CloudTrail trails found'
            }

            $activeTrails = @()
            foreach ($trail in $trails) {
                $trailId = Get-LogTrailIdentifier -Trail $trail
                if (-not $trailId) { continue }

                $status = Get-LogTrailStatus -Region $Region -TrailName $trailId
                $isLogging = $false
                if ($status -and $status.IsLogging -eq $true) {
                    $isLogging = $true
                }

                if ($isLogging) {
                    $activeTrails += @{
                        name        = [string]$trail.Name
                        is_logging  = $true
                        home_region = [string]$trail.HomeRegion
                    }
                }
            }

            $evidence = @{
                trail_count   = (Get-AuditCollectionCount $trails)
                active_trails = @($activeTrails)
            }

            if ((Get-AuditCollectionCount $activeTrails) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-01' `
                    -Status 'PASS' -Evidence $evidence -Notes 'At least one CloudTrail trail has IsLogging=true'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-01' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No trails with IsLogging=true'
        }

        'LOG-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-02'
            }

            $matchingTrails = @()
            foreach ($trail in $trails) {
                if ($trail.IsMultiRegionTrail -eq $true -and $trail.IsOrganizationTrail -eq $true) {
                    $matchingTrails += @{
                        name                   = [string]$trail.Name
                        is_multi_region_trail  = $true
                        is_organization_trail  = $true
                    }
                }
            }

            $evidence = @{
                matching_trail_count = (Get-AuditCollectionCount $matchingTrails)
                trails               = @($matchingTrails)
            }

            if ((Get-AuditCollectionCount $matchingTrails) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-02' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Multi-region organization CloudTrail trail found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-02' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No multi-region organization CloudTrail trail found'
        }

        'LOG-03' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-03'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                if ((Get-AuditCollectionCount $trails) -gt 0) {
                    $orgTrail = $trails[0]
                }
            }

            if (-not $orgTrail) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-03' `
                    -Status 'FAIL' -Evidence $null -Notes 'No CloudTrail trail available for event selector review'
            }

            $trailId = Get-LogTrailIdentifier -Trail $orgTrail
            $selectorData = Invoke-AWSCLI -Arguments @('cloudtrail', 'get-event-selectors', '--trail-name', $trailId) -Region $Region
            if ($null -eq $selectorData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-03'
            }

            $passFound = $false
            $selectorEvidence = @()
            if (Test-AuditHasProperty -Object $selectorData -PropertyName 'EventSelectors') {
                foreach ($selector in (Get-AuditCliArray $selectorData.EventSelectors)) {
                    $readWriteType = [string]$selector.ReadWriteType
                    $includeManagement = ($selector.IncludeManagementEvents -eq $true)
                    $selectorEvidence += @{
                        read_write_type           = $readWriteType
                        include_management_events = $includeManagement
                    }

                    if ($includeManagement -and $readWriteType -eq 'All') {
                        $passFound = $true
                    }
                }
            }

            $evidence = @{
                trail_name       = [string]$orgTrail.Name
                event_selectors  = @($selectorEvidence)
            }

            if ($passFound) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-03' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Management events included with ReadWriteType=All'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-03' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Management events not fully configured (ReadWriteType=All required)'
        }

        'LOG-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-04'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail -and (Get-AuditCollectionCount $trails) -gt 0) {
                $orgTrail = $trails[0]
            }

            if (-not $orgTrail) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-04' `
                    -Status 'FAIL' -Evidence $null -Notes 'No CloudTrail trail available for data event review'
            }

            $trailId = Get-LogTrailIdentifier -Trail $orgTrail
            $selectorData = Invoke-AWSCLI -Arguments @('cloudtrail', 'get-event-selectors', '--trail-name', $trailId) -Region $Region
            if ($null -eq $selectorData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-04'
            }

            $s3DataResources = @()
            if (Test-AuditHasProperty -Object $selectorData -PropertyName 'EventSelectors') {
                foreach ($selector in (Get-AuditCliArray $selectorData.EventSelectors)) {
                    if (Test-AuditHasProperty -Object $selector -PropertyName 'DataResources') {
                        foreach ($resource in (Get-AuditCliArray $selector.DataResources)) {
                            if ([string]$resource.Type -eq 'AWS::S3::Object') {
                                $values = @()
                                if (Test-AuditHasProperty -Object $resource -PropertyName 'Values') {
                                    $values = @($resource.Values)
                                }
                                $s3DataResources += @{
                                    type   = [string]$resource.Type
                                    values = @($values)
                                }
                            }
                        }
                    }
                }
            }

            $evidence = @{
                trail_name          = [string]$orgTrail.Name
                s3_data_resources   = @($s3DataResources)
                s3_data_resource_count = (Get-AuditCollectionCount $s3DataResources)
            }

            if ((Get-AuditCollectionCount $s3DataResources) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-04' `
                    -Status 'PASS' -Evidence $evidence -Notes 'S3 data events configured on CloudTrail'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-04' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No S3 data events configured'
        }

        'LOG-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-05'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-05' `
                    -Status 'FAIL' -Evidence $null -Notes 'No organization CloudTrail trail found'
            }

            $validationEnabled = ($orgTrail.LogFileValidationEnabled -eq $true)
            $evidence = @{
                trail_name                  = [string]$orgTrail.Name
                log_file_validation_enabled = $validationEnabled
            }

            if ($validationEnabled) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-05' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Log file validation enabled on organization trail'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-05' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Log file validation disabled on organization trail'
        }

        'LOG-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-06'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-06' `
                    -Status 'FAIL' -Evidence $null -Notes 'No organization CloudTrail trail found'
            }

            $kmsKeyId = $null
            if (Test-AuditHasProperty -Object $orgTrail -PropertyName 'KMSKeyId') {
                $kmsKeyId = [string]$orgTrail.KMSKeyId
            }

            $evidence = @{
                trail_name = [string]$orgTrail.Name
                kms_key_id = $kmsKeyId
            }

            if (-not [string]::IsNullOrWhiteSpace($kmsKeyId)) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-06' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Organization CloudTrail encrypted with CMK'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-06' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Organization CloudTrail KMSKeyId is null (known gap FND-058)'
        }

        'LOG-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-07'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                if ((Get-AuditCollectionCount $trails) -gt 0) {
                    $orgTrail = $trails[0]
                }
            }

            if (-not $orgTrail -or -not (Test-AuditHasProperty -Object $orgTrail -PropertyName 'S3BucketName')) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-07' `
                    -Status 'FAIL' -Evidence $null -Notes 'No CloudTrail log bucket configured'
            }

            $bucketName = [string]$orgTrail.S3BucketName
            $sseKms = Test-LogS3BucketSseKms -Region $Region -BucketName $bucketName
            $publicBlocked = Test-LogS3BucketPublicAccessBlocked -Region $Region -BucketName $bucketName
            $versioning = Test-LogS3BucketVersioningEnabled -Region $Region -BucketName $bucketName

            $evidence = @{
                bucket_name     = $bucketName
                sse_kms         = $sseKms
                public_blocked  = $publicBlocked
                versioning      = $versioning
            }

            if ($sseKms -and $publicBlocked -and $versioning) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-07' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Log bucket hardened with SSE-KMS, public access blocks, and versioning'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-07' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Log bucket missing one or more hardening controls'
        }

        'LOG-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-08'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                if ((Get-AuditCollectionCount $trails) -gt 0) {
                    $orgTrail = $trails[0]
                }
            }

            if (-not $orgTrail -or -not (Test-AuditHasProperty -Object $orgTrail -PropertyName 'S3BucketName')) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-08' `
                    -Status 'FAIL' -Evidence $null -Notes 'No CloudTrail log bucket configured'
            }

            $bucketName = [string]$orgTrail.S3BucketName
            $lockData = Invoke-AWSCLI -Arguments @('s3api', 'get-object-lock-configuration', '--bucket', $bucketName) -Region $Region
            if ($null -eq $lockData) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-08' `
                    -Status 'FAIL' -Evidence @{ bucket_name = $bucketName; object_lock_enabled = $false } `
                    -Notes 'Object Lock not enabled on log bucket'
            }

            $enabled = $false
            $mode = $null
            $retention = $null

            if (Test-AuditHasProperty -Object $lockData -PropertyName 'ObjectLockConfiguration') {
                if ($lockData.ObjectLockConfiguration.ObjectLockEnabled) {
                    $enabled = ([string]$lockData.ObjectLockConfiguration.ObjectLockEnabled -eq 'Enabled')
                }
                if ($lockData.ObjectLockConfiguration.Rule -and $lockData.ObjectLockConfiguration.Rule.DefaultRetention) {
                    $mode = [string]$lockData.ObjectLockConfiguration.Rule.DefaultRetention.Mode
                    if ($lockData.ObjectLockConfiguration.Rule.DefaultRetention.Days) {
                        $retention = [string]$lockData.ObjectLockConfiguration.Rule.DefaultRetention.Days
                    }
                }
            }

            $evidence = @{
                bucket_name         = $bucketName
                object_lock_enabled = $enabled
                mode                = $mode
                retention_days      = $retention
            }

            if ($enabled -and ($mode -eq 'COMPLIANCE' -or $mode -eq 'GOVERNANCE')) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-08' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Object Lock enabled on log bucket'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-08' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Object Lock not enabled on log bucket'
        }

        'LOG-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('logs', 'describe-log-groups') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-09'
            }

            $logGroups = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'logGroups') {
                $logGroups = @($data.logGroups)
            }

            $nullRetentionCount = 0
            $nullRetentionNames = @()

            foreach ($logGroup in $logGroups) {
                $hasRetention = $false
                if ((Test-AuditHasProperty -Object $logGroup -PropertyName 'retentionInDays')) {
                    if ($null -ne $logGroup.retentionInDays) {
                        $hasRetention = $true
                    }
                }

                if (-not $hasRetention) {
                    $nullRetentionCount++
                    if ((Get-AuditCollectionCount $nullRetentionNames) -lt 5) {
                        $nullRetentionNames += [string]$logGroup.logGroupName
                    }
                }
            }

            $evidence = @{
                log_group_count        = (Get-AuditCollectionCount $logGroups)
                null_retention_count   = $nullRetentionCount
                null_retention_names   = @($nullRetentionNames)
            }

            if ($nullRetentionCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-09' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All log groups have retention configured'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-09' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more log groups have null retention'
        }

        'LOG-10' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('logs', 'describe-log-groups') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-10'
            }

            $cloudTrailGroups = @()
            $flowLogGroups = @()

            if (Test-AuditHasProperty -Object $data -PropertyName 'logGroups') {
                foreach ($logGroup in (Get-AuditCliArray $data.logGroups)) {
                    $name = [string]$logGroup.logGroupName
                    $lowerName = $name.ToLower()
                    if ($lowerName -match 'cloudtrail|aws-cloudtrail') {
                        $cloudTrailGroups += $name
                    }
                    if ($lowerName -match 'flow|vpc') {
                        $flowLogGroups += $name
                    }
                }
            }

            $evidence = @{
                cloudtrail_log_groups = @($cloudTrailGroups)
                flow_log_groups       = @($flowLogGroups)
            }

            if ((Get-AuditCollectionCount $cloudTrailGroups) -gt 0 -and (Get-AuditCollectionCount $flowLogGroups) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-10' `
                    -Status 'PASS' -Evidence $evidence -Notes 'CloudTrail and VPC Flow Logs log groups found'
            }

            if ((Get-AuditCollectionCount $cloudTrailGroups) -gt 0 -or (Get-AuditCollectionCount $flowLogGroups) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-10' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Only CloudTrail or VPC Flow Logs log group found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-10' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No critical log groups found'
        }

        'LOG-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-11'
            }

            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if (-not $orgTrail) {
                if ((Get-AuditCollectionCount $trails) -gt 0) {
                    $orgTrail = $trails[0]
                }
            }

            if (-not $orgTrail -or -not (Test-AuditHasProperty -Object $orgTrail -PropertyName 'S3BucketName')) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-11' `
                    -Status 'FAIL' -Evidence $null -Notes 'No CloudTrail log bucket configured'
            }

            $bucketName = [string]$orgTrail.S3BucketName
            $publicRead = Test-LogBucketPolicyPublicRead -Region $Region -BucketName $bucketName

            $evidence = @{
                bucket_name        = $bucketName
                public_read_allow  = $publicRead
            }

            if ($publicRead) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-11' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Public read access allowed on log bucket policy'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-11' `
                -Status 'PASS' -Evidence $evidence -Notes 'No public read access found on log bucket policy'
        }

        'LOG-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $vpcData = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpcs') -Region $Region
            $flowData = Invoke-AWSCLI -Arguments @('ec2', 'describe-flow-logs') -Region $Region

            if ($null -eq $vpcData -or $null -eq $flowData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-12'
            }

            $vpcs = @()
            if (Test-AuditHasProperty -Object $vpcData -PropertyName 'Vpcs') {
                $vpcs = @($vpcData.Vpcs)
            }

            $flowLogs = @()
            if (Test-AuditHasProperty -Object $flowData -PropertyName 'FlowLogs') {
                $flowLogs = @($flowData.FlowLogs)
            }

            $vpcWithAllFlowLogs = @{}
            $vpcWithPartialFlowLogs = @{}
            foreach ($flowLog in $flowLogs) {
                if ($flowLog.FlowLogStatus -ne 'ACTIVE') {
                    continue
                }

                if (-not (Test-AuditHasProperty -Object $flowLog -PropertyName 'ResourceId')) {
                    continue
                }

                $resourceId = [string]$flowLog.ResourceId
                $trafficType = [string]$flowLog.TrafficType
                if ($trafficType -eq 'ALL') {
                    $vpcWithAllFlowLogs[$resourceId] = $true
                }
                else {
                    $vpcWithPartialFlowLogs[$resourceId] = $trafficType
                }
            }

            $missingVpcIds = @()
            $partialVpcIds = @()
            foreach ($vpc in $vpcs) {
                $vpcId = [string]$vpc.VpcId
                if ($vpcWithAllFlowLogs.ContainsKey($vpcId)) {
                    continue
                }

                if ($vpcWithPartialFlowLogs.ContainsKey($vpcId)) {
                    if ((Get-AuditCollectionCount $partialVpcIds) -lt 10) {
                        $partialVpcIds += $vpcId
                    }
                    continue
                }

                if ((Get-AuditCollectionCount $missingVpcIds) -lt 10) {
                    $missingVpcIds += $vpcId
                }
            }

            $evidence = @{
                vpc_count                 = (Get-AuditCollectionCount $vpcs)
                vpcs_with_all_flow_logs   = (Get-AuditCollectionCount $vpcWithAllFlowLogs)
                missing_vpc_ids           = @($missingVpcIds)
                partial_traffic_vpc_ids   = @($partialVpcIds)
            }

            if ((Get-AuditCollectionCount $missingVpcIds) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-12' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more VPCs missing active Flow Logs'
            }

            if ((Get-AuditCollectionCount $partialVpcIds) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-12' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Flow Logs exist but TrafficType is not ALL on some VPCs'
            }

            if ((Get-AuditCollectionCount $vpcs) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-12' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No VPCs found in region'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-12' `
                -Status 'PASS' -Evidence $evidence -Notes 'All VPCs have active Flow Logs with TrafficType=ALL'
        }

        'LOG-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $lbData = Invoke-AWSCLI -Arguments @('elbv2', 'describe-load-balancers') -Region $Region
            if ($null -eq $lbData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-13'
            }

            $loadBalancers = @()
            if (Test-AuditHasProperty -Object $lbData -PropertyName 'LoadBalancers') {
                $loadBalancers = @($lbData.LoadBalancers)
            }

            if ((Get-AuditCollectionCount $loadBalancers) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-13' `
                    -Status 'PARTIAL' -Evidence @{ alb_count = 0 } -Notes 'No ALBs found in region'
            }

            $withAccessLogs = 0
            $withoutAccessLogs = @()

            foreach ($loadBalancer in $loadBalancers) {
                if (-not (Test-AuditHasProperty -Object $loadBalancer -PropertyName 'LoadBalancerArn')) {
                    continue
                }

                $attrData = Invoke-AWSCLI -Arguments @(
                    'elbv2', 'describe-load-balancer-attributes',
                    '--load-balancer-arn', $loadBalancer.LoadBalancerArn
                ) -Region $Region

                if ($null -eq $attrData) {
                    if ((Get-AuditCollectionCount $withoutAccessLogs) -lt 5) {
                        $withoutAccessLogs += [string]$loadBalancer.LoadBalancerName
                    }
                    continue
                }

                $enabled = $false
                if (Test-AuditHasProperty -Object $attrData -PropertyName 'Attributes') {
                    foreach ($attribute in (Get-AuditCliArray $attrData.Attributes)) {
                        if ($attribute.Key -eq 'access_logs.s3.enabled' -and $attribute.Value -eq 'true') {
                            $enabled = $true
                            break
                        }
                    }
                }

                if ($enabled) {
                    $withAccessLogs++
                }
                else {
                    if ((Get-AuditCollectionCount $withoutAccessLogs) -lt 5) {
                        $withoutAccessLogs += [string]$loadBalancer.LoadBalancerName
                    }
                }
            }

            $evidence = @{
                alb_count              = (Get-AuditCollectionCount $loadBalancers)
                alb_with_access_logs = $withAccessLogs
                alb_without_access_logs = @($withoutAccessLogs)
            }

            if ((Get-AuditCollectionCount $withoutAccessLogs) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-13' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more ALBs missing access logs'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-13' `
                -Status 'PASS' -Evidence $evidence -Notes 'All ALBs have access logs enabled'
        }

        'LOG-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $rulesData = Invoke-AWSCLI -Arguments @('events', 'list-rules') -Region $Region
            $alarmsData = Invoke-AWSCLI -Arguments @('cloudwatch', 'describe-alarms') -Region $Region

            if ($null -eq $rulesData -and $null -eq $alarmsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-14'
            }

            $iamPatterns = 'CreateUser|DeleteUser|ConsoleLogin|CreateAccessKey|Root|iam\.amazonaws\.com'
            $matchingRules = @()
            $matchingAlarms = @()

            if ($rulesData -and $rulesData.Rules) {
                foreach ($rule in (Get-AuditCliArray $rulesData.Rules)) {
                    $ruleName = [string]$rule.Name
                    $eventPattern = [string](Get-AuditPropertyValue $rule -PropertyNames @('EventPattern'))
                    if ($eventPattern -match $iamPatterns -or $ruleName -match 'IAM|Root|ConsoleLogin') {
                        $matchingRules += $ruleName
                    }
                }
            }

            if ($alarmsData -and $alarmsData.MetricAlarms) {
                foreach ($alarm in (Get-AuditCliArray $alarmsData.MetricAlarms)) {
                    $alarmName = [string]$alarm.AlarmName
                    if ($alarmName -match 'IAM|Root|ConsoleLogin|CreateUser|DeleteUser|CreateAccessKey') {
                        $matchingAlarms += $alarmName
                    }
                }
            }

            $evidence = @{
                matching_rule_names  = @($matchingRules)
                matching_alarm_names = @($matchingAlarms)
            }

            if ((Get-AuditCollectionCount $matchingRules) -gt 0 -or (Get-AuditCollectionCount $matchingAlarms) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-14' `
                    -Status 'PASS' -Evidence $evidence -Notes 'IAM alerting rules or alarms found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-14' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No IAM alerting rules or alarms found'
        }

        'LOG-15' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15'
            }

            $logGroupName = $null
            foreach ($trail in $trails) {
                $logGroupName = Get-LogCloudTrailLogGroupName -Trail $trail
                if ($logGroupName) {
                    break
                }
            }

            if (-not $logGroupName) {
                $logGroupData = Invoke-AWSCLI -Arguments @('logs', 'describe-log-groups') -Region $Region
                if ($logGroupData -and $logGroupData.logGroups) {
                    foreach ($logGroup in (Get-AuditCliArray $logGroupData.logGroups)) {
                        $name = [string]$logGroup.logGroupName
                        if ($name -match 'CloudTrail|cloudtrail') {
                            $logGroupName = $name
                            break
                        }
                    }
                }
            }

            if (-not $logGroupName) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15' `
                    -Status 'FAIL' -Evidence $null -Notes 'CloudTrail log group not found'
            }

            $assessment = Get-LogCisMetricFilterAssessment -Region $Region -LogGroupName $logGroupName
            if ($null -eq $assessment) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15'
            }

            $evidence = @{
                log_group_name    = $logGroupName
                matched_count     = $assessment.matched_count
                missing_patterns  = @($assessment.missing_patterns)
                matched_patterns  = @($assessment.matched_patterns)
            }

            if ($assessment.matched_count -ge 10) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Ten or more CIS metric filter patterns matched'
            }

            if ($assessment.matched_count -ge 5) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Five to nine CIS metric filter patterns matched'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-15' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Fewer than five CIS metric filter patterns matched'
        }

        'LOG-16' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-16' `
                -Notes 'Verify analysts can query CloudTrail via Athena, CloudTrail Lake, or QRadar. Check investigation time SLA.'
        }

        'LOG-17' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-17' `
                -Notes 'Verify log freeze procedure exists for incident evidence preservation. Check forensics policy.'
        }

        'LOG-18' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-18' `
                -Notes 'Verify SOC runbooks reference CloudTrail, VPC Flow Logs, WAF for incident investigation. Check DEX.'
        }

        'LOG-19' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-19' `
                -Notes 'Verify periodic tests confirm alarms trigger correctly. Ask for last test date and results.'
        }

        'LOG-20' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-20'
            }

            $bucketNames = @()
            $prefixes = @()
            foreach ($trail in $trails) {
                if (Test-AuditHasProperty -Object $trail -PropertyName 'S3BucketName') {
                    $bucket = [string]$trail.S3BucketName
                    if ($bucketNames -notcontains $bucket) {
                        $bucketNames += $bucket
                    }
                }
                if (Test-AuditHasProperty -Object $trail -PropertyName 'S3KeyPrefix') {
                    $prefix = [string]$trail.S3KeyPrefix
                    if ($prefixes -notcontains $prefix) {
                        $prefixes += $prefix
                    }
                }
            }

            $accountLower = $AccountName.ToLower()
            $isProd = ($accountLower -match 'prod')
            $isNonProd = ($accountLower -match 'dev|test|uat|sandbox|nonprod|non-prod|shared')

            $evidence = @{
                account_name  = $AccountName
                bucket_names  = @($bucketNames)
                s3_prefixes   = @($prefixes)
                appears_prod  = $isProd
                appears_nonprod = $isNonProd
            }

            if ((Get-AuditCollectionCount $bucketNames) -gt 1) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-20' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Distinct CloudTrail log buckets found in account'
            }

            if ((Get-AuditCollectionCount $bucketNames) -eq 1 -and (Get-AuditCollectionCount $prefixes) -gt 1) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-20' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Same bucket with different prefixes may separate environments'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-20' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'Cross-account prod/non-prod bucket separation requires aggregate review across accounts'
        }

        'LOG-21' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $trails = Get-LogCloudTrails -Region $Region
            if ($null -eq $trails) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-21'
            }

            $logBucketName = $null
            $orgTrail = Get-LogOrganizationTrail -Trails $trails
            if ($orgTrail -and $orgTrail.S3BucketName) {
                $logBucketName = [string]$orgTrail.S3BucketName
            }
            elseif ((Get-AuditCollectionCount $trails) -gt 0 -and $trails[0].S3BucketName) {
                $logBucketName = [string]$trails[0].S3BucketName
            }

            $endTime = (Get-Date).ToUniversalTime().ToString('o')
            $startTime = (Get-Date).AddDays(-7).ToUniversalTime().ToString('o')

            $data = Invoke-AWSCLI -Arguments @(
                'cloudtrail', 'lookup-events',
                '--lookup-attributes', 'AttributeKey=EventSource,AttributeValue=s3.amazonaws.com',
                '--start-time', $startTime,
                '--end-time', $endTime,
                '--max-results', '50'
            ) -Region $Region

            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-21'
            }

            $matchingEvents = 0
            if ($data.Events -and $logBucketName) {
                foreach ($event in (Get-AuditCliArray $data.Events)) {
                    $eventJson = [string]$event.CloudTrailEvent
                    if ($eventJson -match [regex]::Escape($logBucketName)) {
                        $matchingEvents++
                    }
                }
            }

            $evidence = @{
                log_bucket_name         = $logBucketName
                s3_event_count          = 0
                log_bucket_event_count  = $matchingEvents
            }

            if (Test-AuditHasProperty -Object $data -PropertyName 'Events') {
                $evidence.s3_event_count = (Get-AuditCollectionCount $data.Events)
            }

            if ($matchingEvents -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-21' `
                    -Status 'PASS' -Evidence $evidence -Notes 'S3 access events on log bucket visible in CloudTrail'
            }

            if ($evidence.s3_event_count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-21' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'CloudTrail active but log bucket access events not captured in sample'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-21' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No S3 events found in CloudTrail lookup sample'
        }

        'LOG-22' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'LOG-22' `
                -Notes 'Verify log architecture documented in DEX post-bascule Dynatrace 27/05. Check CloudWatch vs Dynatrace split.'
        }
    }
}
