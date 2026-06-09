$DomainSeverity = @{
    'DAT-03' = 'P0'
    'DAT-04' = 'P0'
    'DAT-05' = 'P0'
    'DAT-07' = 'P1'
    'DAT-08' = 'P0'
    'DAT-09' = 'P0'
    'DAT-10' = 'P0'
    'DAT-11' = 'P0'
    'DAT-12' = 'P0'
    'DAT-13' = 'P0'
    'DAT-14' = 'P0'
    'DAT-15' = 'P0'
    'DAT-17' = 'P0'
    'DAT-18' = 'P0'
    'DAT-19' = 'P0'
    'DAT-20' = 'P0'
    'DAT-21' = 'P0'
    'DAT-22' = 'P0'
    'DAT-23' = 'P1'
    'DAT-24' = 'P0'
    'DAT-25' = 'P0'
}

function Get-DatS3BucketNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('s3api', 'list-buckets') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    $bucketNames = @()
    if ($data.Buckets) {
        foreach ($bucket in $data.Buckets) {
            if ($bucket.Name) {
                $bucketNames += [string]$bucket.Name
            }
        }
    }

    return $bucketNames
}

function Test-DatBucketNameCritical {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $lowerName = $BucketName.ToLower()
    if ($lowerName -match 'log|backup|critical') {
        return $true
    }

    return $false
}

function Test-DatBucketNameLogOrBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $lowerName = $BucketName.ToLower()
    if ($lowerName -match 'log|backup') {
        return $true
    }

    return $false
}

function Test-DatS3BucketPublic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BucketName
    )

    $aclData = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-acl', '--bucket', $BucketName) -Region $Region
    if ($null -ne $aclData) {
        if ($aclData.Grants) {
            foreach ($grant in $aclData.Grants) {
                if ($grant.Grantee -and $grant.Grantee.URI) {
                    $uri = [string]$grant.Grantee.URI
                    if ($uri -match 'AllUsers|AuthenticatedUsers') {
                        if ($grant.Permission -match 'READ|FULL_CONTROL') {
                            return $true
                        }
                    }
                }
            }
        }
    }

    $pabData = Invoke-AWSCLI -Arguments @('s3api', 'get-public-access-block', '--bucket', $BucketName) -Region $Region
    if ($null -ne $pabData) {
        if ($pabData.PublicAccessBlockConfiguration) {
            $config = $pabData.PublicAccessBlockConfiguration
            $allTrue = ($config.BlockPublicAcls -eq $true) -and
                       ($config.IgnorePublicAcls -eq $true) -and
                       ($config.BlockPublicPolicy -eq $true) -and
                       ($config.RestrictPublicBuckets -eq $true)
            if (-not $allTrue) {
                return $true
            }
        }
    }

    return $false
}

function Test-DatS3BucketSseKms {
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

    if (-not $data.ServerSideEncryptionConfiguration) {
        return $false
    }

    if (-not $data.ServerSideEncryptionConfiguration.Rules) {
        return $false
    }

    foreach ($rule in $data.ServerSideEncryptionConfiguration.Rules) {
        if ($rule.ApplyServerSideEncryptionByDefault) {
            $algorithm = [string]$rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
            if ($algorithm -eq 'aws:kms') {
                return $true
            }
        }
    }

    return $false
}

function Get-DatCustomerMasterKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $keys = @()
    $marker = $null

    do {
        $arguments = @('kms', 'list-keys', '--limit', '1000')
        if ($marker) {
            $arguments += @('--marker', $marker)
        }

        $listData = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $listData) {
            return $null
        }

        if ($listData.Keys) {
            foreach ($key in $listData.Keys) {
                if (-not $key.KeyId) {
                    continue
                }

                $describeData = Invoke-AWSCLI -Arguments @('kms', 'describe-key', '--key-id', $key.KeyId) -Region $Region
                if ($null -eq $describeData) {
                    continue
                }

                if (-not $describeData.KeyMetadata) {
                    continue
                }

                if ([string]$describeData.KeyMetadata.KeyManager -eq 'CUSTOMER') {
                    $keys += $describeData.KeyMetadata
                }
            }
        }

        $marker = $null
        if ($listData.PSObject.Properties.Name -contains 'NextMarker') {
            if (-not [string]::IsNullOrWhiteSpace([string]$listData.NextMarker)) {
                if ($listData.Truncated -eq $true) {
                    $marker = [string]$listData.NextMarker
                }
            }
        }
    } while ($marker)

    return $keys
}

function Get-DomainChecks {
    return [ordered]@{
        'DAT-03' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-03' `
                -Notes 'Verify Macie is active for S3 classification. Link to DET-16/17 results.'
        }

        'DAT-04' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-04' `
                -Status 'PARTIAL' `
                -Evidence $null `
                -Notes 'Check S3 bucket policies and SCP content for data exfiltration blocks. Workshop verification required.'
        }

        'DAT-05' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-05' `
                -Notes 'Verify Macie or equivalent DLP detection is active.'
        }

        'DAT-07' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-07' `
                -Notes 'Verify CloudWatch log patterns do not expose PII. Manual log sampling required.'
        }

        'DAT-08' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $volumeData = Invoke-AWSCLI -Arguments @('ec2', 'describe-volumes') -Region $Region
            if ($null -eq $volumeData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-08'
            }

            $ebsTotal = 0
            $ebsEncrypted = 0
            $ebsUnencrypted = 0
            if ($volumeData.Volumes) {
                foreach ($volume in $volumeData.Volumes) {
                    $ebsTotal++
                    if ($volume.Encrypted -eq $true) {
                        $ebsEncrypted++
                    }
                    else {
                        $ebsUnencrypted++
                    }
                }
            }

            $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
            if ($null -eq $rdsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-08'
            }

            $rdsTotal = 0
            $rdsEncrypted = 0
            $rdsUnencrypted = 0
            if ($rdsData.DBInstances) {
                foreach ($instance in $rdsData.DBInstances) {
                    $rdsTotal++
                    if ($instance.StorageEncrypted -eq $true) {
                        $rdsEncrypted++
                    }
                    else {
                        $rdsUnencrypted++
                    }
                }
            }

            $dynamoTotal = 0
            $dynamoEncrypted = 0
            $dynamoUnencrypted = 0
            $tableNames = @()
            $exclusiveStartTableName = $null

            do {
                $tableArgs = @('dynamodb', 'list-tables')
                if ($exclusiveStartTableName) {
                    $tableArgs += @('--exclusive-start-table-name', $exclusiveStartTableName)
                }

                $tableListData = Invoke-AWSCLI -Arguments $tableArgs -Region $Region
                if ($null -eq $tableListData) {
                    return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-08'
                }

                if ($tableListData.TableNames) {
                    $tableNames += @($tableListData.TableNames)
                }

                $exclusiveStartTableName = $null
                if ($tableListData.PSObject.Properties.Name -contains 'LastEvaluatedTableName') {
                    if (-not [string]::IsNullOrWhiteSpace([string]$tableListData.LastEvaluatedTableName)) {
                        $exclusiveStartTableName = [string]$tableListData.LastEvaluatedTableName
                    }
                }
            } while ($exclusiveStartTableName)

            foreach ($tableName in $tableNames) {
                $tableData = Invoke-AWSCLI -Arguments @('dynamodb', 'describe-table', '--table-name', $tableName) -Region $Region
                if ($null -eq $tableData) {
                    continue
                }

                $dynamoTotal++
                $isEncrypted = $false
                if ($tableData.Table -and $tableData.Table.SSEDescription) {
                    $sse = $tableData.Table.SSEDescription
                    if ($sse.Status -eq 'ENABLED' -and $sse.SSEType -eq 'KMS') {
                        $isEncrypted = $true
                    }
                }

                if ($isEncrypted) {
                    $dynamoEncrypted++
                }
                else {
                    $dynamoUnencrypted++
                }
            }

            $bucketNames = Get-DatS3BucketNames -Region $Region
            if ($null -eq $bucketNames) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-08'
            }

            $s3Total = $bucketNames.Count
            $s3Encrypted = 0
            $s3Unencrypted = 0

            foreach ($bucketName in $bucketNames) {
                if (Test-DatS3BucketSseKms -Region $Region -BucketName $bucketName) {
                    $s3Encrypted++
                }
                else {
                    $s3Unencrypted++
                }
            }

            $evidence = @{
                ebs   = @{ total = $ebsTotal; encrypted = $ebsEncrypted; unencrypted = $ebsUnencrypted }
                rds   = @{ total = $rdsTotal; encrypted = $rdsEncrypted; unencrypted = $rdsUnencrypted }
                dynamodb = @{ total = $dynamoTotal; encrypted = $dynamoEncrypted; unencrypted = $dynamoUnencrypted }
                s3    = @{ total = $s3Total; sse_kms = $s3Encrypted; not_sse_kms = $s3Unencrypted }
            }

            $hasFailure = ($ebsUnencrypted -gt 0) -or ($rdsUnencrypted -gt 0) -or ($dynamoUnencrypted -gt 0) -or ($s3Unencrypted -gt 0)
            if ($hasFailure) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-08' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more resources are not encrypted with managed keys'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-08' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All assessed EBS, RDS, DynamoDB, and S3 resources meet encryption requirements'
        }

        'DAT-09' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $lbData = Invoke-AWSCLI -Arguments @('elbv2', 'describe-load-balancers') -Region $Region
            if ($null -eq $lbData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-09'
            }

            $loadBalancers = @()
            if ($lbData.LoadBalancers) {
                $loadBalancers = @($lbData.LoadBalancers)
            }

            $httpListenerCount = 0
            $httpsListenerCount = 0
            $httpWithoutRedirectCount = 0
            $failingListeners = @()

            foreach ($loadBalancer in $loadBalancers) {
                if (-not $loadBalancer.LoadBalancerArn) {
                    continue
                }

                $listenerData = Invoke-AWSCLI -Arguments @('elbv2', 'describe-listeners', '--load-balancer-arn', $loadBalancer.LoadBalancerArn) -Region $Region
                if ($null -eq $listenerData) {
                    continue
                }

                if (-not $listenerData.Listeners) {
                    continue
                }

                foreach ($listener in $listenerData.Listeners) {
                    $protocol = [string]$listener.Protocol
                    if ($protocol -eq 'HTTPS') {
                        $httpsListenerCount++
                        continue
                    }

                    if ($protocol -eq 'HTTP') {
                        $httpListenerCount++
                        $hasRedirect = $false
                        if ($listener.DefaultActions) {
                            foreach ($action in $listener.DefaultActions) {
                                if ($action.Type -eq 'redirect') {
                                    $hasRedirect = $true
                                    break
                                }
                            }
                        }

                        if (-not $hasRedirect) {
                            $httpWithoutRedirectCount++
                            if ($failingListeners.Count -lt 5) {
                                $failingListeners += @{
                                    load_balancer = [string]$loadBalancer.LoadBalancerName
                                    listener_arn  = [string]$listener.ListenerArn
                                    protocol      = $protocol
                                }
                            }
                        }
                    }
                }
            }

            $evidence = @{
                load_balancer_count         = $loadBalancers.Count
                http_listener_count         = $httpListenerCount
                https_listener_count        = $httpsListenerCount
                http_without_redirect_count = $httpWithoutRedirectCount
                failing_listeners           = @($failingListeners)
            }

            if ($httpWithoutRedirectCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-09' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more HTTP listeners exist without redirect to HTTPS'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-09' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All ALB listeners use HTTPS or HTTP redirects to HTTPS'
        }

        'DAT-10' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $customerKeys = Get-DatCustomerMasterKeys -Region $Region
            if ($null -eq $customerKeys) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-10'
            }

            $keysWithPolicies = 0
            $unreadablePolicyCount = 0

            foreach ($key in $customerKeys) {
                $keyId = [string]$key.KeyId
                $policyData = Invoke-AWSCLI -Arguments @('kms', 'list-key-policies', '--key-id', $keyId) -Region $Region
                if ($null -eq $policyData) {
                    $unreadablePolicyCount++
                    continue
                }

                if ($policyData.PolicyNames) {
                    if (@($policyData.PolicyNames).Count -gt 0) {
                        $keysWithPolicies++
                    }
                }
            }

            $evidence = @{
                cmk_count               = $customerKeys.Count
                keys_with_policies      = $keysWithPolicies
                unreadable_policy_count = $unreadablePolicyCount
            }

            if ($unreadablePolicyCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-10' `
                    -Status 'PARTIAL' `
                    -Evidence $evidence `
                    -Notes 'Cannot read key policies for one or more CMKs'
            }

            if ($customerKeys.Count -gt 0 -and $keysWithPolicies -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-10' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'CMKs exist with defined key policies'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-10' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No CMKs with readable key policies found'
        }

        'DAT-11' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $customerKeys = Get-DatCustomerMasterKeys -Region $Region
            if ($null -eq $customerKeys) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-11'
            }

            $enabledCount = 0
            $disabledCount = 0
            $disabledKeyIds = @()

            foreach ($key in $customerKeys) {
                $keyId = [string]$key.KeyId
                $rotationData = Invoke-AWSCLI -Arguments @('kms', 'get-key-rotation-status', '--key-id', $keyId) -Region $Region
                if ($null -eq $rotationData) {
                    $disabledCount++
                    if ($disabledKeyIds.Count -lt 10) {
                        $disabledKeyIds += $keyId
                    }
                    continue
                }

                if ($rotationData.KeyRotationEnabled -eq $true) {
                    $enabledCount++
                }
                else {
                    $disabledCount++
                    if ($disabledKeyIds.Count -lt 10) {
                        $disabledKeyIds += $keyId
                    }
                }
            }

            $evidence = @{
                cmk_count              = $customerKeys.Count
                rotation_enabled_count = $enabledCount
                rotation_disabled_count = $disabledCount
                keys_without_rotation  = @($disabledKeyIds)
            }

            if ($disabledCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-11' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more CMKs do not have rotation enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-11' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All CMKs have rotation enabled'
        }

        'DAT-12' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $customerKeys = Get-DatCustomerMasterKeys -Region $Region
            if ($null -eq $customerKeys) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-12'
            }

            $scheduledCount = 0
            $scheduledKeyIds = @()

            foreach ($key in $customerKeys) {
                if ($key.PSObject.Properties.Name -contains 'DeletionDate') {
                    if ($null -ne $key.DeletionDate) {
                        $scheduledCount++
                        if ($scheduledKeyIds.Count -lt 10) {
                            $scheduledKeyIds += [string]$key.KeyId
                        }
                    }
                }
            }

            $evidence = @{
                cmk_count                 = $customerKeys.Count
                scheduled_deletion_count = $scheduledCount
                key_ids                   = @($scheduledKeyIds)
            }

            if ($scheduledCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-12' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more CMKs are scheduled for deletion'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-12' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'No keys scheduled for deletion'
        }

        'DAT-13' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $customerKeys = Get-DatCustomerMasterKeys -Region $Region
            if ($null -eq $customerKeys) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-13'
            }

            $totalGrantCount = 0
            $externalGrantCount = 0
            $externalGrants = @()

            foreach ($key in $customerKeys) {
                $keyId = [string]$key.KeyId
                $grantData = Invoke-AWSCLI -Arguments @('kms', 'list-grants', '--key-id', $keyId) -Region $Region
                if ($null -eq $grantData) {
                    continue
                }

                if (-not $grantData.Grants) {
                    continue
                }

                foreach ($grant in $grantData.Grants) {
                    $totalGrantCount++
                    $grantee = [string]$grant.GranteePrincipal
                    if ([string]::IsNullOrWhiteSpace($grantee)) {
                        continue
                    }

                    if ($grantee -notmatch $AccountId) {
                        $externalGrantCount++
                        if ($externalGrants.Count -lt 10) {
                            $externalGrants += @{
                                key_id  = $keyId
                                grantee = $grantee
                            }
                        }
                    }
                }
            }

            $evidence = @{
                total_grant_count    = $totalGrantCount
                external_grant_count = $externalGrantCount
                external_grants      = @($externalGrants)
            }

            if ($externalGrantCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-13' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'Active grants to external principals found'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-13' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'No external KMS grants found'
        }

        'DAT-14' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $data = Invoke-AWSCLI -Arguments @('s3control', 'get-public-access-block', '--account-id', $AccountId) -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-14'
            }

            $config = $null
            if ($data.PublicAccessBlockConfiguration) {
                $config = $data.PublicAccessBlockConfiguration
            }

            $blockPublicAcls = $false
            $ignorePublicAcls = $false
            $blockPublicPolicy = $false
            $restrictPublicBuckets = $false

            if ($config) {
                $blockPublicAcls = ($config.BlockPublicAcls -eq $true)
                $ignorePublicAcls = ($config.IgnorePublicAcls -eq $true)
                $blockPublicPolicy = ($config.BlockPublicPolicy -eq $true)
                $restrictPublicBuckets = ($config.RestrictPublicBuckets -eq $true)
            }

            $evidence = @{
                BlockPublicAcls       = $blockPublicAcls
                IgnorePublicAcls      = $ignorePublicAcls
                BlockPublicPolicy     = $blockPublicPolicy
                RestrictPublicBuckets = $restrictPublicBuckets
            }

            if ($blockPublicAcls -and $ignorePublicAcls -and $blockPublicPolicy -and $restrictPublicBuckets) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-14' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'Account-level S3 Block Public Access is fully enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-14' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'One or more account-level S3 Block Public Access settings is disabled'
        }

        'DAT-15' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $bucketNames = Get-DatS3BucketNames -Region $Region
            if ($null -eq $bucketNames) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-15'
            }

            $publicBucketCount = 0
            $publicBucketNames = @()

            foreach ($bucketName in $bucketNames) {
                if (Test-DatS3BucketPublic -Region $Region -BucketName $bucketName) {
                    $publicBucketCount++
                    if ($publicBucketNames.Count -lt 5) {
                        $publicBucketNames += $bucketName
                    }
                }
            }

            $evidence = @{
                bucket_count         = $bucketNames.Count
                public_bucket_count  = $publicBucketCount
                public_bucket_names  = @($publicBucketNames)
            }

            if ($publicBucketCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-15' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more buckets appear publicly accessible'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-15' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'No publicly accessible buckets detected'
        }

        'DAT-17' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $bucketNames = Get-DatS3BucketNames -Region $Region
            if ($null -eq $bucketNames) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-17'
            }

            $criticalBuckets = @()
            foreach ($bucketName in $bucketNames) {
                if (Test-DatBucketNameCritical -BucketName $bucketName) {
                    $criticalBuckets += $bucketName
                }
            }

            if ($criticalBuckets.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-17' `
                    -Status 'PARTIAL' `
                    -Evidence @{
                        bucket_count           = $bucketNames.Count
                        critical_bucket_count  = 0
                        versioning_enabled     = 0
                        versioning_disabled    = 0
                    } `
                    -Notes 'Cannot determine which buckets are critical without consistent tags'
            }

            $versioningEnabled = 0
            $versioningDisabled = 0
            $disabledBuckets = @()

            foreach ($bucketName in $criticalBuckets) {
                $versionData = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-versioning', '--bucket', $bucketName) -Region $Region
                $status = $null
                if ($versionData -and $versionData.PSObject.Properties.Name -contains 'Status') {
                    $status = [string]$versionData.Status
                }

                if ($status -eq 'Enabled') {
                    $versioningEnabled++
                }
                else {
                    $versioningDisabled++
                    if ($disabledBuckets.Count -lt 5) {
                        $disabledBuckets += $bucketName
                    }
                }
            }

            $evidence = @{
                bucket_count          = $bucketNames.Count
                critical_bucket_count = $criticalBuckets.Count
                versioning_enabled    = $versioningEnabled
                versioning_disabled   = $versioningDisabled
                disabled_buckets      = @($disabledBuckets)
            }

            if ($versioningDisabled -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-17' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more critical buckets do not have versioning enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-17' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'Versioning is enabled on identified critical buckets'
        }

        'DAT-18' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $bucketNames = Get-DatS3BucketNames -Region $Region
            if ($null -eq $bucketNames) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-18'
            }

            $targetBuckets = @()
            foreach ($bucketName in $bucketNames) {
                if (Test-DatBucketNameLogOrBackup -BucketName $bucketName) {
                    $targetBuckets += $bucketName
                }
            }

            if ($targetBuckets.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-18' `
                    -Status 'PARTIAL' `
                    -Evidence @{ bucket_count = $bucketNames.Count; assessed_buckets = @() } `
                    -Notes 'No log or backup buckets identified by naming convention'
            }

            $complianceCount = 0
            $governanceOnlyCount = 0
            $missingLockCount = 0
            $bucketStatuses = @()

            foreach ($bucketName in $targetBuckets) {
                $lockData = Invoke-AWSCLI -Arguments @('s3api', 'get-object-lock-configuration', '--bucket', $bucketName) -Region $Region
                if ($null -eq $lockData) {
                    $missingLockCount++
                    if ($bucketStatuses.Count -lt 10) {
                        $bucketStatuses += @{
                            bucket = $bucketName
                            mode   = 'NONE'
                        }
                    }
                    continue
                }

                $mode = 'NONE'
                if ($lockData.ObjectLockConfiguration -and $lockData.ObjectLockConfiguration.ObjectLockEnabled) {
                    if ($lockData.ObjectLockConfiguration.Rule -and $lockData.ObjectLockConfiguration.Rule.DefaultRetention) {
                        $mode = [string]$lockData.ObjectLockConfiguration.Rule.DefaultRetention.Mode
                    }
                    else {
                        $mode = 'ENABLED'
                    }
                }

                if ($mode -eq 'COMPLIANCE') {
                    $complianceCount++
                }
                elseif ($mode -eq 'GOVERNANCE') {
                    $governanceOnlyCount++
                }
                else {
                    $missingLockCount++
                }

                if ($bucketStatuses.Count -lt 10) {
                    $bucketStatuses += @{
                        bucket = $bucketName
                        mode   = $mode
                    }
                }
            }

            $evidence = @{
                assessed_bucket_count = $targetBuckets.Count
                compliance_mode_count = $complianceCount
                governance_mode_count = $governanceOnlyCount
                missing_lock_count    = $missingLockCount
                bucket_statuses       = @($bucketStatuses)
            }

            if ($complianceCount -eq $targetBuckets.Count) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-18' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'Object Lock enabled in COMPLIANCE mode on assessed buckets'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-18' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'No Object Lock or GOVERNANCE mode only on one or more log or backup buckets'
        }

        'DAT-19' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $defaultData = Invoke-AWSCLI -Arguments @('ec2', 'get-ebs-encryption-by-default') -Region $Region
            if ($null -eq $defaultData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-19'
            }

            $enabled = $false
            if ($defaultData.PSObject.Properties.Name -contains 'EbsEncryptionByDefault') {
                $enabled = ($defaultData.EbsEncryptionByDefault -eq $true)
            }

            $volumeData = Invoke-AWSCLI -Arguments @('ec2', 'describe-volumes', '--filters', 'Name=encrypted,Values=false') -Region $Region
            if ($null -eq $volumeData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-19'
            }

            $unencryptedVolumeCount = 0
            if ($volumeData.Volumes) {
                $unencryptedVolumeCount = @($volumeData.Volumes).Count
            }

            $evidence = @{
                ebs_encryption_by_default = $enabled
                unencrypted_volume_count  = $unencryptedVolumeCount
            }

            if ($enabled -and $unencryptedVolumeCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-19' `
                    -Status 'PASS' `
                    -Evidence $evidence `
                    -Notes 'EBS default encryption is enabled and no unencrypted volumes found'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-19' `
                -Status 'FAIL' `
                -Evidence $evidence `
                -Notes 'EBS default encryption is disabled or unencrypted volumes exist'
        }

        'DAT-20' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $snapshotData = Invoke-AWSCLI -Arguments @('ec2', 'describe-snapshots', '--owner-ids', 'self') -Region $Region
            if ($null -eq $snapshotData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-20'
            }

            $snapshots = @()
            if ($snapshotData.Snapshots) {
                $snapshots = @($snapshotData.Snapshots)
            }

            $encryptedCount = 0
            $unencryptedCount = 0
            $publicShareCount = 0
            $failingSnapshots = @()

            foreach ($snapshot in $snapshots) {
                if ($snapshot.Encrypted -eq $true) {
                    $encryptedCount++
                }
                else {
                    $unencryptedCount++
                    if ($failingSnapshots.Count -lt 10) {
                        $failingSnapshots += @{
                            snapshot_id = [string]$snapshot.SnapshotId
                            reason        = 'unencrypted'
                        }
                    }
                }

                if (-not $snapshot.SnapshotId) {
                    continue
                }

                $attributeData = Invoke-AWSCLI -Arguments @(
                    'ec2', 'describe-snapshot-attribute',
                    '--snapshot-id', $snapshot.SnapshotId,
                    '--attribute', 'createVolumePermission'
                ) -Region $Region

                if ($null -eq $attributeData) {
                    continue
                }

                if ($attributeData.CreateVolumePermissions) {
                    foreach ($permission in $attributeData.CreateVolumePermissions) {
                        if ($permission.Group -eq 'all') {
                            $publicShareCount++
                            if ($failingSnapshots.Count -lt 10) {
                                $failingSnapshots += @{
                                    snapshot_id = [string]$snapshot.SnapshotId
                                    reason        = 'public_share'
                                }
                            }
                            break
                        }
                    }
                }
            }

            $evidence = @{
                snapshot_count       = $snapshots.Count
                encrypted_count      = $encryptedCount
                unencrypted_count    = $unencryptedCount
                public_share_count   = $publicShareCount
                failing_snapshots    = @($failingSnapshots)
            }

            if ($unencryptedCount -gt 0 -or $publicShareCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-20' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'Unencrypted snapshots or public snapshot sharing found'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-20' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All owned snapshots are encrypted and not publicly shared'
        }

        'DAT-21' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $rdsData = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
            if ($null -eq $rdsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-21'
            }

            $instances = @()
            if ($rdsData.DBInstances) {
                $instances = @($rdsData.DBInstances)
            }

            $encryptedCount = 0
            $notPublicCount = 0
            $failingInstances = @()

            foreach ($instance in $instances) {
                $instanceId = [string]$instance.DBInstanceIdentifier
                $isEncrypted = ($instance.StorageEncrypted -eq $true)
                $isPublic = ($instance.PubliclyAccessible -eq $true)

                if ($isEncrypted) {
                    $encryptedCount++
                }

                if (-not $isPublic) {
                    $notPublicCount++
                }

                if (-not $isEncrypted -or $isPublic) {
                    if ($failingInstances.Count -lt 10) {
                        $failingInstances += @{
                            instance_id          = $instanceId
                            storage_encrypted    = $isEncrypted
                            publicly_accessible  = $isPublic
                        }
                    }
                }
            }

            $evidence = @{
                instance_count     = $instances.Count
                encrypted_count    = $encryptedCount
                not_public_count   = $notPublicCount
                failing_instances  = @($failingInstances)
            }

            if ($failingInstances.Count -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-21' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more RDS instances are unencrypted or publicly accessible'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-21' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All RDS instances are encrypted and not publicly accessible'
        }

        'DAT-22' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $vaultData = Invoke-AWSCLI -Arguments @('backup', 'list-backup-vaults') -Region $Region
            if ($null -eq $vaultData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-22'
            }

            $vaultNames = @()
            if ($vaultData.BackupVaultList) {
                foreach ($vault in $vaultData.BackupVaultList) {
                    if ($vault.BackupVaultName) {
                        $vaultNames += [string]$vault.BackupVaultName
                    }
                }
            }

            if ($vaultNames.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-22' `
                    -Status 'PARTIAL' `
                    -Evidence @{ vault_count = 0 } `
                    -Notes 'No backup vaults found to assess'
            }

            $encryptedVaultCount = 0
            $failingVaultCount = 0
            $vaultEvidence = @()

            foreach ($vaultName in $vaultNames) {
                $describeData = Invoke-AWSCLI -Arguments @('backup', 'describe-backup-vault', '--backup-vault-name', $vaultName) -Region $Region
                if ($null -eq $describeData) {
                    $failingVaultCount++
                    continue
                }

                $encryptionKeyArn = $null
                if ($describeData.EncryptionKeyArn) {
                    $encryptionKeyArn = [string]$describeData.EncryptionKeyArn
                }

                $accessPolicyPresent = $false
                if ($describeData.PSObject.Properties.Name -contains 'AccessPolicy') {
                    if (-not [string]::IsNullOrWhiteSpace([string]$describeData.AccessPolicy)) {
                        $accessPolicyPresent = $true
                    }
                }

                $vaultOk = (-not [string]::IsNullOrWhiteSpace($encryptionKeyArn)) -and $accessPolicyPresent
                if ($vaultOk) {
                    $encryptedVaultCount++
                }
                else {
                    $failingVaultCount++
                }

                if ($vaultEvidence.Count -lt 10) {
                    $vaultEvidence += @{
                        vault_name         = $vaultName
                        encryption_key_arn = $encryptionKeyArn
                        access_policy_set  = $accessPolicyPresent
                    }
                }
            }

            $evidence = @{
                vault_count           = $vaultNames.Count
                encrypted_vault_count = $encryptedVaultCount
                failing_vault_count   = $failingVaultCount
                vaults                = @($vaultEvidence)
            }

            if ($failingVaultCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-22' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more backup vaults are not encrypted with a CMK or lack an access policy'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-22' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'Backup vaults are encrypted with CMKs and have access policies'
        }

        'DAT-23' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-23' `
                -Notes 'Verify data deletion procedure exists for decommissioned resources.'
        }

        'DAT-24' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $secretsData = Invoke-AWSCLI -Arguments @('secretsmanager', 'list-secrets', '--max-results', '100') -Region $Region
            if ($null -eq $secretsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-24'
            }

            $secretsCount = 0
            if ($secretsData.SecretList) {
                $secretsCount = @($secretsData.SecretList).Count
            }

            $ssmData = Invoke-AWSCLI -Arguments @('ssm', 'describe-parameters') -Region $Region
            if ($null -eq $ssmData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-24'
            }

            $stringParamCount = 0
            $secureStringCount = 0
            if ($ssmData.Parameters) {
                foreach ($parameter in $ssmData.Parameters) {
                    $paramType = [string]$parameter.Type
                    if ($paramType -eq 'String') {
                        $stringParamCount++
                    }
                    if ($paramType -eq 'SecureString') {
                        $secureStringCount++
                    }
                }
            }

            $evidence = @{
                secrets_manager_count = $secretsCount
                ssm_string_count      = $stringParamCount
                ssm_securestring_count = $secureStringCount
            }

            if ($stringParamCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-24' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'SSM String parameters exist and may contain secrets in plaintext'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-24' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'No SSM String parameters found; secrets should be stored in Secrets Manager'
        }

        'DAT-25' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $secretsData = Invoke-AWSCLI -Arguments @('secretsmanager', 'list-secrets', '--max-results', '100') -Region $Region
            if ($null -eq $secretsData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DAT-25'
            }

            $secrets = @()
            if ($secretsData.SecretList) {
                $secrets = @($secretsData.SecretList)
            }

            if ($secrets.Count -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-25' `
                    -Status 'PARTIAL' `
                    -Evidence @{ secret_count = 0 } `
                    -Notes 'No Secrets Manager secrets found to assess rotation'
            }

            $rotationEnabledCount = 0
            $rotationDisabledCount = 0
            $namesWithoutRotation = @()

            foreach ($secret in $secrets) {
                if ($secret.RotationEnabled -eq $true) {
                    $rotationEnabledCount++
                }
                else {
                    $rotationDisabledCount++
                    if ($namesWithoutRotation.Count -lt 10 -and $secret.Name) {
                        $namesWithoutRotation += [string]$secret.Name
                    }
                }
            }

            $evidence = @{
                secret_count             = $secrets.Count
                rotation_enabled_count   = $rotationEnabledCount
                rotation_disabled_count  = $rotationDisabledCount
                names_without_rotation   = @($namesWithoutRotation)
            }

            if ($rotationDisabledCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DAT-25' `
                    -Status 'FAIL' `
                    -Evidence $evidence `
                    -Notes 'One or more secrets do not have rotation enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DAT-25' `
                -Status 'PASS' `
                -Evidence $evidence `
                -Notes 'All Secrets Manager secrets have rotation enabled'
        }
    }
}
