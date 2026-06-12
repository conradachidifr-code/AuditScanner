$DomainSeverity = @{
    'BCK-01' = 'P1'
    'BCK-02' = 'P1'
    'BCK-03' = 'P1'
    'BCK-04' = 'P1'
    'BCK-05' = 'P1'
    'BCK-06' = 'P1'
    'BCK-07' = 'P1'
    'BCK-08' = 'P1'
    'BCK-09' = 'P1'
    'BCK-10' = 'P1'
    'BCK-11' = 'P1'
    'BCK-12' = 'P1'
    'BCK-13' = 'P1'
    'BCK-14' = 'P1'
    'BCK-15' = 'P1'
    'BCK-16' = 'P1'
    'BCK-17' = 'P1'
    'BCK-18' = 'P1'
    'BCK-19' = 'P1'
    'BCK-20' = 'P1'
}

function Get-BckBackupPlans {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $plans = New-AuditList
    $token = $null

    do {
        $arguments = @('backup', 'list-backup-plans')
        if ($token) {
            $arguments += @('--next-token', $token)
        }

        $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
        if ($null -eq $data) {
            return $null
        }

        if (Test-AuditHasProperty -Object $data -PropertyName 'BackupPlansList') {
            foreach ($plan in (Get-AuditCliArray $data.BackupPlansList)) {
                [void]$plans.Add($plan)
            }
        }

        $token = $null
        if ((Test-AuditHasProperty -Object $data -PropertyName 'NextToken')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$data.NextToken)) {
                $token = [string]$data.NextToken
            }
        }
    } while ($token)

    return $plans.ToArray()
}

function Get-BckBackupPlanDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BackupPlanId
    )

    return Invoke-AWSCLI -Arguments @('backup', 'get-backup-plan', '--backup-plan-id', $BackupPlanId) -Region $Region
}

function Get-BckSelectionResourceTypes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$BackupPlanId
    )

    $listData = Invoke-AWSCLI -Arguments @('backup', 'list-backup-selections', '--backup-plan-id', $BackupPlanId) -Region $Region
    if ($null -eq $listData) {
        return @()
    }

    $resourceTypes = @()
    if (-not (Test-AuditHasProperty -Object $listData -PropertyName 'BackupSelectionsList')) {
        return @()
    }

    foreach ($selection in (Get-AuditCliArray $listData.BackupSelectionsList)) {
        if (-not (Test-AuditHasProperty -Object $selection -PropertyName 'SelectionId')) {
            continue
        }

        $detailData = Invoke-AWSCLI -Arguments @(
            'backup', 'get-backup-selection',
            '--backup-plan-id', $BackupPlanId,
            '--selection-id', $selection.SelectionId
        ) -Region $Region

        if ($null -eq $detailData) {
            continue
        }

        if ($detailData.BackupSelection -and $detailData.BackupSelection.Resources) {
            foreach ($resource in $detailData.BackupSelection.Resources) {
                $resourceText = [string]$resource
                if ($resourceText -match ':ec2:') { if ($resourceTypes -notcontains 'EC2') { $resourceTypes += 'EC2' } }
                if ($resourceText -match ':rds:') { if ($resourceTypes -notcontains 'RDS') { $resourceTypes += 'RDS' } }
                if ($resourceText -match ':elasticfilesystem:') { if ($resourceTypes -notcontains 'EFS') { $resourceTypes += 'EFS' } }
                if ($resourceText -match ':dynamodb:') { if ($resourceTypes -notcontains 'DynamoDB') { $resourceTypes += 'DynamoDB' } }
            }
        }

        if ($detailData.BackupSelection -and $detailData.BackupSelection.ListOfTags) {
            if ($resourceTypes -notcontains 'TAGGED') {
                $resourceTypes += 'TAGGED'
            }
        }
    }

    return $resourceTypes
}

function Test-BckScheduleFrequentEnough {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScheduleExpression
    )

    $schedule = $ScheduleExpression.ToLower()
    if ($schedule -match 'rate\((\d+)\s+hour') {
        return $true
    }
    if ($schedule -match 'rate\(1\s+day') {
        return $true
    }
    if ($schedule -match 'cron\(') {
        if ($schedule -notmatch 'sun|mon|tue|wed|thu|fri|sat|\? \* \d|\? \* [0-9]') {
            return $true
        }
    }

    if ($schedule -match 'rate\((\d+)\s+day') {
        $days = [int]$Matches[1]
        if ($days -le 1) {
            return $true
        }
    }

    return $false
}

function Test-BckBucketNameCritical {
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

function Get-BckS3BucketNames {
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

function Get-BckAccountIdFromArn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Arn
    )

    if ($Arn -match 'arn:aws:[^:]*:[^:]*:(\d{12}):') {
        return $Matches[1]
    }

    return $null
}

function Get-DomainChecks {
    return [ordered]@{
        'BCK-01' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-01' `
                -Notes 'Verify backup policy document exists and is RSSI-approved.'
        }

        'BCK-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $plans = Get-BckBackupPlans -Region $Region
            if ($null -eq $plans) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-02'
            }

            if ((Get-AuditCollectionCount $plans) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-02' `
                    -Status 'FAIL' -Evidence @{ plan_count = 0 } -Notes 'No backup plans found'
            }

            $planEvidence = @()
            $allRequiredTypes = @('EC2', 'RDS', 'EFS', 'DynamoDB')
            $coveredTypes = @()

            foreach ($plan in $plans) {
                $planId = [string]$plan.BackupPlanId
                $planName = [string]$plan.BackupPlanName
                $types = Get-BckSelectionResourceTypes -Region $Region -BackupPlanId $planId

                foreach ($type in $types) {
                    if ($coveredTypes -notcontains $type) {
                        $coveredTypes += $type
                    }
                }

                $planEvidence += @{
                    plan_id        = $planId
                    plan_name      = $planName
                    resource_types = @($types)
                }
            }

            $evidence = @{
                plan_count      = (Get-AuditCollectionCount $plans)
                plans           = @($planEvidence)
                covered_types   = @($coveredTypes)
            }

            $hasEc2 = ($coveredTypes -contains 'EC2') -or ($coveredTypes -contains 'TAGGED')
            $hasRds = ($coveredTypes -contains 'RDS') -or ($coveredTypes -contains 'TAGGED')
            $hasEfs = ($coveredTypes -contains 'EFS') -or ($coveredTypes -contains 'TAGGED')
            $hasDynamo = ($coveredTypes -contains 'DynamoDB') -or ($coveredTypes -contains 'TAGGED')

            if ($hasEc2 -and $hasRds -and $hasEfs -and $hasDynamo) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-02' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Backup plans cover EC2, RDS, EFS, and DynamoDB'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-02' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'Backup plans exist but not all required resource types are explicitly covered'
        }

        'BCK-03' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $plans = Get-BckBackupPlans -Region $Region
            if ($null -eq $plans) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-03'
            }

            if ((Get-AuditCollectionCount $plans) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-03' `
                    -Status 'FAIL' -Evidence @{ plan_count = 0 } -Notes 'No backup plans found'
            }

            $schedules = @()
            $infrequentCount = 0

            foreach ($plan in $plans) {
                $planDetails = Get-BckBackupPlanDetails -Region $Region -BackupPlanId $plan.BackupPlanId
                if ($null -eq $planDetails) {
                    continue
                }

                if (-not (Test-AuditHasProperty -Object $planDetails -PropertyName 'BackupPlan') -or -not (Test-AuditHasProperty -Object $planDetails -PropertyName 'BackupPlan').Rules) {
                    continue
                }

                foreach ($rule in $planDetails.BackupPlan.Rules) {
                    $schedule = [string]$rule.ScheduleExpression
                    $schedules += @{
                        plan_name = [string]$plan.BackupPlanName
                        rule_name = [string]$rule.RuleName
                        schedule  = $schedule
                    }

                    if (-not (Test-BckScheduleFrequentEnough -ScheduleExpression $schedule)) {
                        $infrequentCount++
                    }
                }
            }

            $evidence = @{
                schedule_count    = (Get-AuditCollectionCount $schedules)
                infrequent_count  = $infrequentCount
                schedules         = @($schedules)
            }

            if ((Get-AuditCollectionCount $schedules) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-03' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'No backup rules found'
            }

            if ($infrequentCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-03' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Backup schedules are daily or more frequent'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-03' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more backup schedules are weekly or less frequent'
        }

        'BCK-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('backup', 'list-backup-vaults') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-04'
            }

            $vaults = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'BackupVaultList') {
                $vaults = @($data.BackupVaultList)
            }

            if ((Get-AuditCollectionCount $vaults) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-04' `
                    -Status 'FAIL' -Evidence @{ vault_count = 0 } -Notes 'No backup vaults found'
            }

            $vaultEvidence = @()
            $crossAccountCount = 0

            foreach ($vault in $vaults) {
                $vaultArn = [string]$vault.BackupVaultArn
                $vaultAccount = Get-BckAccountIdFromArn -Arn $vaultArn
                $isCrossAccount = ($vaultAccount -and $vaultAccount -ne $AccountId)

                if ($isCrossAccount) {
                    $crossAccountCount++
                }

                $vaultEvidence += @{
                    vault_name  = [string]$vault.BackupVaultName
                    vault_arn   = $vaultArn
                    account_id  = $vaultAccount
                }
            }

            $evidence = @{
                vault_count          = (Get-AuditCollectionCount $vaults)
                cross_account_count  = $crossAccountCount
                vaults               = @($vaultEvidence)
            }

            if ($crossAccountCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-04' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Backup vault in isolated account detected'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-04' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Backup vaults only exist in the current account'
        }

        'BCK-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('backup', 'list-backup-vaults') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-05'
            }

            if (-not (Test-AuditHasProperty -Object $listData -PropertyName 'BackupVaultList') -or (Get-AuditCollectionCount $listData.BackupVaultList) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-05' `
                    -Status 'FAIL' -Evidence @{ vault_count = 0 } -Notes 'No backup vaults found'
            }

            $vaultEvidence = @()
            $failingVaults = 0

            foreach ($vault in (Get-AuditCliArray $listData.BackupVaultList)) {
                $vaultName = [string]$vault.BackupVaultName
                $detailData = Invoke-AWSCLI -Arguments @('backup', 'describe-backup-vault', '--backup-vault-name', $vaultName) -Region $Region
                if ($null -eq $detailData) {
                    $failingVaults++
                    continue
                }

                $encryptionKeyArn = $null
                if (Test-AuditHasProperty -Object $detailData -PropertyName 'EncryptionKeyArn') {
                    $encryptionKeyArn = [string]$detailData.EncryptionKeyArn
                }

                $isCmk = $false
                if ($encryptionKeyArn -and $encryptionKeyArn -notmatch ':alias/aws/') {
                    if ($encryptionKeyArn -match 'arn:aws:kms:') {
                        $isCmk = $true
                    }
                }

                $vaultEvidence += @{
                    vault_name         = $vaultName
                    encryption_key_arn = $encryptionKeyArn
                    cmk                = $isCmk
                }

                if (-not $isCmk) {
                    $failingVaults++
                }
            }

            $evidence = @{
                vault_count    = (Get-AuditCollectionCount $listData.BackupVaultList)
                vaults         = @($vaultEvidence)
                failing_vaults = $failingVaults
            }

            if ($failingVaults -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-05' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All backup vaults encrypted with CMK'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-05' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more backup vaults lack CMK encryption'
        }

        'BCK-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $listData = Invoke-AWSCLI -Arguments @('backup', 'list-backup-vaults') -Region $Region
            if ($null -eq $listData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-06'
            }

            if (-not (Test-AuditHasProperty -Object $listData -PropertyName 'BackupVaultList') -or (Get-AuditCollectionCount $listData.BackupVaultList) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-06' `
                    -Status 'FAIL' -Evidence @{ vault_count = 0 } -Notes 'No backup vaults found'
            }

            $vaultEvidence = @()
            $failingVaults = 0

            foreach ($vault in (Get-AuditCliArray $listData.BackupVaultList)) {
                $vaultName = [string]$vault.BackupVaultName
                $policyData = Invoke-AWSCLI -Arguments @('backup', 'get-backup-vault-access-policy', '--backup-vault-name', $vaultName) -Region $Region

                $hasPolicy = ($null -ne $policyData)
                $restrictsDelete = $false

                if ($hasPolicy -and $policyData.Policy) {
                    $policyText = [string]$policyData.Policy
                    if ($policyText -match 'backup:DeleteRecoveryPoint') {
                        if ($policyText -match '"Effect"\s*:\s*"Deny"') {
                            $restrictsDelete = $true
                        }
                        if ($policyText -match 'Condition') {
                            $restrictsDelete = $true
                        }
                    }
                }

                $vaultEvidence += @{
                    vault_name       = $vaultName
                    policy_present   = $hasPolicy
                    restricts_delete = $restrictsDelete
                }

                if (-not $hasPolicy -or -not $restrictsDelete) {
                    $failingVaults++
                }
            }

            $evidence = @{
                vault_count    = (Get-AuditCollectionCount $listData.BackupVaultList)
                vaults         = @($vaultEvidence)
                failing_vaults = $failingVaults
            }

            if ($failingVaults -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-06' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Vault access policies restrict recovery point deletion'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-06' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Missing vault policy or unrestricted deletion allowed'
        }

        'BCK-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('backup', 'list-copy-jobs', '--by-state', 'COMPLETED', '--max-results', '100') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-07'
            }

            $copyJobs = @()
            $crossRegionCount = 0

            if (Test-AuditHasProperty -Object $data -PropertyName 'CopyJobs') {
                foreach ($job in (Get-AuditCliArray $data.CopyJobs)) {
                    $destinationArn = [string]$job.DestinationBackupVaultArn
                    $destinationRegion = $null
                    if ($destinationArn -match 'arn:aws:backup:([^:]+):') {
                        $destinationRegion = $Matches[1]
                    }

                    $isCrossRegion = ($destinationRegion -and $destinationRegion -ne $Region)
                    if ($isCrossRegion) {
                        $crossRegionCount++
                    }

                    $copyJobs += @{
                        job_id              = [string]$job.CopyJobId
                        destination_arn     = $destinationArn
                        destination_region  = $destinationRegion
                        cross_region        = $isCrossRegion
                    }
                }
            }

            $evidence = @{
                copy_job_count      = (Get-AuditCollectionCount $copyJobs)
                cross_region_count  = $crossRegionCount
                copy_jobs           = @($copyJobs)
            }

            if ($crossRegionCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-07' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Cross-region backup copies detected'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-07' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No completed cross-region backup copies found'
        }

        'BCK-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('rds', 'describe-db-instances') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-08'
            }

            $instances = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'DBInstances') {
                $instances = @($data.DBInstances)
            }

            if ((Get-AuditCollectionCount $instances) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-08' `
                    -Status 'PARTIAL' -Evidence @{ instance_count = 0 } -Notes 'No RDS instances found in region'
            }

            $failingInstances = @()
            $instanceEvidence = @()

            foreach ($instance in $instances) {
                $retention = 0
                if ((Test-AuditHasProperty -Object $instance -PropertyName 'BackupRetentionPeriod')) {
                    $retention = [int]$instance.BackupRetentionPeriod
                }

                $instanceEvidence += @{
                    instance_id = [string]$instance.DBInstanceIdentifier
                    retention   = $retention
                }

                if ($retention -lt 7) {
                    if ((Get-AuditCollectionCount $failingInstances) -lt 10) {
                        $failingInstances += [string]$instance.DBInstanceIdentifier
                    }
                }
            }

            $evidence = @{
                instance_count      = (Get-AuditCollectionCount $instances)
                instances           = @($instanceEvidence)
                failing_instances   = @($failingInstances)
            }

            if ((Get-AuditCollectionCount $failingInstances) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-08' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more RDS instances have BackupRetentionPeriod below 7 days'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-08' `
                -Status 'PASS' -Evidence $evidence -Notes 'All RDS instances have automated backups retained for at least 7 days'
        }

        'BCK-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $bucketNames = Get-BckS3BucketNames -Region $Region
            if ($null -eq $bucketNames) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-09'
            }

            $criticalBuckets = @()
            foreach ($bucketName in $bucketNames) {
                if (Test-BckBucketNameCritical -BucketName $bucketName) {
                    $criticalBuckets += $bucketName
                }
            }

            if ((Get-AuditCollectionCount $criticalBuckets) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-09' `
                    -Status 'PARTIAL' `
                    -Evidence @{
                        bucket_count          = (Get-AuditCollectionCount $bucketNames)
                        critical_bucket_count = 0
                    } `
                    -Notes 'No critical buckets identified by naming convention (cross-reference DAT-17)'
            }

            $versioningEnabled = 0
            $versioningDisabled = 0
            $bucketEvidence = @()

            foreach ($bucketName in $criticalBuckets) {
                $versionData = Invoke-AWSCLI -Arguments @('s3api', 'get-bucket-versioning', '--bucket', $bucketName) -Region $Region
                $enabled = $false
                if ($versionData -and (Test-AuditHasProperty -Object $versionData -PropertyName 'Status')) {
                    $enabled = ([string]$versionData.Status -eq 'Enabled')
                }

                if ($enabled) {
                    $versioningEnabled++
                }
                else {
                    $versioningDisabled++
                }

                if ((Get-AuditCollectionCount $bucketEvidence) -lt 10) {
                    $bucketEvidence += @{
                        bucket_name = $bucketName
                        versioning  = $enabled
                    }
                }
            }

            $evidence = @{
                critical_bucket_count = (Get-AuditCollectionCount $criticalBuckets)
                versioning_enabled    = $versioningEnabled
                versioning_disabled   = $versioningDisabled
                buckets               = @($bucketEvidence)
            }

            if ($versioningDisabled -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-09' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more critical buckets do not have versioning enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-09' `
                -Status 'PASS' -Evidence $evidence -Notes 'Versioning enabled on critical buckets (aligned with DAT-17)'
        }

        'BCK-10' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('efs', 'describe-file-systems') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-10'
            }

            $fileSystems = @()
            if (Test-AuditHasProperty -Object $data -PropertyName 'FileSystems') {
                $fileSystems = @($data.FileSystems)
            }

            if ((Get-AuditCollectionCount $fileSystems) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-10' `
                    -Status 'PARTIAL' -Evidence @{ efs_count = 0 } -Notes 'No EFS file systems found in region'
            }

            $enabledCount = 0
            $disabledCount = 0
            $efsEvidence = @()

            foreach ($fileSystem in $fileSystems) {
                $fileSystemId = [string]$fileSystem.FileSystemId
                $policyData = Invoke-AWSCLI -Arguments @('efs', 'describe-backup-policy', '--file-system-id', $fileSystemId) -Region $Region

                $status = $null
                if ($policyData -and $policyData.BackupPolicy) {
                    $status = [string]$policyData.BackupPolicy.Status
                }

                if ($status -eq 'ENABLED') {
                    $enabledCount++
                }
                else {
                    $disabledCount++
                }

                if ((Get-AuditCollectionCount $efsEvidence) -lt 10) {
                    $efsEvidence += @{
                        file_system_id = $fileSystemId
                        backup_status  = $status
                    }
                }
            }

            $evidence = @{
                efs_count       = (Get-AuditCollectionCount $fileSystems)
                enabled_count   = $enabledCount
                disabled_count  = $disabledCount
                file_systems    = @($efsEvidence)
            }

            if ($disabledCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-10' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more EFS file systems do not have backup enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-10' `
                -Status 'PASS' -Evidence $evidence -Notes 'EFS backup policy enabled on all file systems'
        }

        'BCK-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $tableNames = New-AuditList
            $exclusiveStart = $null

            do {
                $arguments = @('dynamodb', 'list-tables')
                if ($exclusiveStart) {
                    $arguments += @('--exclusive-start-table-name', $exclusiveStart)
                }

                $listData = Invoke-AWSCLI -Arguments $arguments -Region $Region
                if ($null -eq $listData) {
                    return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-11'
                }

                if (Test-AuditHasProperty -Object $listData -PropertyName 'TableNames') {
                    foreach ($tableName in (Get-AuditCliArray $listData.TableNames)) {
                        [void]$tableNames.Add($tableName)
                    }
                }

                $exclusiveStart = $null
                if ((Test-AuditHasProperty -Object $listData -PropertyName 'LastEvaluatedTableName')) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$listData.LastEvaluatedTableName)) {
                        $exclusiveStart = [string]$listData.LastEvaluatedTableName
                    }
                }
            } while ($exclusiveStart)

            if ((Get-AuditCollectionCount $tableNames) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-11' `
                    -Status 'PARTIAL' -Evidence @{ table_count = 0 } -Notes 'No DynamoDB tables found in region'
            }

            $enabledCount = 0
            $disabledCount = 0
            $tableEvidence = @()

            foreach ($tableName in $tableNames) {
                $backupData = Invoke-AWSCLI -Arguments @('dynamodb', 'describe-continuous-backups', '--table-name', $tableName) -Region $Region
                $pitrStatus = $null

                if ($backupData -and $backupData.ContinuousBackupsDescription -and $backupData.ContinuousBackupsDescription.PointInTimeRecoveryDescription) {
                    $pitrStatus = [string]$backupData.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
                }

                if ($pitrStatus -eq 'ENABLED') {
                    $enabledCount++
                }
                else {
                    $disabledCount++
                }

                if ((Get-AuditCollectionCount $tableEvidence) -lt 10) {
                    $tableEvidence += @{
                        table_name  = $tableName
                        pitr_status = $pitrStatus
                    }
                }
            }

            $evidence = @{
                table_count     = (Get-AuditCollectionCount $tableNames)
                enabled_count   = $enabledCount
                disabled_count  = $disabledCount
                tables          = @($tableEvidence)
            }

            if ($disabledCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-11' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more DynamoDB tables do not have PITR enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-11' `
                -Status 'PASS' -Evidence $evidence -Notes 'Point-in-time recovery enabled on all DynamoDB tables'
        }

        'BCK-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-12' `
                -Notes 'Verify restoration test performed and documented. Check RFC results from 10/06.'
        }

        'BCK-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-13' `
                -Notes 'Verify restoration procedure exists in DEX or backup documentation.'
        }

        'BCK-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $plans = Get-BckBackupPlans -Region $Region
            if ($null -eq $plans) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-14'
            }

            if ((Get-AuditCollectionCount $plans) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-14' `
                    -Status 'FAIL' -Evidence @{ plan_count = 0 } -Notes 'No backup plans found'
            }

            $ruleEvidence = @()
            $failingRules = 0

            foreach ($plan in $plans) {
                $planDetails = Get-BckBackupPlanDetails -Region $Region -BackupPlanId $plan.BackupPlanId
                if ($null -eq $planDetails -or -not (Test-AuditHasProperty -Object $planDetails -PropertyName 'BackupPlan') -or -not (Test-AuditHasProperty -Object $planDetails -PropertyName 'BackupPlan').Rules) {
                    continue
                }

                foreach ($rule in $planDetails.BackupPlan.Rules) {
                    $deleteAfterDays = 0
                    if ($rule.Lifecycle -and $rule.Lifecycle.PSObject.Properties.Name -contains 'DeleteAfterDays') {
                        if ($null -ne $rule.Lifecycle.DeleteAfterDays) {
                            $deleteAfterDays = [int]$rule.Lifecycle.DeleteAfterDays
                        }
                    }

                    $ruleEvidence += @{
                        plan_name         = [string]$plan.BackupPlanName
                        rule_name         = [string]$rule.RuleName
                        delete_after_days = $deleteAfterDays
                    }

                    if ($deleteAfterDays -lt 30) {
                        $failingRules++
                    }
                }
            }

            $evidence = @{
                rule_count     = (Get-AuditCollectionCount $ruleEvidence)
                failing_rules  = $failingRules
                rules          = @($ruleEvidence)
            }

            if ((Get-AuditCollectionCount $ruleEvidence) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-14' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'No backup retention rules found'
            }

            if ($failingRules -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-14' `
                    -Status 'PASS' -Evidence $evidence -Notes 'All backup rules retain data for at least 30 days'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-14' `
                -Status 'FAIL' -Evidence $evidence -Notes 'One or more backup rules have DeleteAfterDays below 30'
        }

        'BCK-15' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-15' `
                -Notes 'Verify PCA in SIPedia was RSSI-approved. Check DIMA 4h / SLA 99.9%.'
        }

        'BCK-16' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-16' `
                -Notes 'Known: only firewall failover tested. RSSI derogation to confirm formally.'
        }

        'BCK-17' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-17' `
                -Notes 'Known: DIMA 4h not tested in real conditions.'
        }

        'BCK-18' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-18' `
                -Notes 'Known: DR covers only crypto-locking and cyber-attack, not region loss.'
        }

        'BCK-19' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-19' `
                -Notes 'Verify RSSI formally approved PCA and DR strategy.'
        }

        'BCK-20' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $resources = New-AuditList
            $token = $null

            do {
                $arguments = @('backup', 'list-protected-resources')
                if ($token) {
                    $arguments += @('--next-token', $token)
                }

                $data = Invoke-AWSCLI -Arguments $arguments -Region $Region
                if ($null -eq $data) {
                    return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-20'
                }

                if (Test-AuditHasProperty -Object $data -PropertyName 'Results') {
                    foreach ($resource in (Get-AuditCliArray $data.Results)) {
                        [void]$resources.Add($resource)
                    }
                }

                $token = $null
                if ((Test-AuditHasProperty -Object $data -PropertyName 'NextToken')) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$data.NextToken)) {
                        $token = [string]$data.NextToken
                    }
                }
            } while ($token)

            $typeCounts = @{}
            foreach ($resource in $resources) {
                $resourceType = [string]$resource.ResourceType
                if (-not $typeCounts.ContainsKey($resourceType)) {
                    $typeCounts[$resourceType] = 0
                }
                $typeCounts[$resourceType] = $typeCounts[$resourceType] + 1
            }

            $hasEc2 = ($typeCounts.ContainsKey('EC2')) -or ($typeCounts.ContainsKey('EBS'))
            $hasRds = ($typeCounts.ContainsKey('RDS')) -or ($typeCounts.ContainsKey('Aurora'))
            $hasEfs = ($typeCounts.ContainsKey('EFS'))

            $evidence = @{
                protected_resource_count = (Get-AuditCollectionCount $resources)
                resource_type_counts     = $typeCounts
            }

            if ($hasEc2 -and $hasRds -and $hasEfs) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-20' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Protected resources include EC2, RDS, and EFS'
            }

            if ((Get-AuditCollectionCount $resources) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-20' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'No protected backup resources found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'BCK-20' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'Backup coverage exists but not all socle critical resource types are protected'
        }
    }
}
