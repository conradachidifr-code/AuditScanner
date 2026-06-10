$DomainSeverity = @{
    'DET-01' = 'P0'
    'DET-02' = 'P1'
    'DET-03' = 'P1'
    'DET-04' = 'P2'
}

function Get-DomainChecks {
    return [ordered]@{
        'DET-01' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $data = Invoke-AWSCLI -Arguments @('guardduty', 'list-detectors') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DET-01'
            }

            $detectorCount = 0
            if (Test-AuditHasProperty -Object $data -PropertyName 'DetectorIds') {
                $detectorCount = (Get-AuditCollectionCount $data.DetectorIds)
            }

            if ($detectorCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DET-01' `
                    -Status 'PASS' `
                    -Evidence @{ detector_count = $detectorCount } `
                    -Notes 'GuardDuty detector is enabled'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DET-01' `
                -Status 'FAIL' `
                -Evidence @{ detector_count = 0 } `
                -Notes 'No GuardDuty detector found in region'
        }

        'DET-02' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $data = Invoke-AWSCLI -Arguments @('securityhub', 'describe-hub') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DET-02'
            }

            $hubArn = $null
            if (Test-AuditHasProperty -Object $data -PropertyName 'HubArn') {
                $hubArn = [string]$data.HubArn
            }

            if ($hubArn) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DET-02' `
                    -Status 'PASS' `
                    -Evidence @{ hub_arn = $hubArn } `
                    -Notes 'Security Hub is enabled in region'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DET-02' `
                -Status 'FAIL' `
                -Evidence $null `
                -Notes 'Security Hub is not enabled in region'
        }

        'DET-03' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            $gate = Get-GlobalControlGate -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DET-03'
            if ($gate) {
                return $gate
            }

            $data = Invoke-AWSCLI -Arguments @('securityhub', 'get-enabled-standards') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'DET-03'
            }

            $standardCount = 0
            if (Test-AuditHasProperty -Object $data -PropertyName 'StandardsSubscriptions') {
                $standardCount = (Get-AuditCollectionCount $data.StandardsSubscriptions)
            }

            if ($standardCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId `
                    -AccountName $AccountName `
                    -Region $Region `
                    -ControlId 'DET-03' `
                    -Status 'PASS' `
                    -Evidence @{ enabled_standards_count = $standardCount } `
                    -Notes 'Security Hub standards are subscribed'
            }

            return New-AuditResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DET-03' `
                -Status 'FAIL' `
                -Evidence @{ enabled_standards_count = 0 } `
                -Notes 'No Security Hub standards subscribed'
        }

        'DET-04' = {
            param(
                [string]$AccountId,
                [string]$AccountName,
                [string]$Region
            )

            return New-WorkshopControlResult `
                -AccountId $AccountId `
                -AccountName $AccountName `
                -Region $Region `
                -ControlId 'DET-04' `
                -Notes 'Workshop control: verify Detective or third-party SIEM integration and alert routing manually'
        }
    }
}
