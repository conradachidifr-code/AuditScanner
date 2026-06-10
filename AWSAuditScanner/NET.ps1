$DomainSeverity = @{
    'NET-01' = 'P0'
    'NET-02' = 'P0'
    'NET-03' = 'P0'
    'NET-04' = 'P0'
    'NET-05' = 'P0'
    'NET-06' = 'P0'
    'NET-07' = 'P0'
    'NET-08' = 'P0'
    'NET-09' = 'P0'
    'NET-10' = 'P0'
    'NET-11' = 'P0'
    'NET-12' = 'P0'
    'NET-13' = 'P0'
    'NET-14' = 'P0'
    'NET-15' = 'P0'
    'NET-16' = 'P2'
    'NET-17' = 'P0'
    'NET-19' = 'P0'
    'NET-20' = 'P0'
    'NET-21' = 'P0'
    'NET-22' = 'P0'
    'NET-23' = 'P0'
    'NET-24' = 'P0'
    'NET-25' = 'P0'
    'NET-26' = 'P0'
    'NET-27' = 'P0'
}

$Script:NetAnyCidr = '0.0.0.0/0'

function Get-NetCliArray {
    param(
        $Items
    )

    if ($null -eq $Items) {
        return @()
    }

    # Generic.List[object] — call ToArray() explicitly to avoid ArgumentException under StrictMode PS 5.1
    if ($Items -is [System.Collections.Generic.List[object]]) {
        return $Items.ToArray()
    }

    if ($Items -is [System.Array]) {
        return @($Items)
    }

    return @($Items)
}

function Test-NetHasProperty {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $false
    }

    if ($Object -is [System.Collections.IDictionary]) {
        return $Object.Contains($PropertyName)
    }

    return ($Object.PSObject.Properties.Name -contains $PropertyName)
}

function New-NetList {
    return New-Object 'System.Collections.Generic.List[object]'
}

function Get-NetCollectionCount {
    param(
        $Items
    )

    if ($null -eq $Items) {
        return 0
    }

    return @((Get-NetCliArray $Items)).Length
}

function Get-NetRouteTables {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-route-tables') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-NetHasProperty -Object $data -PropertyName 'RouteTables') {
        return Get-NetCliArray $data.RouteTables
    }

    return @()
}

function Get-NetSubnets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-subnets') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-NetHasProperty -Object $data -PropertyName 'Subnets') {
        return Get-NetCliArray $data.Subnets
    }

    return @()
}

function Get-NetVpcs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpcs') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-NetHasProperty -Object $data -PropertyName 'Vpcs') {
        return Get-NetCliArray $data.Vpcs
    }

    return @()
}

function Get-NetSecurityGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-security-groups') -Region $Region
    if ($null -eq $data) {
        return $null
    }

    if (Test-NetHasProperty -Object $data -PropertyName 'SecurityGroups') {
        return Get-NetCliArray $data.SecurityGroups
    }

    return @()
}

function Test-NetRouteTableHasIgwRoute {
    param(
        [Parameter(Mandatory = $true)]
        $RouteTable
    )

    if (-not (Test-NetHasProperty -Object $RouteTable -PropertyName 'Routes')) {
        return $false
    }

    foreach ($route in (Get-NetCliArray $RouteTable.Routes)) {
        if (-not (Test-NetHasProperty -Object $route -PropertyName 'GatewayId')) {
            continue
        }

        if ($route.GatewayId -and [string]$route.GatewayId -like 'igw-*') {
            $destination = ''
            if (Test-NetHasProperty -Object $route -PropertyName 'DestinationCidrBlock') {
                $destination = [string]$route.DestinationCidrBlock
            }

            if ($destination -eq $Script:NetAnyCidr) {
                return $true
            }
        }
    }

    return $false
}

function Get-NetSubnetRouteTableMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $routeTables = Get-NetRouteTables -Region $Region
    $subnets = Get-NetSubnets -Region $Region
    if ($null -eq $routeTables -or $null -eq $subnets) {
        return $null
    }

    $mainRouteTables = @{}
    foreach ($routeTable in $routeTables) {
        if (-not (Test-NetHasProperty -Object $routeTable -PropertyName 'Associations')) {
            continue
        }

        foreach ($association in (Get-NetCliArray $routeTable.Associations)) {
            if ((Test-NetHasProperty -Object $association -PropertyName 'Main') -and ($association.Main -eq $true)) {
                $mainRouteTables[[string]$routeTable.VpcId] = $routeTable
            }
        }
    }

    $subnetMap = @{}
    foreach ($subnet in $subnets) {
        $subnetId = [string]$subnet.SubnetId
        $vpcId = [string]$subnet.VpcId
        $matchedRouteTable = $null

        foreach ($routeTable in $routeTables) {
            if (-not (Test-NetHasProperty -Object $routeTable -PropertyName 'Associations')) {
                continue
            }

            foreach ($association in (Get-NetCliArray $routeTable.Associations)) {
                if ((Test-NetHasProperty -Object $association -PropertyName 'SubnetId') -and ([string]$association.SubnetId -eq $subnetId)) {
                    $matchedRouteTable = $routeTable
                    break
                }
            }
            if ($matchedRouteTable) { break }
        }

        if (-not $matchedRouteTable -and $mainRouteTables.ContainsKey($vpcId)) {
            $matchedRouteTable = $mainRouteTables[$vpcId]
        }

        $isPublic = $false
        if ($matchedRouteTable) {
            $isPublic = Test-NetRouteTableHasIgwRoute -RouteTable $matchedRouteTable
        }

        $subnetMap[$subnetId] = @{
            vpc_id    = $vpcId
            is_public = $isPublic
        }
    }

    return $subnetMap
}

function Test-NetPermissionOpenToInternet {
    param(
        [Parameter(Mandatory = $true)]
        $Permission
    )

    if (-not (Test-NetHasProperty -Object $Permission -PropertyName 'IpRanges')) {
        return $false
    }

    foreach ($range in (Get-NetCliArray $Permission.IpRanges)) {
        if ((Test-NetHasProperty -Object $range -PropertyName 'CidrIp') -and ([string]$range.CidrIp -eq $Script:NetAnyCidr)) {
            return $true
        }
    }

    return $false
}

function Get-NetTagValueByKey {
    param(
        $Tags,
        [string]$KeyName
    )

    foreach ($tag in (Get-NetCliArray $Tags)) {
        if ((Test-NetHasProperty -Object $tag -PropertyName 'Key') -and ([string]$tag.Key -eq $KeyName)) {
            if (Test-NetHasProperty -Object $tag -PropertyName 'Value') {
                return [string]$tag.Value
            }
            return $null
        }
    }

    return $null
}

function Test-NetEnvironmentName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('prod', 'nonprod')]
        [string]$EnvironmentType
    )

    $lowerName = $Name.ToLower()
    if ($EnvironmentType -eq 'prod') {
        if ($lowerName -match 'prod' -and $lowerName -notmatch 'nonprod|non-prod|preprod|uat|dev|test|sandbox') {
            return $true
        }
        return $false
    }

    if ($lowerName -match 'nonprod|non-prod|dev|test|uat|sandbox|preprod') {
        return $true
    }

    return $false
}

function Get-DomainChecks {
    return [ordered]@{
        'NET-01' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-01' `
                -Notes 'Verify DAT contains network topology, VPC segmentation, encryption boundaries. Check SIPedia version.'
        }

        'NET-02' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $vpcs = Get-NetVpcs -Region $Region
            if ($null -eq $vpcs) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-02'
            }

            $vpcList = @(Get-NetCliArray $vpcs)
            $vpcEvidence = New-Object 'System.Collections.Generic.List[object]'
            foreach ($vpc in $vpcList) {
                $vpcName = $null
                if (Test-NetHasProperty -Object $vpc -PropertyName 'Tags') {
                    $vpcName = Get-NetTagValueByKey -Tags $vpc.Tags -KeyName 'Name'
                }

                $vpcRecord = @{
                    vpc_id     = [string]$vpc.VpcId
                    cidr_block = [string]$vpc.CidrBlock
                    name       = $vpcName
                }
                [void]$vpcEvidence.Add($vpcRecord)
            }

            $vpcCount = Get-NetCollectionCount $vpcList
            $evidence = @{
                vpc_count = $vpcCount
                vpcs      = @($vpcEvidence.ToArray())
            }
            if ($vpcCount -gt 1) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-02' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Multiple VPCs provide environment segmentation'
            }

            if ($vpcCount -eq 1) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-02' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Single VPC in account; verify cross-account segmentation'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-02' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No VPCs found'
        }

        'NET-03' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $subnetMap = Get-NetSubnetRouteTableMap -Region $Region
            if ($null -eq $subnetMap) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-03'
            }

            $vpcStats = @{}
            foreach ($subnetId in $subnetMap.Keys) {
                $entry = $subnetMap[$subnetId]
                $vpcId = $entry.vpc_id
                if (-not $vpcStats.ContainsKey($vpcId)) {
                    $vpcStats[$vpcId] = @{
                        public_count  = 0
                        private_count = 0
                    }
                }

                if ($entry.is_public) {
                    $vpcStats[$vpcId].public_count = $vpcStats[$vpcId].public_count + 1
                }
                else {
                    $vpcStats[$vpcId].private_count = $vpcStats[$vpcId].private_count + 1
                }
            }

            $failingVpcs = New-Object 'System.Collections.Generic.List[object]'
            $passingVpcs = New-Object 'System.Collections.Generic.List[object]'
            foreach ($vpcId in @($vpcStats.Keys)) {
                $stats = $vpcStats[$vpcId]
                if ($stats.public_count -gt 0 -and $stats.private_count -gt 0) {
                    $passingVpcRecord = @{
                        vpc_id        = $vpcId
                        public_count  = $stats.public_count
                        private_count = $stats.private_count
                    }
                    [void]$passingVpcs.Add($passingVpcRecord)
                }
                elseif ($stats.public_count -gt 0 -and $stats.private_count -eq 0) {
                    $failingVpcRecord = @{
                        vpc_id        = $vpcId
                        public_count  = $stats.public_count
                        private_count = 0
                    }
                    [void]$failingVpcs.Add($failingVpcRecord)
                }
            }

            $evidence = @{
                vpc_count     = ([array]@($vpcStats.Keys)).Count
                passing_vpcs  = @($passingVpcs.ToArray())
                failing_vpcs  = @($failingVpcs.ToArray())
            }

            if ((Get-NetCollectionCount $failingVpcs) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-03' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'One or more VPCs have only public subnets'
            }

            if ((Get-NetCollectionCount $passingVpcs) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-03' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Public and private subnets exist per VPC'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-03' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'No clear public/private subnet separation detected'
        }

        'NET-04' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $routeTables = Get-NetRouteTables -Region $Region
            if ($null -eq $routeTables) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-04'
            }

            $igwRouteTableCount = 0
            $mainTableWithIgw = New-NetList
            $subnetAssociatedIgwTables = New-NetList

            foreach ($routeTable in $routeTables) {
                if (-not (Test-NetRouteTableHasIgwRoute -RouteTable $routeTable)) {
                    continue
                }

                $igwRouteTableCount++
                $isMain = $false
                $associatedSubnets = New-NetList

                if (Test-NetHasProperty -Object $routeTable -PropertyName 'Associations') {
                    foreach ($association in (Get-NetCliArray $routeTable.Associations)) {
                        if ((Test-NetHasProperty -Object $association -PropertyName 'Main') -and ($association.Main -eq $true)) {
                            $isMain = $true
                        }
                        if (Test-NetHasProperty -Object $association -PropertyName 'SubnetId') {
                            [void]$associatedSubnets.Add([string]$association.SubnetId)
                        }
                    }
                }

                if ($isMain) {
                    if ((Get-NetCollectionCount $mainTableWithIgw) -lt 10) {
                        [void]$mainTableWithIgw.Add([string]$routeTable.RouteTableId)
                    }
                }
                elseif ((Get-NetCollectionCount $associatedSubnets) -gt 0) {
                    if ((Get-NetCollectionCount $subnetAssociatedIgwTables) -lt 10) {
                        [void]$subnetAssociatedIgwTables.Add([string]$routeTable.RouteTableId)
                    }
                }
            }

            $evidence = @{
                route_table_count              = (Get-NetCollectionCount $routeTables)
                igw_route_table_count          = $igwRouteTableCount
                main_route_tables_with_igw     = @($mainTableWithIgw)
                subnet_associated_igw_tables   = @($subnetAssociatedIgwTables)
            }

            if ((Get-NetCollectionCount $mainTableWithIgw) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-04' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Main route table routes private subnets to an Internet Gateway'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-04' `
                -Status 'PASS' -Evidence $evidence -Notes 'Internet Gateway routes limited to non-main route tables'
        }

        'NET-05' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-internet-gateways') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-05'
            }

            $igws = @()
            if (Test-NetHasProperty -Object $data -PropertyName 'InternetGateways') {
                $igws = Get-NetCliArray $data.InternetGateways
            }

            $attachedVpcIds = New-NetList
            foreach ($igw in $igws) {
                if (-not (Test-NetHasProperty -Object $igw -PropertyName 'Attachments')) {
                    continue
                }

                foreach ($attachment in (Get-NetCliArray $igw.Attachments)) {
                    if (Test-NetHasProperty -Object $attachment -PropertyName 'VpcId') {
                        [void]$attachedVpcIds.Add([string]$attachment.VpcId)
                    }
                }
            }

            $igwCount = (Get-NetCollectionCount $igws)
            $evidence = @{
                igw_count        = $igwCount
                attached_vpc_ids = @($attachedVpcIds)
            }

            if ($igwCount -le (Get-NetCollectionCount $attachedVpcIds)) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-05' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Internet Gateway usage appears limited to attached VPCs'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-05' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'Review Internet Gateway attachments for unnecessary exposure'
        }

        'NET-06' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $subnetMap = Get-NetSubnetRouteTableMap -Region $Region
            $natData = Invoke-AWSCLI -Arguments @('ec2', 'describe-nat-gateways', '--filter', 'Name=state,Values=available') -Region $Region

            if ($null -eq $subnetMap -or $null -eq $natData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-06'
            }

            $privateVpcIds = @{}
            foreach ($subnetId in $subnetMap.Keys) {
                if (-not $subnetMap[$subnetId].is_public) {
                    $privateVpcIds[$subnetMap[$subnetId].vpc_id] = $true
                }
            }

            $natGateways = @()
            if (Test-NetHasProperty -Object $natData -PropertyName 'NatGateways') {
                $natGateways = Get-NetCliArray $natData.NatGateways
            }

            $natVpcIds = New-NetList
            foreach ($nat in $natGateways) {
                if (Test-NetHasProperty -Object $nat -PropertyName 'VpcId') {
                    [void]$natVpcIds.Add([string]$nat.VpcId)
                }
            }

            $evidence = @{
                private_vpc_count = @($privateVpcIds.Keys).Length
                nat_gateway_count   = Get-NetCollectionCount $natGateways
                nat_vpc_ids         = @($natVpcIds)
            }

            if (@($privateVpcIds.Keys).Length -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-06' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'No private subnets detected'
            }

            if ((Get-NetCollectionCount $natGateways) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-06' `
                    -Status 'PASS' -Evidence $evidence -Notes 'NAT Gateways exist for private subnet egress'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-06' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Private subnets exist but no NAT Gateways found'
        }

        'NET-07' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $firewallData = Invoke-AWSCLI -Arguments @('network-firewall', 'list-firewalls') -Region $Region
            $securityGroups = Get-NetSecurityGroups -Region $Region

            if ($null -eq $firewallData -and $null -eq $securityGroups) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-07'
            }

            $firewallCount = 0
            if ($firewallData -and (Test-NetHasProperty -Object $firewallData -PropertyName 'Firewalls')) {
                $firewallCount = Get-NetCollectionCount $firewallData.Firewalls
            }

            $unrestrictedEgressCount = 0
            if ($securityGroups) {
                foreach ($sg in $securityGroups) {
                    if (-not (Test-NetHasProperty -Object $sg -PropertyName 'IpPermissionsEgress')) { continue }
                    foreach ($rule in (Get-NetCliArray $sg.IpPermissionsEgress)) {
                        $openInternet = Test-NetPermissionOpenToInternet -Permission $rule
                        $allTraffic = ((Test-NetHasProperty -Object $rule -PropertyName 'IpProtocol') -and ($rule.IpProtocol -eq '-1'))
                        if ($openInternet -and $allTraffic) {
                            $unrestrictedEgressCount++
                            break
                        }
                    }
                }
            }

            $evidence = @{
                firewall_count              = $firewallCount
                unrestricted_egress_sg_count = $unrestrictedEgressCount
            }

            if ($firewallCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-07' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Network Firewall deployed for egress filtering'
            }

            if ($unrestrictedEgressCount -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-07' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Security groups do not allow unrestricted egress'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-07' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No Network Firewall and unrestricted egress security groups found'
        }

        'NET-08' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $securityGroups = Get-NetSecurityGroups -Region $Region
            if ($null -eq $securityGroups) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-08'
            }

            $offendingGroups = New-NetList
            foreach ($sg in $securityGroups) {
                if (-not (Test-NetHasProperty -Object $sg -PropertyName 'IpPermissions')) { continue }

                foreach ($rule in (Get-NetCliArray $sg.IpPermissions)) {
                    if (-not (Test-NetPermissionOpenToInternet -Permission $rule)) {
                        continue
                    }

                    $fromPort = 0
                    $toPort = 65535
                    if ((Test-NetHasProperty -Object $rule -PropertyName 'FromPort') -and $null -ne $rule.FromPort) {
                        $fromPort = [int]$rule.FromPort
                    }
                    if ((Test-NetHasProperty -Object $rule -PropertyName 'ToPort') -and $null -ne $rule.ToPort) {
                        $toPort = [int]$rule.ToPort
                    }

                    $allProtocols = ((Test-NetHasProperty -Object $rule -PropertyName 'IpProtocol') -and ($rule.IpProtocol -eq '-1'))
                    $allowsSsh = ($fromPort -le 22 -and $toPort -ge 22) -or $allProtocols
                    $allowsRdp = ($fromPort -le 3389 -and $toPort -ge 3389) -or $allProtocols

                    if ($allowsSsh -or $allowsRdp) {
                        if ((Get-NetCollectionCount $offendingGroups) -lt 10) {
                            [void]$offendingGroups.Add([string]$sg.GroupId)
                        }
                        break
                    }
                }
            }

            $evidence = @{
                offending_security_group_ids = @($offendingGroups)
            }

            if ((Get-NetCollectionCount $offendingGroups) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-08' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Security groups allow SSH or RDP from the internet'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-08' `
                -Status 'PASS' -Evidence $evidence -Notes 'No internet-exposed SSH or RDP rules found'
        }

        'NET-09' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $ssmData = Invoke-AWSCLI -Arguments @('ssm', 'describe-instance-information') -Region $Region
            $securityGroups = Get-NetSecurityGroups -Region $Region

            if ($null -eq $ssmData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-09'
            }

            $managedCount = 0
            if (Test-NetHasProperty -Object $ssmData -PropertyName 'InstanceInformationList') {
                $managedCount = Get-NetCollectionCount $ssmData.InstanceInformationList
            }

            $internetAdminExposure = $false
            if ($securityGroups) {
                foreach ($sg in $securityGroups) {
                    if (-not (Test-NetHasProperty -Object $sg -PropertyName 'IpPermissions')) { continue }
                    foreach ($rule in (Get-NetCliArray $sg.IpPermissions)) {
                        if (-not (Test-NetPermissionOpenToInternet -Permission $rule)) { continue }
                        $fromPort = 0
                        $toPort = 65535
                        if ((Test-NetHasProperty -Object $rule -PropertyName 'FromPort') -and $null -ne $rule.FromPort) {
                            $fromPort = [int]$rule.FromPort
                        }
                        if ((Test-NetHasProperty -Object $rule -PropertyName 'ToPort') -and $null -ne $rule.ToPort) {
                            $toPort = [int]$rule.ToPort
                        }
                        $allProtocols = ((Test-NetHasProperty -Object $rule -PropertyName 'IpProtocol') -and ($rule.IpProtocol -eq '-1'))
                        if (($fromPort -le 22 -and $toPort -ge 22) -or ($fromPort -le 3389 -and $toPort -ge 3389) -or $allProtocols) {
                            $internetAdminExposure = $true
                            break
                        }
                    }
                    if ($internetAdminExposure) { break }
                }
            }

            $evidence = @{
                ssm_managed_instance_count = $managedCount
                internet_admin_exposure    = $internetAdminExposure
            }

            if ($managedCount -gt 0 -and -not $internetAdminExposure) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-09' `
                    -Status 'PASS' -Evidence $evidence -Notes 'SSM-managed instances exist with no internet admin access'
            }

            if ($internetAdminExposure) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-09' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Internet-exposed admin ports found despite SSM availability'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-09' `
                -Status 'PARTIAL' -Evidence $evidence -Notes 'No SSM-managed instances detected'
        }

        'NET-10' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $securityGroups = Get-NetSecurityGroups -Region $Region
            if ($null -eq $securityGroups) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-10'
            }

            $openGroups = New-NetList
            foreach ($sg in $securityGroups) {
                if (-not (Test-NetHasProperty -Object $sg -PropertyName 'IpPermissions')) { continue }
                foreach ($rule in (Get-NetCliArray $sg.IpPermissions)) {
                    $allProtocols = ((Test-NetHasProperty -Object $rule -PropertyName 'IpProtocol') -and ($rule.IpProtocol -eq '-1'))
                    if ((Test-NetPermissionOpenToInternet -Permission $rule) -and $allProtocols) {
                        if ((Get-NetCollectionCount $openGroups) -lt 10) {
                            [void]$openGroups.Add([string]$sg.GroupId)
                        }
                        break
                    }
                }
            }

            $evidence = @{
                security_group_count = (Get-NetCollectionCount $securityGroups)
                open_all_traffic_sgs = @($openGroups)
            }

            if ((Get-NetCollectionCount $openGroups) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-10' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Security groups allow all traffic from the internet'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-10' `
                -Status 'PASS' -Evidence $evidence -Notes 'No all-traffic internet inbound rules found'
        }

        'NET-11' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-network-acls') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-11'
            }

            $acls = @()
            if (Test-NetHasProperty -Object $data -PropertyName 'NetworkAcls') {
                $acls = Get-NetCliArray $data.NetworkAcls
            }

            $customAclCount = 0
            foreach ($acl in $acls) {
                if ($acl.IsDefault -eq $true) {
                    continue
                }
                $customAclCount++
            }

            $evidence = @{
                nacl_count        = Get-NetCollectionCount $acls
                custom_nacl_count = $customAclCount
                default_nacl_count = ((Get-NetCollectionCount $acls) - $customAclCount)
            }

            if ($customAclCount -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-11' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Custom NACLs exist beyond default allow-all'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-11' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Only default NACLs detected'
        }

        'NET-12' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $peeringData = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpc-peering-connections') -Region $Region
            $tgwAttachData = Invoke-AWSCLI -Arguments @('ec2', 'describe-transit-gateway-attachments') -Region $Region

            if ($null -eq $peeringData -and $null -eq $tgwAttachData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-12'
            }

            $peeringCount = 0
            if ($peeringData -and (Test-NetHasProperty -Object $peeringData -PropertyName 'VpcPeeringConnections')) {
                $peeringCount = Get-NetCollectionCount $peeringData.VpcPeeringConnections
            }

            $attachmentCount = 0
            if ($tgwAttachData -and (Test-NetHasProperty -Object $tgwAttachData -PropertyName 'TransitGatewayAttachments')) {
                $attachmentCount = Get-NetCollectionCount $tgwAttachData.TransitGatewayAttachments
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-12' `
                -Status 'PARTIAL' `
                -Evidence @{
                    peering_count           = $peeringCount
                    tgw_attachment_count    = $attachmentCount
                } `
                -Notes 'Review inter-VPC flows against approved connectivity matrix'
        }

        'NET-13' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $tgwData = Invoke-AWSCLI -Arguments @('ec2', 'describe-transit-gateways') -Region $Region
            $attachData = Invoke-AWSCLI -Arguments @('ec2', 'describe-transit-gateway-attachments') -Region $Region

            if ($null -eq $tgwData -and $null -eq $attachData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-13'
            }

            $tgwIds = New-NetList
            if ($tgwData -and (Test-NetHasProperty -Object $tgwData -PropertyName 'TransitGateways')) {
                foreach ($tgw in (Get-NetCliArray $tgwData.TransitGateways)) {
                    if (Test-NetHasProperty -Object $tgw -PropertyName 'TransitGatewayId') {
                        [void]$tgwIds.Add([string]$tgw.TransitGatewayId)
                    }
                }
            }

            $attachments = New-NetList
            if ($attachData -and (Test-NetHasProperty -Object $attachData -PropertyName 'TransitGatewayAttachments')) {
                foreach ($attachment in (Get-NetCliArray $attachData.TransitGatewayAttachments)) {
                    $attachmentRecord = @{
                        attachment_id = [string]$attachment.TransitGatewayAttachmentId
                        resource_id   = [string]$attachment.ResourceId
                        resource_type = [string]$attachment.ResourceType
                    }
                    [void]$attachments.Add($attachmentRecord)
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-13' `
                -Status 'PARTIAL' `
                -Evidence @{
                    tgw_ids           = @($tgwIds.ToArray())
                    attachment_count  = Get-NetCollectionCount $attachments
                    attachments       = @($attachments.ToArray())
                } `
                -Notes 'Review TGW attachments for justification and least connectivity'
        }

        'NET-14' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpc-endpoints') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-14'
            }

            $requiredServices = @('.s3', '.ssm', '.secretsmanager', '.kms')
            $foundServices = New-NetList
            $serviceNames = New-NetList
            $requiredMissing = New-NetList

            if (Test-NetHasProperty -Object $data -PropertyName 'VpcEndpoints') {
                foreach ($endpoint in (Get-NetCliArray $data.VpcEndpoints)) {
                    $serviceName = [string]$endpoint.ServiceName
                    [void]$serviceNames.Add($serviceName)
                    foreach ($required in $requiredServices) {
                        if ($serviceName -like ('*{0}' -f $required)) {
                            if (-not ($foundServices -contains $required)) {
                                [void]$foundServices.Add($required)
                            }
                        }
                    }
                }
            }

            $endpointCount = 0
            if (Test-NetHasProperty -Object $data -PropertyName 'VpcEndpoints') {
                $endpointCount = Get-NetCollectionCount $data.VpcEndpoints
            }

            foreach ($required in $requiredServices) {
                if (-not ($foundServices -contains $required)) {
                    [void]$requiredMissing.Add($required)
                }
            }

            $evidence = @{
                endpoint_count   = $endpointCount
                service_names    = @($serviceNames.ToArray())
                required_found   = @($foundServices.ToArray())
                required_missing = @($requiredMissing.ToArray())
            }

            if ((Get-NetCollectionCount $foundServices) -eq (Get-NetCollectionCount $requiredServices)) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-14' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Required private endpoints are present'
            }

            if ((Get-NetCollectionCount $foundServices) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-14' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Some required private endpoints are missing'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-14' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No required private endpoints found'
        }

        'NET-15' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('route53resolver', 'list-resolver-endpoints') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-15'
            }

            $endpoints = New-NetList
            if (Test-NetHasProperty -Object $data -PropertyName 'ResolverEndpoints') {
                foreach ($endpoint in (Get-NetCliArray $data.ResolverEndpoints)) {
                    $endpointRecord = @{
                        id        = [string]$endpoint.Id
                        direction = [string]$endpoint.Direction
                        status    = [string]$endpoint.Status
                    }
                    [void]$endpoints.Add($endpointRecord)
                }
            }

            $evidence = @{
                resolver_endpoint_count = Get-NetCollectionCount $endpoints
                endpoints               = @($endpoints.ToArray())
            }

            if ((Get-NetCollectionCount $endpoints) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-15' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Route53 resolver endpoints configured'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-15' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No Route53 resolver endpoints configured'
        }

        'NET-16' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $firewallData = Invoke-AWSCLI -Arguments @('network-firewall', 'list-firewalls') -Region $Region
            if ($null -eq $firewallData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-16'
            }

            $firewallCount = 0
            if (Test-NetHasProperty -Object $firewallData -PropertyName 'Firewalls') {
                $firewallCount = Get-NetCollectionCount $firewallData.Firewalls
            }

            if ($firewallCount -eq 0) {
                return New-WorkshopControlResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-16' `
                    -Notes 'Verify if east-west traffic inspection is required and implemented.'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-16' `
                -Status 'PARTIAL' `
                -Evidence @{ firewall_count = $firewallCount } `
                -Notes 'Network Firewall present; verify sensitive east-west flows are inspected'
        }

        'NET-17' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $lbData = Invoke-AWSCLI -Arguments @('elbv2', 'describe-load-balancers') -Region $Region
            if ($null -eq $lbData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-17'
            }

            $internetFacing = New-NetList
            if (Test-NetHasProperty -Object $lbData -PropertyName 'LoadBalancers') {
                foreach ($lb in (Get-NetCliArray $lbData.LoadBalancers)) {
                    if ([string]$lb.Scheme -eq 'internet-facing') {
                        [void]$internetFacing.Add($lb)
                    }
                }
            }

            if ((Get-NetCollectionCount $internetFacing) -eq 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-17' `
                    -Status 'PARTIAL' -Evidence @{ internet_facing_alb_count = 0 } `
                    -Notes 'No internet-facing ALBs found in region'
            }

            $failingAlbs = New-NetList
            $passingAlbs = New-NetList

            foreach ($lb in $internetFacing) {
                $lbName = [string]$lb.LoadBalancerName
                $lbArn = [string]$lb.LoadBalancerArn

                $listenerData = Invoke-AWSCLI -Arguments @('elbv2', 'describe-listeners', '--load-balancer-arn', $lbArn) -Region $Region
                $hasHttps = $false
                $httpWithoutRedirect = $false

                if ($listenerData -and (Test-NetHasProperty -Object $listenerData -PropertyName 'Listeners')) {
                    foreach ($listener in (Get-NetCliArray $listenerData.Listeners)) {
                        if ([string]$listener.Protocol -eq 'HTTPS') {
                            $hasHttps = $true
                        }
                        if ([string]$listener.Protocol -eq 'HTTP') {
                            $hasRedirect = $false
                            if (Test-NetHasProperty -Object $listener -PropertyName 'DefaultActions') {
                                foreach ($action in (Get-NetCliArray $listener.DefaultActions)) {
                                    if ($action.Type -eq 'redirect') {
                                        $hasRedirect = $true
                                    }
                                }
                            }
                            if (-not $hasRedirect) {
                                $httpWithoutRedirect = $true
                            }
                        }
                    }
                }

                $wafData = Invoke-AWSCLI -Arguments @('wafv2', 'get-web-acl-for-resource', '--resource-arn', $lbArn) -Region $Region
                $hasWaf = ($null -ne $wafData -and (Test-NetHasProperty -Object $wafData -PropertyName 'WebACL'))

                if ($hasHttps -and $hasWaf -and -not $httpWithoutRedirect) {
                    $passingAlbRecord = @{
                        name   = $lbName
                        scheme = [string]$lb.Scheme
                    }
                    [void]$passingAlbs.Add($passingAlbRecord)
                }
                else {
                    $failingAlbRecord = @{
                        name                  = $lbName
                        scheme                = [string]$lb.Scheme
                        https                 = $hasHttps
                        waf                   = $hasWaf
                        http_without_redirect = $httpWithoutRedirect
                    }
                    [void]$failingAlbs.Add($failingAlbRecord)
                }
            }

            $evidence = @{
                internet_facing_alb_count = Get-NetCollectionCount $internetFacing
                passing_albs              = @($passingAlbs.ToArray())
                failing_albs              = @($failingAlbs.ToArray())
            }

            if ((Get-NetCollectionCount $failingAlbs) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-17' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Internet-facing ALB missing HTTPS, WAF, or uses HTTP without redirect'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-17' `
                -Status 'PASS' -Evidence $evidence -Notes 'Internet-facing ALBs are hardened with HTTPS and WAF'
        }

        'NET-19' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('shield', 'describe-subscription') -Region 'us-east-1'
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-19'
            }

            $subscriptionArn = $null
            if ($data.Subscription) {
                if ($data.Subscription.SubscriptionArn) {
                    $subscriptionArn = [string]$data.Subscription.SubscriptionArn
                }
            }

            $evidence = @{
                subscription_arn = $subscriptionArn
                checked_region   = 'us-east-1'
            }

            if ($subscriptionArn) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-19' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Shield Advanced subscription active'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-19' `
                -Status 'FAIL' -Evidence $evidence -Notes 'Shield Advanced not subscribed'
        }

        'NET-20' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $addressData = Invoke-AWSCLI -Arguments @('ec2', 'describe-addresses') -Region $Region
            $instanceData = Invoke-AWSCLI -Arguments @('ec2', 'describe-instances') -Region $Region

            if ($null -eq $addressData -and $null -eq $instanceData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-20'
            }

            $eipCount = 0
            if ($addressData -and (Test-NetHasProperty -Object $addressData -PropertyName 'Addresses')) {
                $eipCount = Get-NetCollectionCount $addressData.Addresses
            }

            $publicInstanceCount = 0
            if ($instanceData -and (Test-NetHasProperty -Object $instanceData -PropertyName 'Reservations')) {
                foreach ($reservation in (Get-NetCliArray $instanceData.Reservations)) {
                    if (-not (Test-NetHasProperty -Object $reservation -PropertyName 'Instances')) { continue }
                    foreach ($instance in (Get-NetCliArray $reservation.Instances)) {
                        if (Test-NetHasProperty -Object $instance -PropertyName 'PublicIpAddress') {
                            if ($instance.PublicIpAddress) {
                                $publicInstanceCount++
                            }
                        }
                    }
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-20' `
                -Status 'PARTIAL' `
                -Evidence @{
                    elastic_ip_count          = $eipCount
                    instances_with_public_ip  = $publicInstanceCount
                } `
                -Notes 'Review public IP inventory against authorized exposure list'
        }

        'NET-21' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ram', 'list-resources', '--resource-owner', 'SELF') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-21'
            }

            $resources = New-NetList
            if (Test-NetHasProperty -Object $data -PropertyName 'Resources') {
                foreach ($resource in (Get-NetCliArray $data.Resources)) {
                    $resourceRecord = @{
                        arn    = [string]$resource.Arn
                        type   = [string]$resource.type
                        status = [string]$resource.status
                    }
                    [void]$resources.Add($resourceRecord)
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-21' `
                -Status 'PARTIAL' `
                -Evidence @{
                    shared_resource_count = Get-NetCollectionCount $resources
                    resources             = @($resources.ToArray())
                } `
                -Notes 'Review AWS RAM shared network resources for authorization'
        }

        'NET-22' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $dxData = Invoke-AWSCLI -Arguments @('directconnect', 'describe-connections') -Region $Region
            $vpnData = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpn-connections') -Region $Region

            if ($null -eq $dxData -and $null -eq $vpnData) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-22'
            }

            $dxConnections = New-NetList
            if ($dxData -and (Test-NetHasProperty -Object $dxData -PropertyName 'connections')) {
                foreach ($connection in (Get-NetCliArray $dxData.connections)) {
                    $dxConnectionRecord = @{
                        id       = [string]$connection.connectionId
                        state    = [string]$connection.connectionState
                        location = [string]$connection.location
                    }
                    [void]$dxConnections.Add($dxConnectionRecord)
                }
            }

            $vpnConnections = New-NetList
            if ($vpnData -and (Test-NetHasProperty -Object $vpnData -PropertyName 'VpnConnections')) {
                foreach ($vpn in (Get-NetCliArray $vpnData.VpnConnections)) {
                    $vpnConnectionRecord = @{
                        id    = [string]$vpn.VpnConnectionId
                        state = [string]$vpn.State
                    }
                    [void]$vpnConnections.Add($vpnConnectionRecord)
                }
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-22' `
                -Status 'PARTIAL' `
                -Evidence @{
                    direct_connect_count = Get-NetCollectionCount $dxConnections
                    vpn_connection_count = Get-NetCollectionCount $vpnConnections
                    direct_connects      = @($dxConnections.ToArray())
                    vpn_connections      = @($vpnConnections.ToArray())
                } `
                -Notes 'Review VPN and Direct Connect security configuration manually'
        }

        'NET-23' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('events', 'list-rules') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-23'
            }

            $networkPatterns = 'ec2\.amazonaws\.com|CreateRoute|DeleteRoute|AuthorizeSecurityGroup|RevokeSecurityGroup|CreateVpc|DeleteVpc|ModifyVpc|CreateSubnet|DeleteSubnet'
            $matchingRules = New-NetList

            if (Test-NetHasProperty -Object $data -PropertyName 'Rules') {
                foreach ($rule in (Get-NetCliArray $data.Rules)) {
                    $ruleName = [string]$rule.Name
                    $eventPattern = ''
                    if (Test-NetHasProperty -Object $rule -PropertyName 'EventPattern') {
                        $eventPattern = [string]$rule.EventPattern
                    }
                    if ($eventPattern -match $networkPatterns -or $ruleName -match 'Network|VPC|SecurityGroup|Route') {
                        [void]$matchingRules.Add($ruleName)
                    }
                }
            }

            $evidence = @{ matching_rule_names = @($matchingRules.ToArray()) }

            if ((Get-NetCollectionCount $matchingRules) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-23' `
                    -Status 'PASS' -Evidence $evidence -Notes 'EventBridge rules on network changes found'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-23' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No network alerting rules found'
        }

        'NET-24' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-24' `
                -Notes 'Verify periodic network exposure testing. Ask for last test date and report.'
        }

        'NET-25' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-vpc-peering-connections') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-25'
            }

            $peerings = New-NetList
            $riskyPeerings = New-NetList

            if (Test-NetHasProperty -Object $data -PropertyName 'VpcPeeringConnections') {
                foreach ($peering in (Get-NetCliArray $data.VpcPeeringConnections)) {
                    if ([string]$peering.Status.Code -ne 'active') {
                        continue
                    }

                    $requesterName = $null
                    $accepterName = $null
                    if ($peering.RequesterVpcInfo -and $peering.RequesterVpcInfo.Tags) {
                        $requesterName = Get-NetTagValueByKey -Tags $peering.RequesterVpcInfo.Tags -KeyName 'Name'
                    }
                    if ($peering.AccepterVpcInfo -and $peering.AccepterVpcInfo.Tags) {
                        $accepterName = Get-NetTagValueByKey -Tags $peering.AccepterVpcInfo.Tags -KeyName 'Name'
                    }

                    $requesterLabel = $requesterName
                    if (-not $requesterLabel) { $requesterLabel = [string]$peering.RequesterVpcInfo.VpcId }
                    $accepterLabel = $accepterName
                    if (-not $accepterLabel) { $accepterLabel = [string]$peering.AccepterVpcInfo.VpcId }

                    $record = @{
                        peering_id      = [string]$peering.VpcPeeringConnectionId
                        requester       = $requesterLabel
                        accepter        = $accepterLabel
                    }
                    [void]$peerings.Add($record)

                    $requesterProd = Test-NetEnvironmentName -Name $requesterLabel -EnvironmentType 'prod'
                    $requesterNonProd = Test-NetEnvironmentName -Name $requesterLabel -EnvironmentType 'nonprod'
                    $accepterProd = Test-NetEnvironmentName -Name $accepterLabel -EnvironmentType 'prod'
                    $accepterNonProd = Test-NetEnvironmentName -Name $accepterLabel -EnvironmentType 'nonprod'

                    if (($requesterProd -and $accepterNonProd) -or ($requesterNonProd -and $accepterProd)) {
                        [void]$riskyPeerings.Add($record)
                    }
                }
            }

            $evidence = @{
                active_peering_count = Get-NetCollectionCount $peerings
                peerings             = @($peerings.ToArray())
                risky_peerings       = @($riskyPeerings.ToArray())
            }

            if ((Get-NetCollectionCount $riskyPeerings) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-25' `
                    -Status 'FAIL' -Evidence $evidence -Notes 'Direct peering between prod and non-prod environments detected'
            }

            if ((Get-NetCollectionCount $peerings) -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-25' `
                    -Status 'PARTIAL' -Evidence $evidence -Notes 'Peering exists; verify environment isolation using tags and naming'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-25' `
                -Status 'PASS' -Evidence $evidence -Notes 'No active VPC peering connections detected'
        }

        'NET-26' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            return New-WorkshopControlResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-26' `
                -Notes 'Verify network flow matrix exists in DAT.'
        }

        'NET-27' = {
            param([string]$AccountId, [string]$AccountName, [string]$Region)

            $data = Invoke-AWSCLI -Arguments @('ec2', 'describe-flow-logs') -Region $Region
            if ($null -eq $data) {
                return New-NullApiPartialResult -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-27'
            }

            $flowLogs = New-NetList
            $activeCount = 0

            if (Test-NetHasProperty -Object $data -PropertyName 'FlowLogs') {
                foreach ($flowLog in (Get-NetCliArray $data.FlowLogs)) {
                    $destination = $null
                    if (Test-NetHasProperty -Object $flowLog -PropertyName 'LogDestinationType') {
                        $destination = [string]$flowLog.LogDestinationType
                    }

                    $isActive = ([string]$flowLog.FlowLogStatus -eq 'ACTIVE')
                    if ($isActive) {
                        $activeCount++
                    }

                    $flowLogRecord = @{
                        id          = [string]$flowLog.FlowLogId
                        status      = [string]$flowLog.FlowLogStatus
                        destination = $destination
                    }
                    [void]$flowLogs.Add($flowLogRecord)
                }
            }

            $validDestinations = 0
            foreach ($flowLog in $flowLogs) {
                if ($flowLog.status -ne 'ACTIVE') { continue }
                if ($flowLog.destination -eq 's3' -or $flowLog.destination -eq 'cloud-watch-logs') {
                    $validDestinations++
                }
            }

            $evidence = @{
                flow_log_count            = Get-NetCollectionCount $flowLogs
                active_flow_log_count     = $activeCount
                valid_destination_count   = $validDestinations
                flow_logs                 = @($flowLogs.ToArray())
            }

            if ($validDestinations -gt 0) {
                return New-AuditResult `
                    -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-27' `
                    -Status 'PASS' -Evidence $evidence -Notes 'Active flow logs export to S3 or CloudWatch Logs'
            }

            return New-AuditResult `
                -AccountId $AccountId -AccountName $AccountName -Region $Region -ControlId 'NET-27' `
                -Status 'FAIL' -Evidence $evidence -Notes 'No active flow logs with S3 or CloudWatch Logs destination'
        }
    }
}