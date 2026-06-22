"""NET domain — network segmentation and exposure controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "NET-01": "P0",
    "NET-02": "P0",
    "NET-03": "P0",
    "NET-04": "P0",
    "NET-05": "P0",
    "NET-06": "P0",
    "NET-07": "P0",
    "NET-08": "P0",
    "NET-09": "P0",
    "NET-10": "P0",
    "NET-11": "P0",
    "NET-12": "P0",
    "NET-13": "P0",
    "NET-14": "P0",
    "NET-15": "P0",
    "NET-16": "P2",
    "NET-17": "P0",
    "NET-18": "P0",
    "NET-19": "P0",
    "NET-20": "P0",
    "NET-21": "P0",
    "NET-22": "P0",
    "NET-23": "P0",
    "NET-24": "P0",
    "NET-25": "P0",
    "NET-26": "P0",
    "NET-27": "P0",
}

_NET_ANY_CIDR = "0.0.0.0/0"


def _get_net_cli_array(items: Any) -> list[Any]:
    return cli_array(items)


def _test_net_has_property(obj: Any, property_name: str) -> bool:
    return has_property(obj, property_name)


def _new_net_list() -> list[Any]:
    return []


def _get_net_collection_count(items: Any) -> int:
    return collection_count(items)


def _get_net_property_value(obj: Any, property_names: list[str]) -> Any:
    return property_value(obj, property_names)


def _invoke_aws_cli_in_region(ctx: CheckContext, arguments: list[str], region: str) -> Any | None:
    original_region = ctx.aws.region
    try:
        ctx.aws.region = region
        return ctx.invoke_aws_cli(arguments)
    finally:
        ctx.aws.region = original_region


def _get_net_route_tables(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["ec2", "describe-route-tables"])
    if data is None:
        return None
    if _test_net_has_property(data, "RouteTables"):
        return _get_net_cli_array(data.get("RouteTables"))
    return []


def _get_net_subnets(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["ec2", "describe-subnets"])
    if data is None:
        return None
    if _test_net_has_property(data, "Subnets"):
        return _get_net_cli_array(data.get("Subnets"))
    return []


def _get_net_vpcs(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["ec2", "describe-vpcs"])
    if data is None:
        return None
    if _test_net_has_property(data, "Vpcs"):
        return _get_net_cli_array(data.get("Vpcs"))
    return []


def _get_net_security_groups(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["ec2", "describe-security-groups"])
    if data is None:
        return None
    if _test_net_has_property(data, "SecurityGroups"):
        return _get_net_cli_array(data.get("SecurityGroups"))
    return []


def _test_net_route_table_has_igw_route(route_table: dict[str, Any]) -> bool:
    if not _test_net_has_property(route_table, "Routes"):
        return False
    for route in _get_net_cli_array(route_table.get("Routes")):
        if not _test_net_has_property(route, "GatewayId"):
            continue
        gateway_id = str(route.get("GatewayId", "") or "")
        if gateway_id.startswith("igw-"):
            destination = ""
            if _test_net_has_property(route, "DestinationCidrBlock"):
                destination = str(route.get("DestinationCidrBlock", "") or "")
            if destination == _NET_ANY_CIDR:
                return True
    return False


def _get_net_subnet_route_table_map(ctx: CheckContext) -> dict[str, dict[str, Any]] | None:
    route_tables = _get_net_route_tables(ctx)
    subnets = _get_net_subnets(ctx)
    if route_tables is None or subnets is None:
        return None

    main_route_tables: dict[str, dict[str, Any]] = {}
    for route_table in route_tables:
        if not _test_net_has_property(route_table, "Associations"):
            continue
        for association in _get_net_cli_array(route_table.get("Associations")):
            if _test_net_has_property(association, "Main") and association.get("Main") is True:
                main_route_tables[str(route_table.get("VpcId", "") or "")] = route_table

    subnet_map: dict[str, dict[str, Any]] = {}
    for subnet in subnets:
        subnet_id = str(subnet.get("SubnetId", "") or "")
        vpc_id = str(subnet.get("VpcId", "") or "")
        matched_route_table = None

        for route_table in route_tables:
            if not _test_net_has_property(route_table, "Associations"):
                continue
            for association in _get_net_cli_array(route_table.get("Associations")):
                if _test_net_has_property(association, "SubnetId") and str(association.get("SubnetId", "") or "") == subnet_id:
                    matched_route_table = route_table
                    break
            if matched_route_table:
                break

        if matched_route_table is None and vpc_id in main_route_tables:
            matched_route_table = main_route_tables[vpc_id]

        is_public = False
        if matched_route_table is not None:
            is_public = _test_net_route_table_has_igw_route(matched_route_table)

        subnet_map[subnet_id] = {"vpc_id": vpc_id, "is_public": is_public}

    return subnet_map


def _test_net_permission_open_to_internet(permission: dict[str, Any]) -> bool:
    if not _test_net_has_property(permission, "IpRanges"):
        return False
    for ip_range in _get_net_cli_array(permission.get("IpRanges")):
        if _test_net_has_property(ip_range, "CidrIp") and str(ip_range.get("CidrIp", "") or "") == _NET_ANY_CIDR:
            return True
    return False


def _get_net_tag_value_by_key(tags: Any, key_name: str) -> str | None:
    for tag in _get_net_cli_array(tags):
        if _test_net_has_property(tag, "Key") and str(tag.get("Key", "") or "") == key_name:
            if _test_net_has_property(tag, "Value"):
                value = tag.get("Value")
                return str(value) if value is not None else None
            return None
    return None


def _test_net_environment_name(name: str, environment_type: str) -> bool:
    lower_name = name.lower()
    if environment_type == "prod":
        if re.search("prod", lower_name) and not re.search("nonprod|non-prod|preprod|uat|dev|test|sandbox", lower_name):
            return True
        return False
    if re.search("nonprod|non-prod|dev|test|uat|sandbox|preprod", lower_name):
        return True
    return False


def _get_net_igw_route_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    route_tables = _get_net_route_tables(ctx)
    subnet_map = _get_net_subnet_route_table_map(ctx)
    if route_tables is None or subnet_map is None:
        return None

    igw_route_tables: list[str] = []
    private_subnet_igw_issues: list[dict[str, str]] = []
    public_subnet_igw_routes: list[str] = []

    for route_table in route_tables:
        if not _test_net_route_table_has_igw_route(route_table):
            continue
        route_table_id = str(route_table.get("RouteTableId", "") or "")
        igw_route_tables.append(route_table_id)
        if not _test_net_has_property(route_table, "Associations"):
            continue
        for association in _get_net_cli_array(route_table.get("Associations")):
            subnet_id = str(association.get("SubnetId", "") or "")
            if not subnet_id or subnet_id not in subnet_map:
                continue
            if subnet_map[subnet_id].get("is_public"):
                public_subnet_igw_routes.append(subnet_id)
            elif _get_net_collection_count(private_subnet_igw_issues) < 10:
                private_subnet_igw_issues.append(
                    {"subnet_id": subnet_id, "route_table_id": route_table_id}
                )

    return {
        "igw_route_table_count": _get_net_collection_count(igw_route_tables),
        "public_subnet_igw_route_count": _get_net_collection_count(public_subnet_igw_routes),
        "private_subnet_igw_issues": list(private_subnet_igw_issues),
    }


def _evaluate_net_exposed_api(ctx: CheckContext, api_id: str, api_name: str) -> dict[str, Any]:
    resource_data = ctx.invoke_aws_cli(["apigateway", "get-resources", "--rest-api-id", api_id])
    stages_data = ctx.invoke_aws_cli(["apigateway", "get-stages", "--rest-api-id", api_id])

    unauthenticated_methods = 0
    method_count = 0
    if resource_data and _test_net_has_property(resource_data, "items"):
        for resource in _get_net_cli_array(resource_data.get("items")):
            if not _test_net_has_property(resource, "resourceMethods"):
                continue
            resource_methods = resource.get("resourceMethods")
            if not isinstance(resource_methods, dict):
                continue
            resource_id = str(resource.get("id", "") or "")
            for method_name in resource_methods.keys():
                method_count += 1
                method_data = ctx.invoke_aws_cli(
                    [
                        "apigateway",
                        "get-method",
                        "--rest-api-id",
                        api_id,
                        "--resource-id",
                        resource_id,
                        "--http-method",
                        str(method_name),
                    ]
                )
                authorization_type = str(_get_net_property_value(method_data, ["authorizationType"]) or "")
                if authorization_type.lower() == "none":
                    unauthenticated_methods += 1

    throttled_stages = 0
    logged_stages = 0
    waf_protected_stages = 0
    stage_count = 0
    if stages_data and _test_net_has_property(stages_data, "item"):
        for stage in _get_net_cli_array(stages_data.get("item")):
            stage_count += 1
            stage_name = str(stage.get("stageName", "") or "")
            route_settings = stage.get("defaultRouteSettings")
            if isinstance(route_settings, dict):
                burst = route_settings.get("throttlingBurstLimit")
                rate = route_settings.get("throttlingRateLimit")
                if burst is not None and rate is not None:
                    throttled_stages += 1
            access_log_settings = stage.get("accessLogSettings")
            if isinstance(access_log_settings, dict) and access_log_settings.get("destinationArn"):
                logged_stages += 1
            if stage_name:
                stage_arn = f"arn:aws:apigateway:{ctx.aws.region}::/restapis/{api_id}/stages/{stage_name}"
                waf_data = ctx.invoke_aws_cli(["wafv2", "get-web-acl-for-resource", "--resource-arn", stage_arn])
                if waf_data is not None and _test_net_has_property(waf_data, "WebACL"):
                    waf_protected_stages += 1

    return {
        "api_id": api_id,
        "api_name": api_name,
        "method_count": method_count,
        "unauthenticated_method_count": unauthenticated_methods,
        "stage_count": stage_count,
        "throttled_stage_count": throttled_stages,
        "logged_stage_count": logged_stages,
        "waf_protected_stage_count": waf_protected_stages,
    }


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(control_id: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, control_id, notes)

        return _check

    checks["NET-01"] = workshop(
        "NET-01",
        "Verify DAT contains network topology, VPC segmentation, encryption boundaries. Check SIPedia version.",
    )

    def net02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vpcs = _get_net_vpcs(ctx)
        if vpcs is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-02")

        vpc_list = _get_net_cli_array(vpcs)
        vpc_evidence = _new_net_list()
        for vpc in vpc_list:
            vpc_name = None
            if _test_net_has_property(vpc, "Tags"):
                vpc_name = _get_net_tag_value_by_key(vpc.get("Tags"), "Name")
            vpc_record = {
                "vpc_id": str(vpc.get("VpcId", "") or ""),
                "cidr_block": str(vpc.get("CidrBlock", "") or ""),
                "name": vpc_name,
            }
            vpc_evidence.append(vpc_record)

        vpc_count = _get_net_collection_count(vpc_list)
        evidence = {"vpc_count": vpc_count, "vpcs": list(vpc_evidence)}

        if vpc_count > 1:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-02",
                "PASS",
                evidence,
                "Multiple VPCs provide environment segmentation",
            )
        if vpc_count == 1:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-02",
                "PARTIAL",
                evidence,
                "Single VPC in account; verify cross-account segmentation",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-02", "FAIL", evidence, "No VPCs found"
        )

    checks["NET-02"] = net02

    def net03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        subnet_map = _get_net_subnet_route_table_map(ctx)
        if subnet_map is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-03")

        vpc_stats: dict[str, dict[str, int]] = {}
        for subnet_id in _get_net_cli_array(list(subnet_map.keys())):
            entry = subnet_map.get(str(subnet_id), {})
            vpc_id = str(entry.get("vpc_id", "") or "")
            if vpc_id not in vpc_stats:
                vpc_stats[vpc_id] = {"public_count": 0, "private_count": 0}
            if bool(entry.get("is_public")):
                vpc_stats[vpc_id]["public_count"] = vpc_stats[vpc_id]["public_count"] + 1
            else:
                vpc_stats[vpc_id]["private_count"] = vpc_stats[vpc_id]["private_count"] + 1

        failing_vpcs = _new_net_list()
        passing_vpcs = _new_net_list()
        for vpc_id in list(vpc_stats.keys()):
            stats = vpc_stats[vpc_id]
            if stats["public_count"] > 0 and stats["private_count"] > 0:
                passing_vpcs.append(
                    {
                        "vpc_id": vpc_id,
                        "public_count": stats["public_count"],
                        "private_count": stats["private_count"],
                    }
                )
            elif stats["public_count"] > 0 and stats["private_count"] == 0:
                failing_vpcs.append({"vpc_id": vpc_id, "public_count": stats["public_count"], "private_count": 0})

        evidence = {
            "vpc_count": len(list(vpc_stats.keys())),
            "passing_vpcs": list(passing_vpcs),
            "failing_vpcs": list(failing_vpcs),
        }

        if _get_net_collection_count(failing_vpcs) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-03",
                "FAIL",
                evidence,
                "One or more VPCs have only public subnets",
            )
        if _get_net_collection_count(passing_vpcs) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-03",
                "PASS",
                evidence,
                "Public and private subnets exist per VPC",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-03",
            "PARTIAL",
            evidence,
            "No clear public/private subnet separation detected",
        )

    checks["NET-03"] = net03

    def net04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        route_tables = _get_net_route_tables(ctx)
        if route_tables is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-04")

        igw_route_table_count = 0
        main_table_with_igw = _new_net_list()
        subnet_associated_igw_tables = _new_net_list()

        for route_table in route_tables:
            if not _test_net_route_table_has_igw_route(route_table):
                continue
            igw_route_table_count += 1
            is_main = False
            associated_subnets = _new_net_list()

            if _test_net_has_property(route_table, "Associations"):
                for association in _get_net_cli_array(route_table.get("Associations")):
                    if _test_net_has_property(association, "Main") and association.get("Main") is True:
                        is_main = True
                    if _test_net_has_property(association, "SubnetId"):
                        associated_subnets.append(str(association.get("SubnetId", "") or ""))

            if is_main:
                if _get_net_collection_count(main_table_with_igw) < 10:
                    main_table_with_igw.append(str(route_table.get("RouteTableId", "") or ""))
            elif _get_net_collection_count(associated_subnets) > 0:
                if _get_net_collection_count(subnet_associated_igw_tables) < 10:
                    subnet_associated_igw_tables.append(str(route_table.get("RouteTableId", "") or ""))

        evidence = {
            "route_table_count": _get_net_collection_count(route_tables),
            "igw_route_table_count": igw_route_table_count,
            "main_route_tables_with_igw": list(main_table_with_igw),
            "subnet_associated_igw_tables": list(subnet_associated_igw_tables),
        }

        if _get_net_collection_count(main_table_with_igw) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-04",
                "FAIL",
                evidence,
                "Main route table routes private subnets to an Internet Gateway",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-04",
            "PASS",
            evidence,
            "Internet Gateway routes limited to non-main route tables",
        )

    checks["NET-04"] = net04

    def net05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        igw_evidence = _get_net_igw_route_evidence(ctx)
        if igw_evidence is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-05")

        evidence = igw_evidence
        if evidence["igw_route_table_count"] == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-05",
                "PARTIAL",
                evidence,
                "No Internet Gateway routes detected in route tables",
            )
        if _get_net_collection_count(evidence["private_subnet_igw_issues"]) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-05",
                "FAIL",
                evidence,
                "One or more private subnets route to an Internet Gateway",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-05",
            "PASS",
            evidence,
            "Internet Gateway routes are limited to public subnets",
        )

    checks["NET-05"] = net05

    def net06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        subnet_map = _get_net_subnet_route_table_map(ctx)
        nat_data = ctx.invoke_aws_cli(["ec2", "describe-nat-gateways", "--filter", "Name=state,Values=available"])
        if subnet_map is None or nat_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-06")

        private_vpc_ids: dict[str, bool] = {}
        for subnet_id in _get_net_cli_array(list(subnet_map.keys())):
            entry = subnet_map.get(str(subnet_id), {})
            if not bool(entry.get("is_public")):
                private_vpc_ids[str(entry.get("vpc_id", "") or "")] = True

        nat_gateways: list[dict[str, Any]] = []
        if _test_net_has_property(nat_data, "NatGateways"):
            nat_gateways = _get_net_cli_array(nat_data.get("NatGateways"))

        nat_vpc_ids = _new_net_list()
        for nat in nat_gateways:
            if _test_net_has_property(nat, "VpcId"):
                nat_vpc_ids.append(str(nat.get("VpcId", "") or ""))

        evidence = {
            "private_vpc_count": len(list(private_vpc_ids.keys())),
            "nat_gateway_count": _get_net_collection_count(nat_gateways),
            "nat_vpc_ids": list(nat_vpc_ids),
        }

        if len(list(private_vpc_ids.keys())) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "NET-06", "PARTIAL", evidence, "No private subnets detected"
            )
        if _get_net_collection_count(nat_gateways) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-06",
                "PASS",
                evidence,
                "NAT Gateways exist for private subnet egress",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-06",
            "FAIL",
            evidence,
            "Private subnets exist but no NAT Gateways found",
        )

    checks["NET-06"] = net06

    def net07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        firewall_data = ctx.invoke_aws_cli(["network-firewall", "list-firewalls"])
        security_groups = _get_net_security_groups(ctx)

        if firewall_data is None and security_groups is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-07")

        firewall_count = 0
        if firewall_data and _test_net_has_property(firewall_data, "Firewalls"):
            firewall_count = _get_net_collection_count(firewall_data.get("Firewalls"))

        unrestricted_egress_count = 0
        if security_groups:
            for sg in security_groups:
                if not _test_net_has_property(sg, "IpPermissionsEgress"):
                    continue
                for rule in _get_net_cli_array(sg.get("IpPermissionsEgress")):
                    open_internet = _test_net_permission_open_to_internet(rule)
                    all_traffic = _test_net_has_property(rule, "IpProtocol") and str(rule.get("IpProtocol", "") or "") == "-1"
                    if open_internet and all_traffic:
                        unrestricted_egress_count += 1
                        break

        evidence = {
            "firewall_count": firewall_count,
            "unrestricted_egress_sg_count": unrestricted_egress_count,
        }

        if firewall_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-07",
                "PASS",
                evidence,
                "Network Firewall deployed for egress filtering",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-07",
            "PARTIAL",
            evidence,
            "No Network Firewall detected; verify controlled egress path via proxy, TGW or firewall",
        )

    checks["NET-07"] = net07

    def net08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        security_groups = _get_net_security_groups(ctx)
        if security_groups is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-08")

        offending_groups = _new_net_list()
        for sg in security_groups:
            if not _test_net_has_property(sg, "IpPermissions"):
                continue
            for rule in _get_net_cli_array(sg.get("IpPermissions")):
                if not _test_net_permission_open_to_internet(rule):
                    continue
                from_port = 0
                to_port = 65535
                if _test_net_has_property(rule, "FromPort") and rule.get("FromPort") is not None:
                    from_port = int(rule.get("FromPort"))
                if _test_net_has_property(rule, "ToPort") and rule.get("ToPort") is not None:
                    to_port = int(rule.get("ToPort"))
                all_protocols = _test_net_has_property(rule, "IpProtocol") and str(rule.get("IpProtocol", "") or "") == "-1"
                allows_ssh = (from_port <= 22 and to_port >= 22) or all_protocols
                allows_rdp = (from_port <= 3389 and to_port >= 3389) or all_protocols
                if allows_ssh or allows_rdp:
                    if _get_net_collection_count(offending_groups) < 10:
                        offending_groups.append(str(sg.get("GroupId", "") or ""))
                    break

        evidence = {"offending_security_group_ids": list(offending_groups)}
        if _get_net_collection_count(offending_groups) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-08",
                "FAIL",
                evidence,
                "Security groups allow SSH or RDP from the internet",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-08",
            "PASS",
            evidence,
            "No internet-exposed SSH or RDP rules found",
        )

    checks["NET-08"] = net08

    def net09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        ssm_data = ctx.invoke_aws_cli(["ssm", "describe-instance-information"])
        security_groups = _get_net_security_groups(ctx)

        if ssm_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-09")

        managed_count = 0
        if _test_net_has_property(ssm_data, "InstanceInformationList"):
            managed_count = _get_net_collection_count(ssm_data.get("InstanceInformationList"))

        internet_admin_exposure = False
        if security_groups:
            for sg in security_groups:
                if not _test_net_has_property(sg, "IpPermissions"):
                    continue
                for rule in _get_net_cli_array(sg.get("IpPermissions")):
                    if not _test_net_permission_open_to_internet(rule):
                        continue
                    from_port = 0
                    to_port = 65535
                    if _test_net_has_property(rule, "FromPort") and rule.get("FromPort") is not None:
                        from_port = int(rule.get("FromPort"))
                    if _test_net_has_property(rule, "ToPort") and rule.get("ToPort") is not None:
                        to_port = int(rule.get("ToPort"))
                    all_protocols = _test_net_has_property(rule, "IpProtocol") and str(rule.get("IpProtocol", "") or "") == "-1"
                    if (from_port <= 22 and to_port >= 22) or (from_port <= 3389 and to_port >= 3389) or all_protocols:
                        internet_admin_exposure = True
                        break
                if internet_admin_exposure:
                    break

        evidence = {
            "ssm_managed_instance_count": managed_count,
            "internet_admin_exposure": internet_admin_exposure,
        }
        if managed_count > 0 and not internet_admin_exposure:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-09",
                "PASS",
                evidence,
                "SSM-managed instances exist with no internet admin access",
            )
        if internet_admin_exposure:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-09",
                "FAIL",
                evidence,
                "Internet-exposed admin ports found despite SSM availability",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-09", "PARTIAL", evidence, "No SSM-managed instances detected"
        )

    checks["NET-09"] = net09

    def net10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        security_groups = _get_net_security_groups(ctx)
        if security_groups is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-10")

        open_groups = _new_net_list()
        for sg in security_groups:
            if not _test_net_has_property(sg, "IpPermissions"):
                continue
            for rule in _get_net_cli_array(sg.get("IpPermissions")):
                all_protocols = _test_net_has_property(rule, "IpProtocol") and str(rule.get("IpProtocol", "") or "") == "-1"
                if _test_net_permission_open_to_internet(rule) and all_protocols:
                    if _get_net_collection_count(open_groups) < 10:
                        open_groups.append(str(sg.get("GroupId", "") or ""))
                    break

        evidence = {
            "security_group_count": _get_net_collection_count(security_groups),
            "open_all_traffic_sgs": list(open_groups),
        }
        if _get_net_collection_count(open_groups) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-10",
                "FAIL",
                evidence,
                "Security groups allow all traffic from the internet",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-10",
            "PASS",
            evidence,
            "No all-traffic internet inbound rules found",
        )

    checks["NET-10"] = net10

    def net11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["ec2", "describe-network-acls"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-11")

        acls: list[dict[str, Any]] = []
        if _test_net_has_property(data, "NetworkAcls"):
            acls = _get_net_cli_array(data.get("NetworkAcls"))

        custom_acl_count = 0
        for acl in acls:
            if acl.get("IsDefault") is True:
                continue
            custom_acl_count += 1

        evidence = {
            "nacl_count": _get_net_collection_count(acls),
            "custom_nacl_count": custom_acl_count,
            "default_nacl_count": (_get_net_collection_count(acls) - custom_acl_count),
        }
        if custom_acl_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-11",
                "PASS",
                evidence,
                "Custom NACLs exist beyond default allow-all",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-11", "FAIL", evidence, "Only default NACLs detected"
        )

    checks["NET-11"] = net11

    def net12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        peering_data = ctx.invoke_aws_cli(["ec2", "describe-vpc-peering-connections"])
        tgw_attach_data = ctx.invoke_aws_cli(["ec2", "describe-transit-gateway-attachments"])

        if peering_data is None and tgw_attach_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-12")

        peering_count = 0
        if peering_data and _test_net_has_property(peering_data, "VpcPeeringConnections"):
            peering_count = _get_net_collection_count(peering_data.get("VpcPeeringConnections"))

        attachment_count = 0
        if tgw_attach_data and _test_net_has_property(tgw_attach_data, "TransitGatewayAttachments"):
            attachment_count = _get_net_collection_count(tgw_attach_data.get("TransitGatewayAttachments"))

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-12",
            "PARTIAL",
            {"peering_count": peering_count, "tgw_attachment_count": attachment_count},
            "Review inter-VPC flows against approved connectivity matrix",
        )

    checks["NET-12"] = net12

    def net13(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        tgw_data = ctx.invoke_aws_cli(["ec2", "describe-transit-gateways"])
        attach_data = ctx.invoke_aws_cli(["ec2", "describe-transit-gateway-attachments"])

        if tgw_data is None and attach_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-13")

        tgw_ids = _new_net_list()
        if tgw_data and _test_net_has_property(tgw_data, "TransitGateways"):
            for tgw in _get_net_cli_array(tgw_data.get("TransitGateways")):
                if _test_net_has_property(tgw, "TransitGatewayId"):
                    tgw_ids.append(str(tgw.get("TransitGatewayId", "") or ""))

        attachments = _new_net_list()
        if attach_data and _test_net_has_property(attach_data, "TransitGatewayAttachments"):
            for attachment in _get_net_cli_array(attach_data.get("TransitGatewayAttachments")):
                attachment_record = {
                    "attachment_id": str(attachment.get("TransitGatewayAttachmentId", "") or ""),
                    "resource_id": str(attachment.get("ResourceId", "") or ""),
                    "resource_type": str(attachment.get("ResourceType", "") or ""),
                }
                attachments.append(attachment_record)

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-13",
            "PARTIAL",
            {
                "tgw_ids": list(tgw_ids),
                "attachment_count": _get_net_collection_count(attachments),
                "attachments": list(attachments),
            },
            "Review TGW attachments for justification and least connectivity",
        )

    checks["NET-13"] = net13

    def net14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["ec2", "describe-vpc-endpoints"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-14")

        required_services = [".s3", ".ssm", ".secretsmanager", ".kms", ".dynamodb", ".logs", ".monitoring"]
        found_services = _new_net_list()
        service_names = _new_net_list()
        required_missing = _new_net_list()

        if _test_net_has_property(data, "VpcEndpoints"):
            for endpoint in _get_net_cli_array(data.get("VpcEndpoints")):
                service_name = str(endpoint.get("ServiceName", "") or "")
                service_names.append(service_name)
                for required in required_services:
                    if service_name.lower().endswith(required):
                        if required not in found_services:
                            found_services.append(required)

        endpoint_count = 0
        if _test_net_has_property(data, "VpcEndpoints"):
            endpoint_count = _get_net_collection_count(data.get("VpcEndpoints"))

        for required in required_services:
            if required not in found_services:
                required_missing.append(required)

        evidence = {
            "endpoint_count": endpoint_count,
            "service_names": list(service_names),
            "required_found": list(found_services),
            "required_missing": list(required_missing),
        }

        if _get_net_collection_count(found_services) == _get_net_collection_count(required_services):
            return ctx.results.audit_result(
                account_id, account_name, region, "NET-14", "PASS", evidence, "Required private endpoints are present"
            )
        if _get_net_collection_count(found_services) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-14",
                "PARTIAL",
                evidence,
                "Some required private endpoints are missing",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-14", "FAIL", evidence, "No required private endpoints found"
        )

    checks["NET-14"] = net14

    def net15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["route53resolver", "list-resolver-endpoints"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-15")

        endpoints = _new_net_list()
        if _test_net_has_property(data, "ResolverEndpoints"):
            for endpoint in _get_net_cli_array(data.get("ResolverEndpoints")):
                endpoint_record = {
                    "id": str(endpoint.get("Id", "") or ""),
                    "direction": str(endpoint.get("Direction", "") or ""),
                    "status": str(endpoint.get("Status", "") or ""),
                }
                endpoints.append(endpoint_record)

        evidence = {"resolver_endpoint_count": _get_net_collection_count(endpoints), "endpoints": list(endpoints)}
        if _get_net_collection_count(endpoints) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "NET-15", "PASS", evidence, "Route53 resolver endpoints configured"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-15", "FAIL", evidence, "No Route53 resolver endpoints configured"
        )

    checks["NET-15"] = net15

    def net16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        firewall_data = ctx.invoke_aws_cli(["network-firewall", "list-firewalls"])
        if firewall_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-16")

        firewall_count = 0
        if _test_net_has_property(firewall_data, "Firewalls"):
            firewall_count = _get_net_collection_count(firewall_data.get("Firewalls"))

        if firewall_count == 0:
            return ctx.results.workshop_control(
                account_id,
                account_name,
                region,
                "NET-16",
                "Verify if east-west traffic inspection is required and implemented.",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-16",
            "PARTIAL",
            {"firewall_count": firewall_count},
            "Network Firewall present; verify sensitive east-west flows are inspected",
        )

    checks["NET-16"] = net16

    def net17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        lb_data = ctx.invoke_aws_cli(["elbv2", "describe-load-balancers"])
        if lb_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-17")

        internet_facing = _new_net_list()
        if _test_net_has_property(lb_data, "LoadBalancers"):
            for lb in _get_net_cli_array(lb_data.get("LoadBalancers")):
                if str(lb.get("Scheme", "") or "") == "internet-facing":
                    internet_facing.append(lb)

        if _get_net_collection_count(internet_facing) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-17",
                "PARTIAL",
                {"internet_facing_alb_count": 0},
                "No internet-facing ALBs found in region",
            )

        failing_albs = _new_net_list()
        passing_albs = _new_net_list()
        for lb in internet_facing:
            lb_name = str(lb.get("LoadBalancerName", "") or "")
            lb_arn = str(lb.get("LoadBalancerArn", "") or "")

            listener_data = ctx.invoke_aws_cli(["elbv2", "describe-listeners", "--load-balancer-arn", lb_arn])
            has_https = False
            http_without_redirect = False

            if listener_data and _test_net_has_property(listener_data, "Listeners"):
                for listener in _get_net_cli_array(listener_data.get("Listeners")):
                    if str(listener.get("Protocol", "") or "") == "HTTPS":
                        has_https = True
                    if str(listener.get("Protocol", "") or "") == "HTTP":
                        has_redirect = False
                        if _test_net_has_property(listener, "DefaultActions"):
                            for action in _get_net_cli_array(listener.get("DefaultActions")):
                                if str(action.get("Type", "") or "") == "redirect":
                                    has_redirect = True
                        if not has_redirect:
                            http_without_redirect = True

            waf_data = ctx.invoke_aws_cli(["wafv2", "get-web-acl-for-resource", "--resource-arn", lb_arn])
            has_waf = waf_data is not None and _test_net_has_property(waf_data, "WebACL")

            if has_https and has_waf and not http_without_redirect:
                passing_albs.append({"name": lb_name, "scheme": str(lb.get("Scheme", "") or "")})
            else:
                failing_albs.append(
                    {
                        "name": lb_name,
                        "scheme": str(lb.get("Scheme", "") or ""),
                        "https": has_https,
                        "waf": has_waf,
                        "http_without_redirect": http_without_redirect,
                    }
                )

        evidence = {
            "internet_facing_alb_count": _get_net_collection_count(internet_facing),
            "passing_albs": list(passing_albs),
            "failing_albs": list(failing_albs),
        }
        if _get_net_collection_count(failing_albs) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-17",
                "FAIL",
                evidence,
                "Internet-facing ALB missing HTTPS, WAF, or uses HTTP without redirect",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-17",
            "PASS",
            evidence,
            "Internet-facing ALBs are hardened with HTTPS and WAF",
        )

    checks["NET-17"] = net17

    def net18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rest_data = ctx.invoke_aws_cli(["apigateway", "get-rest-apis"])
        http_data = ctx.invoke_aws_cli(["apigatewayv2", "get-apis"])
        if rest_data is None and http_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-18")

        apis: list[dict[str, Any]] = []
        if rest_data and _test_net_has_property(rest_data, "items"):
            for api in _get_net_cli_array(rest_data.get("items")):
                api_id = str(api.get("id", "") or "")
                api_name = str(api.get("name", "") or "")
                endpoint_types = _get_net_cli_array(api.get("endpointConfiguration", {}).get("types", []))
                if "PRIVATE" in [str(item) for item in endpoint_types]:
                    continue
                if api_id:
                    apis.append(_evaluate_net_exposed_api(ctx, api_id, api_name))

        http_api_summaries: list[dict[str, Any]] = []
        if http_data and _test_net_has_property(http_data, "Items"):
            for api in _get_net_cli_array(http_data.get("Items")):
                http_api_summaries.append(
                    {
                        "api_id": str(api.get("ApiId", "") or ""),
                        "name": str(api.get("Name", "") or ""),
                        "protocol": str(api.get("ProtocolType", "") or ""),
                    }
                )

        if _get_net_collection_count(apis) == 0 and _get_net_collection_count(http_api_summaries) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-18",
                "PARTIAL",
                {"rest_api_count": 0, "http_api_count": 0},
                "No public REST or HTTP APIs found in region",
            )

        failing_apis: list[dict[str, Any]] = []
        passing_apis: list[dict[str, Any]] = []
        for api in apis:
            unauth = int(api.get("unauthenticated_method_count", 0) or 0)
            throttled = int(api.get("throttled_stage_count", 0) or 0)
            logged = int(api.get("logged_stage_count", 0) or 0)
            waf_stages = int(api.get("waf_protected_stage_count", 0) or 0)
            if unauth > 0 or throttled == 0 or logged == 0 or waf_stages == 0:
                failing_apis.append(api)
            else:
                passing_apis.append(api)

        evidence = {
            "rest_api_count": _get_net_collection_count(apis),
            "http_api_count": _get_net_collection_count(http_api_summaries),
            "passing_rest_apis": list(passing_apis),
            "failing_rest_apis": list(failing_apis),
            "http_apis": list(http_api_summaries),
        }
        if _get_net_collection_count(failing_apis) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-18",
                "FAIL",
                evidence,
                "One or more exposed APIs lack authentication, throttling, logging or WAF protection",
            )
        if _get_net_collection_count(http_api_summaries) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-18",
                "PARTIAL",
                evidence,
                "REST APIs are protected; review HTTP APIs (v2) separately",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-18",
            "PASS",
            evidence,
            "Exposed REST APIs have authentication, throttling, logging and WAF protection",
        )

    checks["NET-18"] = net18

    def net19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = _invoke_aws_cli_in_region(ctx, ["shield", "describe-subscription"], "us-east-1")
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-19")

        subscription_arn = None
        subscription = data.get("Subscription") if isinstance(data, dict) else None
        if subscription and isinstance(subscription, dict):
            sub_arn = subscription.get("SubscriptionArn")
            if sub_arn:
                subscription_arn = str(sub_arn)

        evidence = {"subscription_arn": subscription_arn, "checked_region": "us-east-1"}
        if subscription_arn:
            return ctx.results.audit_result(
                account_id, account_name, region, "NET-19", "PASS", evidence, "Shield Advanced subscription active"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-19", "FAIL", evidence, "Shield Advanced not subscribed"
        )

    checks["NET-19"] = net19

    def net20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        address_data = ctx.invoke_aws_cli(["ec2", "describe-addresses"])
        instance_data = ctx.invoke_aws_cli(["ec2", "describe-instances"])

        if address_data is None and instance_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-20")

        eip_count = 0
        if address_data and _test_net_has_property(address_data, "Addresses"):
            eip_count = _get_net_collection_count(address_data.get("Addresses"))

        public_instance_count = 0
        if instance_data and _test_net_has_property(instance_data, "Reservations"):
            for reservation in _get_net_cli_array(instance_data.get("Reservations")):
                if not _test_net_has_property(reservation, "Instances"):
                    continue
                for instance in _get_net_cli_array(reservation.get("Instances")):
                    if _test_net_has_property(instance, "PublicIpAddress"):
                        if instance.get("PublicIpAddress"):
                            public_instance_count += 1

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-20",
            "PARTIAL",
            {"elastic_ip_count": eip_count, "instances_with_public_ip": public_instance_count},
            "Review public IP inventory against authorized exposure list",
        )

    checks["NET-20"] = net20

    def net21(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["ram", "list-resources", "--resource-owner", "SELF"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-21")

        resources = _new_net_list()
        if _test_net_has_property(data, "Resources"):
            for resource in _get_net_cli_array(data.get("Resources")):
                resource_record = {
                    "arn": str(_get_net_property_value(resource, ["arn", "Arn"]) or ""),
                    "type": str(_get_net_property_value(resource, ["type", "Type", "resourceType"]) or ""),
                    "status": str(_get_net_property_value(resource, ["status", "Status"]) or ""),
                }
                resources.append(resource_record)

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-21",
            "PARTIAL",
            {"shared_resource_count": _get_net_collection_count(resources), "resources": list(resources)},
            "Review AWS RAM shared network resources for authorization",
        )

    checks["NET-21"] = net21

    def net22(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        dx_data = ctx.invoke_aws_cli(["directconnect", "describe-connections"])
        vpn_data = ctx.invoke_aws_cli(["ec2", "describe-vpn-connections"])

        if dx_data is None and vpn_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-22")

        dx_connections = _new_net_list()
        if dx_data and _test_net_has_property(dx_data, "connections"):
            for connection in _get_net_cli_array(dx_data.get("connections")):
                dx_connections.append(
                    {
                        "id": str(connection.get("connectionId", "") or ""),
                        "state": str(connection.get("connectionState", "") or ""),
                        "location": str(connection.get("location", "") or ""),
                    }
                )

        vpn_connections = _new_net_list()
        if vpn_data and _test_net_has_property(vpn_data, "VpnConnections"):
            for vpn in _get_net_cli_array(vpn_data.get("VpnConnections")):
                vpn_connections.append(
                    {"id": str(vpn.get("VpnConnectionId", "") or ""), "state": str(vpn.get("State", "") or "")}
                )

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-22",
            "PARTIAL",
            {
                "direct_connect_count": _get_net_collection_count(dx_connections),
                "vpn_connection_count": _get_net_collection_count(vpn_connections),
                "direct_connects": list(dx_connections),
                "vpn_connections": list(vpn_connections),
            },
            "Review VPN and Direct Connect security configuration manually",
        )

    checks["NET-22"] = net22

    def net23(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["events", "list-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-23")

        network_patterns = (
            r"ec2\.amazonaws\.com|CreateRoute|DeleteRoute|AuthorizeSecurityGroup|RevokeSecurityGroup|CreateVpc|"
            r"DeleteVpc|ModifyVpc|CreateSubnet|DeleteSubnet|TransitGateway|VpcEndpoint|CreateInternetGateway"
        )
        matching_rules = _new_net_list()
        rules_with_targets = _new_net_list()
        if _test_net_has_property(data, "Rules"):
            for rule in _get_net_cli_array(data.get("Rules")):
                rule_name = str(_get_net_property_value(rule, ["Name", "name"]) or "")
                event_pattern = str(_get_net_property_value(rule, ["EventPattern", "eventPattern"]) or "")
                if (
                    (event_pattern.strip() and re.search(network_patterns, event_pattern, re.IGNORECASE))
                    or re.search("Network|VPC|SecurityGroup|Route|TGW|TransitGateway", rule_name, re.IGNORECASE)
                ):
                    matching_rules.append(rule_name)
                    targets_data = ctx.invoke_aws_cli(["events", "list-targets-by-rule", "--rule", rule_name])
                    if targets_data and _test_net_has_property(targets_data, "Targets"):
                        if _get_net_collection_count(targets_data.get("Targets")) > 0:
                            rules_with_targets.append(rule_name)

        evidence = {
            "matching_rule_names": list(matching_rules),
            "rules_with_active_targets": list(rules_with_targets),
        }
        if _get_net_collection_count(rules_with_targets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-23",
                "PASS",
                evidence,
                "EventBridge rules on network changes have active targets",
            )
        if _get_net_collection_count(matching_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-23",
                "PARTIAL",
                evidence,
                "Network EventBridge rules exist but no active targets were detected",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-23", "FAIL", evidence, "No network alerting rules found"
        )

    checks["NET-23"] = net23

    checks["NET-24"] = workshop(
        "NET-24",
        "Verify periodic network exposure testing. Ask for last test date and report.",
    )

    def net25(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["ec2", "describe-vpc-peering-connections"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-25")

        peerings = _new_net_list()
        risky_peerings = _new_net_list()
        if _test_net_has_property(data, "VpcPeeringConnections"):
            for peering in _get_net_cli_array(data.get("VpcPeeringConnections")):
                status_obj = peering.get("Status") if isinstance(peering, dict) else None
                status_code = ""
                if isinstance(status_obj, dict):
                    status_code = str(status_obj.get("Code", "") or "")
                if status_code != "active":
                    continue

                requester_name = None
                accepter_name = None
                requester_vpc_info = peering.get("RequesterVpcInfo") if isinstance(peering, dict) else None
                accepter_vpc_info = peering.get("AccepterVpcInfo") if isinstance(peering, dict) else None
                if isinstance(requester_vpc_info, dict) and requester_vpc_info.get("Tags"):
                    requester_name = _get_net_tag_value_by_key(requester_vpc_info.get("Tags"), "Name")
                if isinstance(accepter_vpc_info, dict) and accepter_vpc_info.get("Tags"):
                    accepter_name = _get_net_tag_value_by_key(accepter_vpc_info.get("Tags"), "Name")

                requester_label = requester_name
                if not requester_label:
                    requester_label = str((requester_vpc_info or {}).get("VpcId", "") or "")
                accepter_label = accepter_name
                if not accepter_label:
                    accepter_label = str((accepter_vpc_info or {}).get("VpcId", "") or "")

                record = {
                    "peering_id": str(peering.get("VpcPeeringConnectionId", "") or ""),
                    "requester": requester_label,
                    "accepter": accepter_label,
                }
                peerings.append(record)

                requester_prod = _test_net_environment_name(requester_label, "prod")
                requester_nonprod = _test_net_environment_name(requester_label, "nonprod")
                accepter_prod = _test_net_environment_name(accepter_label, "prod")
                accepter_nonprod = _test_net_environment_name(accepter_label, "nonprod")
                if (requester_prod and accepter_nonprod) or (requester_nonprod and accepter_prod):
                    risky_peerings.append(record)

        evidence = {
            "active_peering_count": _get_net_collection_count(peerings),
            "peerings": list(peerings),
            "risky_peerings": list(risky_peerings),
        }
        if _get_net_collection_count(risky_peerings) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-25",
                "FAIL",
                evidence,
                "Direct peering between prod and non-prod environments detected",
            )
        if _get_net_collection_count(peerings) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-25",
                "PARTIAL",
                evidence,
                "Peering exists; verify environment isolation using tags and naming",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "NET-25", "PASS", evidence, "No active VPC peering connections detected"
        )

    checks["NET-25"] = net25

    checks["NET-26"] = workshop("NET-26", "Verify network flow matrix exists in DAT.")

    def net27(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["ec2", "describe-flow-logs"])
        vpcs = _get_net_vpcs(ctx)
        if data is None or vpcs is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "NET-27")

        flow_logs = _new_net_list()
        active_count = 0
        if _test_net_has_property(data, "FlowLogs"):
            for flow_log in _get_net_cli_array(data.get("FlowLogs")):
                destination = None
                if _test_net_has_property(flow_log, "LogDestinationType"):
                    destination = str(flow_log.get("LogDestinationType", "") or "")
                is_active = str(flow_log.get("FlowLogStatus", "") or "") == "ACTIVE"
                if is_active:
                    active_count += 1
                flow_log_record = {
                    "id": str(flow_log.get("FlowLogId", "") or ""),
                    "status": str(flow_log.get("FlowLogStatus", "") or ""),
                    "destination": destination,
                    "resource_id": str(flow_log.get("ResourceId", "") or ""),
                }
                flow_logs.append(flow_log_record)

        vpc_coverage: list[dict[str, Any]] = []
        vpcs_without_flow_logs = 0
        for vpc in vpcs:
            vpc_id = str(vpc.get("VpcId", "") or "")
            active_for_vpc = 0
            for flow_log in flow_logs:
                resource_id = str(flow_log.get("resource_id", "") or "")
                if resource_id == vpc_id and flow_log.get("status") == "ACTIVE":
                    active_for_vpc += 1
            vpc_coverage.append({"vpc_id": vpc_id, "active_flow_log_count": active_for_vpc})
            if active_for_vpc == 0:
                vpcs_without_flow_logs += 1

        valid_destinations = 0
        for flow_log in flow_logs:
            if flow_log.get("status") != "ACTIVE":
                continue
            if flow_log.get("destination") in ("s3", "cloud-watch-logs"):
                valid_destinations += 1

        evidence = {
            "flow_log_count": _get_net_collection_count(flow_logs),
            "active_flow_log_count": active_count,
            "valid_destination_count": valid_destinations,
            "vpc_count": _get_net_collection_count(vpcs),
            "vpcs_without_flow_logs": vpcs_without_flow_logs,
            "vpc_coverage": list(vpc_coverage),
            "flow_logs": list(flow_logs),
        }
        if valid_destinations > 0 and vpcs_without_flow_logs == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-27",
                "PASS",
                evidence,
                "All VPCs have active flow logs exporting to S3 or CloudWatch Logs",
            )
        if valid_destinations > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "NET-27",
                "PARTIAL",
                evidence,
                "Flow logs exist but not all VPCs have active flow log coverage",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "NET-27",
            "FAIL",
            evidence,
            "No active flow logs with S3 or CloudWatch Logs destination",
        )

    checks["NET-27"] = net27

    if len(checks) != 27:
        raise RuntimeError(f"get_domain expected 27 NET controls but defined {len(checks)}")

    return DomainModule(code="NET", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
