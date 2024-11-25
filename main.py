from typing import List, Tuple

import boto3

from internal.cloudflare import CloudflareClient, CloudflareNotFoundException
from internal.env import Env

# Initialize AWS and Cloudflare clients
aws_client = boto3.client(
    "route53",
    aws_access_key_id=Env.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=Env.AWS_SECRET_ACCESS_KEY,
)
cloudflare = CloudflareClient(
    email=Env.CLOUDFLARE_EMAIL, api_key=Env.CLOUDFLARE_API_KEY
)


def get_hosted_zones_from_aws():
    """Retrieve all hosted zones from AWS Route 53 and filter the latest unique zones."""
    hosted_zones = []
    marker = None
    print("Fetching all hosted zones from AWS Route 53...")
    while True:
        if marker:
            res = aws_client.list_hosted_zones(Marker=marker)
        else:
            res = aws_client.list_hosted_zones()
        hosted_zones.extend(res["HostedZones"])
        if res["IsTruncated"]:
            marker = res["NextMarker"]
        else:
            break

    print(f"Found {len(hosted_zones)} total hosted zones")

    # Keep only the latest hosted zone for each unique domain name
    unique_zones = {}
    for zone in hosted_zones:
        domain_name = zone["Name"]
        if domain_name not in unique_zones:
            unique_zones[domain_name] = zone
        else:
            if zone["Id"] > unique_zones[domain_name]["Id"]:
                unique_zones[domain_name] = zone

    print(f"After removing duplicates, {len(unique_zones)} unique hosted zones left")

    return unique_zones.values()


def migrate_to_cloudflare() -> Tuple[int, int, List[Tuple[str, str]]]:
    """Migrate DNS records from AWS Route 53 to Cloudflare."""

    OLD_IPs = ["209.216.83.146", "209.216.83.147"]

    hosted_zones = get_hosted_zones_from_aws()

    account = cloudflare.get_current_account()

    processed = 0
    success = 0

    failure_domains = []

    for zone_number, zone in enumerate(hosted_zones, start=1):
        try:
            domain = zone["Name"].rstrip(".")
            print(f"Migrating domain: {domain} ({zone_number}/{len(hosted_zones)})")

            # Check if the domain already exists on Cloudflare
            try:
                existing_zone = cloudflare.get_zone_by_domain(domain=domain)
                print(f"Domain {domain} already exists on Cloudflare")
                if Env.SKIP_DNS_SYNC:
                    print("Skipping...")
                    continue
                print("Syncing DNS records")
                cloudflare_zone_id = existing_zone.id
                existing_dns_records = cloudflare.get_dns_records(
                    zone_id=cloudflare_zone_id
                )
            except CloudflareNotFoundException:
                # Add domain to Cloudflare
                zone_info = cloudflare.create_zone(account=account, name=domain)
                cloudflare_zone_id = zone_info.id
                existing_dns_records = None

            # Retrieve DNS records from AWS
            record_sets = aws_client.list_resource_record_sets(
                HostedZoneId=zone["Id"],
                MaxItems="1000",
            )["ResourceRecordSets"]

            # Migrate records
            one_done = False
            for record in record_sets:
                if record["Type"] in ["NS", "SOA", "SPF"]:
                    continue  # Skip NS and SOA records, SPF records are not supported

                record_name = record["Name"].rstrip(".")
                record_type = record["Type"]
                kwargs = {}
                data = {}
                if "TTL" in record:
                    kwargs["ttl"] = record["TTL"]
                if "ResourceRecords" not in record:
                    continue
                record_content = [
                    r["Value"] for r in record["ResourceRecords"]
                ]  # Transform IP for A/CNAME if needed
                if record_type in ["A", "CNAME"]:
                    record_content = [
                        "44.198.12.127" if r in OLD_IPs else r for r in record_content
                    ]

                    if "44.198.12.127" in record_content:
                        if one_done:
                            record_content.remove("44.198.12.127")
                        else:
                            one_done = True

                # Create record on Cloudflare
                for content in record_content:
                    if record_type == "MX" or record_type == "SRV":
                        content_split = content.split()
                        content = " ".join(content_split[1:])
                        kwargs["priority"] = int(content_split[0])
                    if record_type == "SRV":
                        content_split = content.split()
                        data["weight"] = int(content_split[0])
                        data["port"] = int(content_split[1])
                        data["target"] = content
                    if (record_type == "A" and record_name == domain) or (
                        record_type == "CNAME" and record_name.startswith("www")
                    ):
                        kwargs["proxied"] = True

                    record_exists = False
                    if existing_dns_records:
                        for existing_record in existing_dns_records:
                            if (
                                existing_record.name == record_name
                                and existing_record.type == record_type
                                and existing_record.content.lower()
                                == content.lower().rstrip(".")
                            ):
                                record_exists = True
                                break

                    if record_exists:
                        continue

                    cloudflare.create_dns_record(
                        zone_id=cloudflare_zone_id,
                        content=content,
                        record_name=record_name,
                        record_type=record_type,
                        data=data,
                        **kwargs,
                    )
                    print(f"Added {record_type} record: {record_name} -> {content}")

            # Additional Cloudflare configurations
            print("Setting SSL encryption mode to full")
            cloudflare.edit_setting(
                zone_id=cloudflare_zone_id, name="ssl", value="full"
            )
            print("Setting always_use_https to off")
            cloudflare.edit_setting(
                zone_id=cloudflare_zone_id, name="always_use_https", value="off"
            )

            # Add WAF rules
            print("Adding WAF rules...")
            waf_rules = [
                {
                    "action": "skip",
                    "description": "UptimeRobot IP List Bypass WAF",
                    "expression": "(ip.src in $uptimetobot_ip_list)",
                    "action_parameters": {
                        "ruleset": "current",
                        "phases": [
                            "http_ratelimit",
                            "http_request_sbfm",
                            "http_request_firewall_managed",
                        ],
                        "products": [
                            "zoneLockdown",
                            "uaBlock",
                            "bic",
                            "hot",
                            "securityLevel",
                            "rateLimit",
                            "waf",
                        ],
                    },
                },
                {
                    "action": "block",
                    "description": "Country block list",
                    "expression": '(ip.geoip.country in {"CN" "KP" "RU" "T1" "XX"})',
                    "action_parameters": {},
                },
            ]
            cloudflare.add_rules(
                zone_id=cloudflare_zone_id,
                phase="http_request_firewall_custom",
                rules=waf_rules,
                ruleset_name="WAF rules",
            )

            # Speed optimization settings
            print("Configuring speed optimizations...")
            speed_optimization_settings = [
                "speed_brain",
                "fonts",
                "early_hints",
                "rocket_loader",
            ]
            for speed_optimization_setting in speed_optimization_settings:
                cloudflare.edit_setting(
                    zone_id=cloudflare_zone_id,
                    name=speed_optimization_setting,
                    value="on",
                )

            # Configure caching settings
            print("Configuring caching settings...")
            cloudflare.edit_setting(
                zone_id=cloudflare_zone_id, name="cache_level", value="aggressive"
            )
            cloudflare.edit_setting(
                zone_id=cloudflare_zone_id, name="browser_cache_ttl", value=2678400
            )
            cloudflare.edit_setting(
                zone_id=cloudflare_zone_id, name="always_online", value="on"
            )
            cache_rules = [
                {
                    "description": "ByPass WP Cache",
                    "expression": """(starts_with(http.request.uri.path, "/wp-admin")) or 
                            (http.request.full_uri contains "/wp-login.php") or (http.request.full_uri contains 
                            "/creative813-login") or (http.request.full_uri contains "/checkout") or 
                            (http.request.full_uri contains "/kasse") or (http.request.full_uri contains "/cart") or 
                            (http.request.full_uri contains "/handlekurv") or (http.request.full_uri contains "/my-
                            account") or (http.request.full_uri contains ".txt") or (http.request.full_uri contains 
                            ".xlst") or (http.request.full_uri contains ".xml") or (http.cookie contains "no_cache") 
                            or (http.cookie contains "wp-") or (http.cookie contains "wordpress-") or (http.cookie 
                            contains "comment_") or (http.cookie contains "woocommerce_") or (http.cookie 
                            contains "PHPSESSID") or (starts_with(http.request.full_uri, "/graphql")) or 
                            (starts_with(http.request.full_uri, "/xmlrpc.php"))""",
                    "action": "set_cache_settings",
                    "action_parameters": {"cache": False},
                },
                {
                    "description": "Cache Everything",
                    "expression": 'http.request.method in {"GET" "HEAD"}',
                    "action": "set_cache_settings",
                    "action_parameters": {"cache": True},
                },
            ]
            cloudflare.add_rules(
                zone_id=cloudflare_zone_id,
                phase="http_request_cache_settings",
                rules=cache_rules,
                ruleset_name="Cache Rules",
            )

            # Add Page Rule for Let's Encrypt
            print("Adding page rule for Let's Encrypt...")
            cloudflare.add_page_rule(zone_id=cloudflare_zone_id, domain=domain)
            success += 1
        except Exception as e:
            print(f"Error: {e}")
            failure_domains.append((domain, zone["Id"]))
        processed += 1

    print("Migration to Cloudflare completed.")
    return processed, success, failure_domains


def monitor_ns_propagation() -> Tuple[int, int, List[Tuple[str, str]]]:
    """
    Monitor NS propagation for Cloudflare sites and update SSL/TLS settings upon activation.
    """
    print("Starting NS propagation monitoring...")

    # Fetch all zones
    zones = cloudflare.cloudflare.zones.list().result
    if not zones:
        print("No zones found in Cloudflare account.")
        return

    processed = 0
    success = 0

    failure_domains = []

    for zone in zones:
        domain = zone.name
        zone_id = zone.id

        # Check the status of the domain
        status = zone.status
        print(f"Domain: {domain}, Status: {status}")
        processed += 1

        if status == "pending":
            print(f"Triggering 'Check nameserver now' for domain: {domain}")
            try:
                cloudflare.cloudflare.zones.activation_check.trigger(zone_id=zone_id)
                print(f"Nameserver check triggered for {domain}")
                success += 1
            except Exception as e:
                failure_domains.append((domain, zone_id))
                print(f"Failed to trigger nameserver check for {domain}: {e}")

        elif status == "active":
            print(f"Updating SSL/TLS settings for active domain: {domain}")
            try:
                # Set SSL/TLS to "Custom" with encryption type "Full"
                cloudflare.edit_setting(zone_id=zone_id, name="ssl", value="full")
                print(f"SSL/TLS settings updated to 'Full' for {domain}")
                success += 1
            except Exception as e:
                print(f"Failed to update SSL/TLS settings for {domain}: {e}")
                failure_domains.append((domain, zone_id))

    print("NS propagation monitoring completed.")
    return processed, success, failure_domains


def migrate_to_aws():
    """Migrate DNS records from Cloudflare to AWS Route 53."""
    zones = cloudflare.zones.get()

    for zone in zones:
        domain = zone["name"]
        print(f"Migrating domain: {domain}")

        # Check if hosted zone exists on AWS
        existing_zones = get_hosted_zones_from_aws()
        if domain in [z["Name"].rstrip(".") for z in existing_zones]:
            print(f"Domain {domain} already exists on AWS. Skipping...")
            continue

        # Create hosted zone
        hosted_zone = aws_client.create_hosted_zone(
            Name=domain,
            CallerReference=str(hash(domain)),
        )
        hosted_zone_id = hosted_zone["HostedZone"]["Id"]

        # Retrieve DNS records from Cloudflare
        records = cloudflare.zones.dns_records.get(zone["id"])

        for record in records:
            if record["type"] in ["NS", "SOA"]:
                continue  # Skip NS and SOA records

            # Create record in AWS
            aws_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "CREATE",
                            "ResourceRecordSet": {
                                "Name": record["name"],
                                "Type": record["type"],
                                "TTL": record["ttl"],
                                "ResourceRecords": [{"Value": record["content"]}],
                            },
                        }
                    ]
                },
            )
            print(
                f"Added {record['type']} record: {record['name']} -> {record['content']}"
            )

    print("Migration to AWS completed.")


if __name__ == "__main__":
    # import argparse

    # parser = argparse.ArgumentParser(description="Migrate DNS Records")
    # parser.add_argument(
    #     "--direction", choices=["aws-to-cloudflare", "cloudflare-to-aws"], required=True
    # )
    # args = parser.parse_args()

    # if args.direction == "aws-to-cloudflare":
    #     migrate_to_cloudflare()
    # elif args.direction == "cloudflare-to-aws":
    #     migrate_to_aws()

    processed, success, failure_domains = monitor_ns_propagation()
    print("Total Processed: ", processed)
    print("Total Success: ", success)
    print("Total Failure: ", len(failure_domains))
    if len(failure_domains) > 0:
        print("The following domains failed:")
        for domain, zone_id in failure_domains:
            print(f"{domain} | zone id: {zone_id}")
