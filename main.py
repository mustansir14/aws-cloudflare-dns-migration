from typing import List, Tuple

from internal.aws import AWSClient
from internal.cloudflare import CloudflareClient
from internal.env import Env
from internal.exceptions import NotFoundException, RateLimitException

# Initialize AWS and Cloudflare clients
aws = AWSClient(Env.AWS_ACCESS_KEY_ID, Env.AWS_SECRET_ACCESS_KEY)
cloudflare = CloudflareClient(
    email=Env.CLOUDFLARE_EMAIL, api_key=Env.CLOUDFLARE_API_KEY
)


def migrate_to_cloudflare() -> Tuple[int, int, List[Tuple[str, str]]]:
    """Migrate DNS records from AWS Route 53 to Cloudflare."""

    OLD_IPs = [Env.PRIMARY_IP, Env.SECONDARY_IP]

    hosted_zones = aws.list_unique_hosted_zones()

    account = cloudflare.get_current_account()

    processed = 0
    success = 0

    failure_domains = []

    for zone_number, zone in enumerate(hosted_zones, start=1):
        try:
            cloudflare_zone_id = None
            processed += 1
            domain = zone["Name"].rstrip(".")
            print(f"Migrating domain: {domain} ({zone_number}/{len(hosted_zones)})")

            # Check if the domain already exists on Cloudflare
            try:
                existing_zone = cloudflare.get_zone_by_domain(domain=domain)
                print(f"Domain {domain} already exists on Cloudflare")
                if Env.SKIP_DNS_SYNC:
                    print("Skipping...")
                    success += 1
                    continue
                print("Syncing DNS records")
                cloudflare_zone_id = existing_zone.id
                existing_dns_records = cloudflare.get_dns_records(
                    zone_id=cloudflare_zone_id
                )
            except NotFoundException:
                # Add domain to Cloudflare
                try:
                    zone_info = cloudflare.create_zone(account=account, name=domain)
                except RateLimitException:
                    print("Rate limit error while adding domain, Exiting....")
                    failure_domains.append((domain, None))
                    break
                cloudflare_zone_id = zone_info.id
                existing_dns_records = None

            # Retrieve DNS records from AWS
            record_sets = aws.get_dns_records(zone["Id"])

            # Migrate records
            one_done = False
            for record in record_sets:
                if record["Type"] in ["NS", "SOA", "SPF"]:
                    continue  # Skip NS and SOA records, SPF records are not supported

                record_name = record["Name"].rstrip(".").replace("\\052", "*")
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
                        Env.LOAD_BALANCER_IP if r in OLD_IPs else r
                        for r in record_content
                    ]

                    if Env.LOAD_BALANCER_IP in record_content:
                        if one_done:
                            record_content.remove(Env.LOAD_BALANCER_IP)
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
                        data["target"] = content_split[2]
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
                    "action_parameters": {
                        "cache": True,
                        "edge_ttl": {"mode": "respect_origin"},
                        "browser_ttl": {"mode": "respect_origin"},
                    },
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
            # delete dangling zone
            if cloudflare_zone_id:
                cloudflare.delete_zone(cloudflare_zone_id)
            failure_domains.append((domain, zone["Id"]))

    print("Migration to Cloudflare completed.")
    return processed, success, failure_domains


def monitor_ns_propagation() -> Tuple[int, int, List[Tuple[str, str]]]:
    """
    Monitor NS propagation for Cloudflare sites and update SSL/TLS settings upon activation.
    """
    print("Starting NS propagation monitoring...")

    # Fetch all zones
    zones = cloudflare.list_zones()
    if not zones:
        print("No zones found in Cloudflare account.")
        return 0, 0, []

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
                cloudflare.check_nameservers_now(zone_id=zone_id)
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
    zones = cloudflare.list_zones()

    processed = 0
    success = 0

    failure_domains = []

    for zone in zones:
        domain = zone.name
        print(f"Migrating domain: {domain}")
        processed += 1

        try:
            # Check if the domain already exists on AWS
            try:
                existing_zone = aws.get_zone_by_domain(domain=domain)
                print(f"Domain {domain} already exists on AWS")
                if Env.SKIP_DNS_SYNC:
                    print("Skipping...")
                    continue
                print("Syncing DNS records")
                aws_zone_id = existing_zone["Id"]
                existing_dns_records = aws.get_dns_records(zone_id=aws_zone_id)
            except NotFoundException:
                # Add domain to AWS
                zone_info = aws.create_zone(domain)
                aws_zone_id = zone_info["Id"]
                existing_dns_records = None

            # Retrieve DNS records from Cloudflare
            records = cloudflare.get_dns_records(zone.id)

            create_records = []
            for record in records:
                record_name = record.name
                record_type = record.type
                content = record.content
                if record_type in ["NS", "SOA"]:
                    continue  # Skip NS and SOA records

                # we will create failover records for this
                if (
                    record_type == "A"
                    and record_name == domain
                    and Env.CREATE_FAILOVER_RECORDS
                ):
                    continue

                if existing_dns_records:
                    # Check if record already exists
                    existing_record = next(
                        (
                            r
                            for r in existing_dns_records
                            if r["Name"].rstrip(".") == record_name
                            and r["Type"] == record_type
                        ),
                        None,
                    )
                    if existing_record:
                        continue

                if record_type == "MX" or record_type == "SRV":
                    content = f"{int(record.priority)} {content}"

                create_record = {
                    "Name": record_name,
                    "Type": record_type,
                    "ResourceRecords": [{"Value": content}],
                }
                try:
                    create_record["TTL"] = int(record.ttl)
                except:
                    pass

                create_records.append(create_record)
                print(f"Adding {record_type} record: {record_name} -> {content}")

            if Env.CREATE_FAILOVER_RECORDS:
                # add primary failover record
                existing_record = next(
                    (
                        r
                        for r in existing_dns_records
                        if r["Name"].rstrip(".") == domain
                        and r["Type"] == "A"
                        and "Failover" in r
                        and r["Failover"] == "PRIMARY"
                    ),
                    None,
                )
                if not existing_record:
                    create_records.append(
                        {
                            "Name": domain,
                            "Type": "A",
                            "Failover": "PRIMARY",
                            "TTL": 300,
                            "HealthCheckId": Env.HEALTH_CHECK_ID,
                            "SetIdentifier": Env.PRIMARY_IP.split(".")[-1] + "-f",
                            "ResourceRecords": [
                                {"Value": Env.PRIMARY_IP},
                            ],
                        }
                    )
                # add secondary failover record
                existing_record = next(
                    (
                        r
                        for r in existing_dns_records
                        if r["Name"].rstrip(".") == domain
                        and r["Type"] == "A"
                        and "Failover" in r
                        and r["Failover"] == "SECONDARY"
                    ),
                    None,
                )
                if not existing_record:
                    create_records.append(
                        {
                            "Name": domain,
                            "Type": "A",
                            "Failover": "SECONDARY",
                            "TTL": 300,
                            "SetIdentifier": Env.SECONDARY_IP.split(".")[-1],
                            "ResourceRecords": [
                                {"Value": Env.SECONDARY_IP},
                            ],
                        }
                    )

            # Create records in AWS
            if create_records:
                aws.create_dns_records(zone_id=aws_zone_id, records=create_records)
            success += 1
        except Exception as e:
            print(f"Error: {e}")
            failure_domains.append((domain, zone.id))

    print("Migration to AWS completed.")
    return processed, success, failure_domains


if __name__ == "__main__":

    if Env.SCENARIO == 1:
        operation = migrate_to_cloudflare
    elif Env.SCENARIO == 2:
        operation = monitor_ns_propagation
    elif Env.SCENARIO == 3:
        operation = migrate_to_aws

    processed, success, failure_domains = operation()
    print("Total Processed: ", processed)
    print("Total Success: ", success)
    print("Total Failure: ", len(failure_domains))
    if len(failure_domains) > 0:
        print("The following domains failed:")
        for domain, zone_id in failure_domains:
            print(f"{domain} | zone id: {zone_id}")
