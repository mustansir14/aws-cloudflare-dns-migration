import boto3
from cloudflare import Cloudflare, BadRequestError
from internal.env import Env


# Initialize AWS and Cloudflare clients
aws_client = boto3.client(
    "route53",
    aws_access_key_id=Env.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=Env.AWS_SECRET_ACCESS_KEY,
)
cloudflare = Cloudflare(api_email=Env.CLOUDFLARE_EMAIL, api_key=Env.CLOUDFLARE_API_KEY)


def get_hosted_zones_from_aws():
    """Retrieve all hosted zones from AWS Route 53 and filter the latest unique zones."""
    hosted_zones = []
    marker = None
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

    # Keep only the latest hosted zone for each unique domain name
    unique_zones = {}
    for zone in hosted_zones:
        domain_name = zone["Name"]
        if domain_name not in unique_zones:
            unique_zones[domain_name] = zone
        else:
            if zone["Id"] > unique_zones[domain_name]["Id"]:
                unique_zones[domain_name] = zone

    return unique_zones.values()



def migrate_to_cloudflare():
    """Migrate DNS records from AWS Route 53 to Cloudflare."""

    OLD_IPs = ["209.216.83.146", "209.216.83.147"]

    hosted_zones = get_hosted_zones_from_aws()

    account = cloudflare.accounts.list().result[0]

    for zone in hosted_zones:
        domain = zone["Name"].rstrip(".")
        print(f"Migrating domain: {domain}")

        # Check if the domain already exists on Cloudflare
        existing_zones = cloudflare.zones.list(name=domain)
        if existing_zones.result:
            print(f"Domain {domain} already exists on Cloudflare")
            if Env.SKIP_DNS_SYNC:
                print("Skipping...")
                continue
            print("Syncing DNS records")
            cloudflare_zone_id = existing_zones.result[0].id
            existing_dns_records = cloudflare.dns.records.list(zone_id=cloudflare_zone_id).result
        else:
            # Add domain to Cloudflare
            zone_info = cloudflare.zones.create(account=account, name=domain)
            cloudflare_zone_id = zone_info.id
            existing_dns_records = None

        # Retrieve DNS records from AWS
        record_sets = aws_client.list_resource_record_sets(
            HostedZoneId=zone["Id"]
        )["ResourceRecordSets"]

        # Migrate records
        one_done = False
        for record in record_sets:
            if record["Type"] in ["NS", "SOA"]:
                continue  # Skip NS and SOA records

            record_name = record["Name"].rstrip(".")
            record_type = record["Type"]
            record_ttl = record["TTL"]
            record_content = [
                r["Value"] for r in record["ResourceRecords"]
            ]  # Transform IP for A/CNAME if needed
            if record_type in ["A", "CNAME"]:
                record_content = [
                    "44.198.12.127" if r in OLD_IPs else r
                    for r in record_content
                ]

                if "44.198.12.127" in record_content:
                    if one_done:
                        record_content.remove("44.198.12.127")
                    else:
                        one_done = True

            # Create record on Cloudflare
            for content in record_content:
                if record_type == "MX":
                    content_split = content.split()
                    content = content_split[1]
                    kwargs = {
                        "priority": int(content_split[0])
                    }
                else:
                    kwargs = {}

                
                if (record_type == "A" and record_name == domain) or (record_type == "CNAME" and record_name.startswith("www")):
                    kwargs["proxied"] = True 
                    
                record_exists = False
                if existing_dns_records:
                    for existing_record in existing_dns_records:
                        if (
                            existing_record.name == record_name
                            and existing_record.type == record_type
                            and existing_record.content.lower() == content.lower().rstrip(".")
                        ):
                            record_exists = True
                            break
                
                if record_exists:
                    continue
                
                try:
                    cloudflare.dns.records.create(
                        zone_id=cloudflare_zone_id, 
                        content=content, 
                        name=record_name, 
                        type=record_type, 
                        ttl=record_ttl,
                        **kwargs
                    )
                except BadRequestError as e:
                    if "already exists" in str(e):
                        continue
                print(f"Added {record_type} record: {record_name} -> {content}")

        # Additional Cloudflare configurations
        cloudflare.zones.settings.edit(zone_id=cloudflare_zone_id, setting_id="ssl", value="full")
        cloudflare.zones.settings.edit(zone_id=cloudflare_zone_id, setting_id="always_use_https", value="off")
        

    print("Migration to Cloudflare completed.")


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
                                "ResourceRecords": [
                                    {"Value": record["content"]}
                                ],
                            },
                        }
                    ]
                },
            )
            print(f"Added {record['type']} record: {record['name']} -> {record['content']}")

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

    migrate_to_cloudflare()
