import boto3

from internal.exceptions import NotFoundException

class AWSClient:

    def __init__(self, access_key_id: str, secret_access_key: str):
        self.client = boto3.client(
            "route53",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )

    
    def list_unique_hosted_zones(self):
        """Retrieve all hosted zones from AWS Route 53 and filter the latest unique zones."""
        hosted_zones = []
        marker = None
        print("Fetching all hosted zones from AWS Route 53...")
        while True:
            if marker:
                res = self.client.list_hosted_zones(Marker=marker)
            else:
                res = self.client.list_hosted_zones()
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
    

    def get_dns_records(self, zone_id: str):
        return self.client.list_resource_record_sets(
                HostedZoneId=zone_id,
                MaxItems="1000",
            )["ResourceRecordSets"]
    
    def get_zone_by_domain(self, domain: str) -> object:
        zones = self.client.list_hosted_zones_by_name(DNSName=domain, MaxItems="1")["HostedZones"]
        if not zones or zones[0]["Name"].rstrip(".") != domain:
            raise NotFoundException(f"Zone with domain {domain} not found")
        return zones[0]
    
    def create_zone(self, domain: str) -> object:
        return self.client.create_hosted_zone(
            Name=domain,
            CallerReference=str(hash(domain)),
        )["HostedZone"]