import warnings
from typing import Dict, List

from cloudflare import (BadRequestError, Cloudflare, NotFoundError,
                        RateLimitError)

from internal.exceptions import NotFoundException, RateLimitException

warnings.filterwarnings("ignore", category=DeprecationWarning)


class CloudflareClient:
    def __init__(self, email: str, api_key: str):
        self.cloudflare = Cloudflare(api_email=email, api_key=api_key)

    def get_current_account(self) -> object:
        return self.cloudflare.accounts.list().result[0]

    def get_zone_by_domain(self, domain: str) -> object:
        zone = self.cloudflare.zones.list(name=domain)
        if zone.result:
            return zone.result[0]
        raise NotFoundException(f"Zone with domain {domain} not found")

    def get_dns_records(self, zone_id: str) -> List[object]:
        dns_records = []
        for dns_record in self.cloudflare.dns.records.list(zone_id=zone_id):
            dns_records.append(dns_record)
        return dns_records

    def create_zone(self, account: object, name: str) -> object:
        try:
            return self.cloudflare.zones.create(account=account, name=name)
        except RateLimitError:
            raise RateLimitException("Domain adding limit exceeded.")

    def create_dns_record(
        self,
        zone_id: str,
        content: str,
        record_name: str,
        record_type: str,
        data: Dict,
        **kwargs,
    ):
        if data:
            kwargs["data"] = data
        else:
            kwargs["content"] = content

        if "priority" in kwargs and data:
            data["priority"] = kwargs["priority"]
        try:
            self.cloudflare.dns.records.create(
                zone_id=zone_id, name=record_name, type=record_type, **kwargs
            )
        except BadRequestError as e:
            if "already exists" in str(e):
                return
            raise e

    def edit_setting(self, zone_id: str, name: str, value: str):
        self.cloudflare.zones.settings.edit(
            zone_id=zone_id, setting_id=name, value=value
        )

    def add_rules(self, zone_id: str, phase: str, rules: List[Dict], ruleset_name: str):
        try:
            ruleset = self.cloudflare.rulesets.phases.get(
                zone_id=zone_id, ruleset_phase=phase
            )
        except NotFoundError:
            ruleset = self.cloudflare.rulesets.create(
                zone_id=zone_id, phase=phase, kind="zone", name=ruleset_name, rules=[]
            )

        # Update ruleset with the rules
        for rule in rules:
            if ruleset.rules:
                rule_exists = False
                for existing_rule in ruleset.rules:
                    if existing_rule.description == rule["description"]:
                        rule_exists = True
                        break

                if rule_exists:
                    continue

            self.cloudflare.rulesets.rules.create(
                ruleset_id=ruleset.id,
                zone_id=zone_id,
                action=rule["action"],
                expression=rule["expression"],
                description=rule["description"],
                action_parameters=rule["action_parameters"],
            )

    def add_page_rule(self, zone_id: str, domain) -> None:
        try:
            self.cloudflare.pagerules.create(
                zone_id=zone_id,
                actions=[{"id": "disable_security"}, {"id": "ssl", "value": "off"}],
                targets=[
                    {
                        "constraint": {
                            "operator": "matches",
                            "value": f"*{domain}/.well-known/acme-challenge/*",
                        },
                        "target": "url",
                    }
                ],
                status="active",
            )
        except BadRequestError as e:
            if "existing page rule" in str(e):
                return
            raise e

    def list_zones(self) -> List[object]:
        print("Fetching all hosted zones from cloudflare....")
        zones = []
        for zone in self.cloudflare.zones.list():
            zones.append(zone)
        return zones

    def check_nameservers_now(self, zone_id: str) -> None:
        self.cloudflare.zones.activation_check.trigger(zone_id=zone_id)


    def delete_zone(self, zone_id: str):
        self.cloudflare.zones.delete(zone_id=zone_id)
