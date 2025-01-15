from internal.cloudflare import CloudflareClient
from internal.env import Env

cloudflare = CloudflareClient(Env.CLOUDFLARE_EMAIL, Env.CLOUDFLARE_API_KEY)

zones = cloudflare.list_zones()

print(f"Editing 'Cache Everything' rule for {len(zones)} zones")

for zone in zones:
    
    cache_rules = [
        {
            "description": "Cache Everything",
            "expression": 'true',
            "action": "set_cache_settings",
            "action_parameters": {
                "cache": True,
                "edge_ttl": {"mode": "respect_origin"},
                "browser_ttl": {"mode": "respect_origin"},
            },
        },
    ]
    cloudflare.add_rules(
        zone_id=zone.id,
        phase="http_request_cache_settings",
        rules=cache_rules,
        ruleset_name="Cache Rules",
    )

print("All done!")