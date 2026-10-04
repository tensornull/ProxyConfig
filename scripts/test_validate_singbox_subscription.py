#!/usr/bin/env python3
"""Unit checks for the template policy assertions in the validator."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_singbox_subscription import (
    ADS_RULE_SET,
    check_document,
    infer_template_variant,
    selected_templates,
)


def policy_document(variant: str) -> dict:
    """Build a small, node-free document that exercises policy checks."""

    rule_sets = [
        {"tag": tag, "type": "remote", "format": "binary", "url": "https://rules.invalid/" + tag}
        for tag in (ADS_RULE_SET, "geosite-cn", "geoip-cn", "geosite-geolocation-!cn", "geosite-steam")
    ]
    route_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"rule_set": ADS_RULE_SET, "action": "reject"},
        {
            "protocol": "quic",
            "rule_set": ["geosite-cn", "geoip-cn"],
            "action": "route",
            "outbound": "🇨🇳 China",
        },
        {"protocol": "quic", "action": "reject"},
        {"clash_mode": "direct", "action": "route", "outbound": "direct"},
        {
            "clash_mode": "global",
            "action": "route",
            "outbound": "🛩️ NodeSelected",
        },
        {"rule_set": "geosite-cn", "action": "route", "outbound": "🇨🇳 China"},
        {
            "rule_set": "geosite-geolocation-!cn",
            "action": "route",
            "outbound": "🎯 Foreign",
        },
    ]
    if variant == "v4":
        route_rules.insert(
            0,
            {"ip_version": 6, "network": "tcp", "action": "reject", "no_drop": True},
        )

    return {
        "dns": {
            "strategy": "ipv4_only" if variant == "v4" else "prefer_ipv6",
            "final": "dns_resolver",
            "servers": [{"tag": "dns_resolver"}, {"tag": "dns_proxy"}],
            "rules": [
                {"rule_set": ADS_RULE_SET, "action": "reject"},
                {"rule_set": "geosite-cn", "server": "dns_resolver"},
                {"clash_mode": "direct", "server": "dns_resolver"},
                {"clash_mode": "global", "server": "dns_proxy"},
                {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"},
            ],
        },
        "inbounds": [
            {
                "type": "tun",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "route_exclude_address": ["fc00::/7"],
                "auto_route": True,
            }
        ],
        "route": {
            "final": "😮‍💨 Final",
            "default_domain_resolver": {
                "server": "dns_resolver",
                "strategy": "prefer_ipv4" if variant == "v4" else "prefer_ipv6",
            },
            "rules": route_rules,
            "rule_set": rule_sets,
        },
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "trojan", "tag": "node"},
            {
                "type": "selector",
                "tag": "🛩️ NodeSelected",
                "outbounds": ["node"],
                "default": "node",
            },
            {
                "type": "selector",
                "tag": "🇨🇳 China",
                "outbounds": ["direct", "🛩️ NodeSelected"],
                "default": "direct",
            },
            {
                "type": "selector",
                "tag": "🎯 Foreign",
                "outbounds": ["🛩️ NodeSelected"],
                "default": "🛩️ NodeSelected",
            },
            {
                "type": "selector",
                "tag": "😮‍💨 Final",
                "outbounds": ["direct"],
                "default": "direct",
            },
        ],
    }


class ValidatorPolicyTests(unittest.TestCase):
    def validate(self, doc: dict, variant: str | None):
        return check_document(
            "test-template",
            doc,
            allow_placeholders=True,
            require_real_nodes=False,
            expected_variant=variant,
        )[0]

    def test_v4_policy_passes(self):
        self.assertEqual(self.validate(policy_document("v4"), "v4"), [])

    def test_v6_policy_passes_without_ipv6_reject(self):
        self.assertEqual(self.validate(policy_document("v6"), "v6"), [])

    def test_v4_requires_pre_sniff_ipv6_reject(self):
        document = policy_document("v4")
        document["route"]["rules"].pop(0)
        failures = self.validate(document, "v4")
        self.assertTrue(any("pre-sniff" in failure for failure in failures))

    def test_v4_requires_prefer_ipv4_resolver(self):
        document = policy_document("v4")
        document["route"]["default_domain_resolver"]["strategy"] = "prefer_ipv6"
        failures = self.validate(document, "v4")
        self.assertTrue(any("prefer_ipv4" in failure for failure in failures))

    def test_v6_rejects_pre_sniff_ipv6_reject(self):
        document = policy_document("v6")
        document["route"]["rules"].insert(
            0,
            {"ip_version": 6, "network": "tcp", "action": "reject", "no_drop": True},
        )
        failures = self.validate(document, "v6")
        self.assertTrue(any("must not pre-reject" in failure for failure in failures))

    def test_outbound_rule_requires_explicit_route_action(self):
        document = policy_document("v4")
        document["route"]["rules"][6].pop("action")
        failures = self.validate(document, "v4")
        self.assertTrue(any("action=route" in failure for failure in failures))

    def test_ads_must_precede_business_rules(self):
        document = policy_document("v4")
        ads_rule = document["route"]["rules"].pop(3)
        document["route"]["rules"].append(ads_rule)
        failures = self.validate(document, "v4")
        self.assertTrue(any("business/mode" in failure for failure in failures))

    def test_hand_written_process_and_app_rules_fail(self):
        document = policy_document("v4")
        document["route"]["rules"].insert(
            4,
            {"process_name": ["WeChat"], "action": "route", "outbound": "🇨🇳 China"},
        )
        failures = self.validate(document, "v4")
        self.assertTrue(any("process_name" in failure for failure in failures))

    def test_variant_inference_and_directory_selection(self):
        self.assertEqual(infer_template_variant(Path("country-auto-v4.json")), "v4")
        self.assertEqual(infer_template_variant(Path("country-auto-v6.json")), "v6")
        self.assertEqual(infer_template_variant(Path("country-auto.json")), "v6")
        self.assertEqual(infer_template_variant(Path("custom.json")), None)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "country-auto-v4.json").write_text("{}", encoding="utf-8")
            (root / "country-auto-v6.json").write_text("{}", encoding="utf-8")
            (root / "ignore.txt").write_text("", encoding="utf-8")
            selected = selected_templates([f"{root / 'country-auto-v4.json'},{root}"])
            self.assertEqual(
                [path.name for path in selected],
                ["country-auto-v4.json", "country-auto-v6.json"],
            )


if __name__ == "__main__":
    unittest.main()
