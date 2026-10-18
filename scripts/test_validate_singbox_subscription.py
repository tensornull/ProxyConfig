#!/usr/bin/env python3
"""Unit checks for the template policy assertions in the validator."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import test_singbox_templates as probes

from scripts.validate_singbox_subscription import (
    ADS_RULE_SET,
    REQUIRED_SERVICE_RULESETS,
    check_document,
    check_simplified_policy,
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
        {
            "rule_set": ADS_RULE_SET,
            "action": "route",
            "outbound": "🌱 Purification",
        },
        {
            "protocol": "quic",
            "rule_set": ["geosite-cn", "geoip-cn"],
            "action": "route",
            "outbound": "🇨🇳 China",
        },
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
        {"protocol": "quic", "action": "reject"},
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
            "servers": [
                {"tag": "fakeip", "type": "fakeip"},
                {"tag": "dns_resolver"},
                {"tag": "dns_proxy"},
            ],
            "rules": [
                {"rule_set": ADS_RULE_SET, "server": "fakeip"},
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
            {"type": "block", "tag": "reject"},
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
                "tag": "🌱 Purification",
                "outbounds": ["direct", "reject", "🛩️ NodeSelected"],
                "default": "direct",
            },
            {
                "type": "selector",
                "tag": "😮‍💨 Final",
                "outbounds": ["direct"],
                "default": "direct",
            },
        ],
    }


def simplified_document() -> dict:
    """An expanded policy fixture with distinct real country members."""
    document = policy_document("v6")
    countries = ["🇭🇰 Hong Kong", "🇯🇵 Japan", "🇸🇬 Singapore", "🇹🇼 Taiwan", "🇺🇸 America"]
    for index, country in enumerate(countries):
        node = f"country-node-{index}"
        document["outbounds"].extend([
            {"tag": node, "type": "trojan"},
            {"tag": country, "type": "selector", "outbounds": [node], "default": node},
        ])
    document["outbounds"].extend([
        {"tag": "🤖 AI", "type": "selector", "outbounds": countries[1:],
         "default": "🇺🇸 America"},
        {"tag": "🎮 Other", "type": "selector", "outbounds": ["🛩️ NodeSelected", "direct"],
         "default": "🛩️ NodeSelected"},
    ])
    document["route"]["rule_set"] = [
        {"tag": tag, "type": "remote", "format": "binary", "url": "https://rules.invalid/" + tag}
        for tag in REQUIRED_SERVICE_RULESETS
    ]
    ai_sets = ["geosite-openai", "geosite-anthropic", "geosite-google-gemini"]
    original = document["route"]["rules"]
    document["route"]["rules"] = [
        *original[:2],
        {"rule_set": ai_sets, "clash_mode": "rule", "action": "route", "outbound": "🤖 AI"},
        *original[2:6],
        {"rule_set": "geosite-steam", "action": "route", "outbound": "🎮 Other"},
        original[6],
        {"rule_set": ["geosite-google", "geoip-google", "geosite-microsoft", "geosite-github"],
         "action": "route", "outbound": "🛩️ NodeSelected"},
        {"rule_set": ["geosite-apple", "geosite-bilibili"], "action": "route", "outbound": "direct"},
        original[7],
        {"rule_set": ["geoip-cn", "geosite-feishu"], "action": "route", "outbound": "🇨🇳 China"},
        *original[8:],
    ]
    document["dns"]["rules"].insert(0, {
        "rule_set": ai_sets, "clash_mode": "rule", "query_type": ["A", "AAAA"], "server": "fakeip",
    })
    return document


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

    def test_tailscale_rejects_physical_interface_exclusion(self):
        document = policy_document("v6")
        document["outbounds"].append({"type": "direct", "tag": "tailscale-direct"})
        document["inbounds"][0]["route_exclude_address"].append("100.64.0.0/10")
        failures = self.validate(document, "v6")
        self.assertTrue(any("Apple TUN excluded route" in failure for failure in failures))

    def test_tailscale_without_physical_interface_exclusion_passes(self):
        document = policy_document("v6")
        document["outbounds"].append({"type": "direct", "tag": "tailscale-direct"})
        self.assertEqual(self.validate(document, "v6"), [])

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
        ads_index = next(
            index
            for index, rule in enumerate(document["route"]["rules"])
            if rule.get("rule_set") == ADS_RULE_SET
        )
        ads_rule = document["route"]["rules"].pop(ads_index)
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


class SimplifiedPolicyTests(unittest.TestCase):
    def validate(self, document: dict) -> list[str]:
        return check_document("candidate", document, allow_placeholders=False,
                              require_real_nodes=True, require_simplified_policy=True)[0]

    def test_expanded_candidate_passes(self):
        self.assertEqual(self.validate(simplified_document()), [])

    def test_old_final_remains_an_optional_baseline(self):
        document = policy_document("v6")
        failures, stats = check_document("old-final", document, allow_placeholders=True,
                                         require_real_nodes=False)
        self.assertEqual(failures, [])
        self.assertFalse(stats["simplified_policy_checked"])
        self.assertTrue(check_simplified_policy("candidate", document))

    def test_ai_rejects_direct_candidate(self):
        document = simplified_document()
        ai = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "🤖 AI")
        ai["outbounds"].append("direct")
        self.assertTrue(any("AI candidates" in failure for failure in self.validate(document)))

    def test_ai_rejects_nested_direct_leaf(self):
        document = simplified_document()
        japan = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "🇯🇵 Japan")
        japan["outbounds"] = ["nested"]
        document["outbounds"].append({"tag": "nested", "type": "urltest", "outbounds": ["direct"]})
        self.assertTrue(any("non-proxy leaf" in failure for failure in self.validate(document)))

    def test_ai_rejects_hong_kong_leaf_under_an_allowed_country(self):
        document = simplified_document()
        japan = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "🇯🇵 Japan")
        japan["outbounds"] = ["country-node-0"]
        japan["default"] = "country-node-0"
        self.assertTrue(any("Hong Kong node" in failure for failure in self.validate(document)))

    def test_ai_rejects_selector_cycle(self):
        document = simplified_document()
        japan = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "🇯🇵 Japan")
        japan["outbounds"] = ["🤖 AI"]
        self.assertTrue(any("selector cycle" in failure for failure in self.validate(document)))

    def test_expanded_ai_country_must_have_real_nodes(self):
        document = simplified_document()
        japan = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "🇯🇵 Japan")
        japan["outbounds"] = ["{all}"]
        self.assertTrue(any("AI country" in failure for failure in self.validate(document)))

    def test_ai_route_must_precede_ads(self):
        document = simplified_document()
        rules = document["route"]["rules"]
        rules[2], rules[3] = rules[3], rules[2]
        self.assertTrue(any("route AI rule must precede ads" in failure for failure in self.validate(document)))

    def test_ai_cannot_be_shadowed_by_an_earlier_route(self):
        document = simplified_document()
        document["route"]["rules"].insert(2, {
            "domain_suffix": "openai.com", "action": "route", "outbound": "direct",
        })
        self.assertTrue(any("unsafe earlier terminal" in failure for failure in self.validate(document)))

    def test_unscoped_dns_hijack_is_not_a_safe_ai_prefix(self):
        document = simplified_document()
        document["route"]["rules"][1].pop("protocol")
        self.assertTrue(any("unsafe earlier terminal" in failure for failure in self.validate(document)))

    def test_ai_dns_must_cover_gemini_in_rule_mode(self):
        document = simplified_document()
        document["dns"]["rules"][0]["rule_set"].remove("geosite-google-gemini")
        self.assertTrue(any("dns needs one complete rule-mode AI rule" in failure
                            for failure in self.validate(document)))

    def test_gemini_cannot_remain_in_general_google_rule(self):
        document = simplified_document()
        rule = next(rule for rule in document["route"]["rules"]
                    if "geosite-google" in probes.as_list(rule.get("rule_set")))
        rule["rule_set"].append("geosite-google-gemini")
        self.assertTrue(any("route needs one complete rule-mode AI rule" in failure
                            for failure in self.validate(document)))

    def test_removed_selector_reference_fails(self):
        document = simplified_document()
        document["dns"]["servers"][1]["detour"] = "🌐 Google"
        self.assertTrue(any("removed service selector/reference" in failure
                            for failure in self.validate(document)))
        document = simplified_document()
        document["experimental"] = {"clash_api": {"external_ui_download_detour": "🍎 Apple"}}
        self.assertTrue(any("removed service selector/reference" in failure
                            for failure in self.validate(document)))

    def test_original_remote_service_sets_must_remain(self):
        document = simplified_document()
        document["route"]["rule_set"] = [rule for rule in document["route"]["rule_set"]
                                         if rule["tag"] != "geosite-twitter"]
        self.assertTrue(any("retain all remote service" in failure for failure in self.validate(document)))

    def test_domestic_rules_precede_google_microsoft_and_media(self):
        document = simplified_document()
        rules = document["route"]["rules"]
        cn = next(rule for rule in rules if rule.get("rule_set") == "geosite-cn")
        rules.remove(cn)
        rules.insert(-1, cn)
        self.assertTrue(any("general geosite-cn" in failure for failure in self.validate(document)))

    def test_domestic_route_cannot_override_mode_or_steam(self):
        document = simplified_document()
        rules = document["route"]["rules"]
        cn = next(rule for rule in rules if rule.get("rule_set") == "geosite-cn")
        rules.remove(cn)
        rules.insert(4, cn)
        self.assertTrue(any("mode/Steam/infrastructure" in failure for failure in self.validate(document)))

    def test_geoip_china_cannot_override_foreign_geolocation_or_mode(self):
        document = simplified_document()
        rules = document["route"]["rules"]
        geoip = next(rule for rule in rules if rule.get("rule_set") == ["geoip-cn", "geosite-feishu"])
        rules.remove(geoip)
        rules.insert(4, geoip)
        self.assertTrue(any("non-QUIC geoip-cn" in failure for failure in self.validate(document)))

    def test_early_ai_dns_does_not_replace_generic_fakeip_order_check(self):
        document = simplified_document()
        document["dns"]["reverse_mapping"] = True
        document["dns"]["servers"][0].update({
            "inet4_range": "198.18.0.0/15", "inet6_range": "2001:2::/48",
        })
        document["experimental"] = {"cache_file": {"enabled": True, "store_fakeip": True}}
        rules = document["dns"]["rules"]
        index = next(index for index, rule in enumerate(rules) if rule.get("clash_mode") == "global")
        rules.insert(index, {"query_type": ["A", "AAAA"], "server": "fakeip"})
        result = probes.CheckResult()
        probes.check_fakeip("candidate", document, result)
        self.assertEqual(result.failures, [])


class RouteProbeTests(unittest.TestCase):
    def evaluate(self, rules: list[dict], **context):
        packet = {"domain": "api.openai.com", "mode": "rule", "protocol": "tls",
                  "network": "tcp", "port": 443, "ip_version": 4, "inbound": "tun-in", **context}
        memberships = {
            "geosite-openai": {"api.openai.com", "browser-intake-datadoghq.com"},
            ADS_RULE_SET: {"browser-intake-datadoghq.com"},
            "geosite-cn": {"google.cn"}, "geosite-google": {"google.cn"},
        }
        return probes.evaluate_route({"route": {"rules": rules, "final": "fallback"}}, packet,
                                     lambda tag, metadata: metadata["domain"] in memberships.get(tag, set()))

    def test_ai_and_ads_intersection_respects_mode(self):
        rules = simplified_document()["route"]["rules"]
        for mode, main, telemetry in (
            ("rule", "🤖 AI", "🤖 AI"),
            ("direct", "direct", "🌱 Purification"),
            ("global", "🛩️ NodeSelected", "🌱 Purification"),
        ):
            with self.subTest(mode=mode):
                self.assertEqual(self.evaluate(rules, mode=mode)[0], main)
                self.assertEqual(self.evaluate(rules, mode=mode,
                                              domain="browser-intake-datadoghq.com")[0], telemetry)

    def test_domestic_google_intersection_and_quic_scope(self):
        rules = simplified_document()["route"]["rules"]
        self.assertEqual(self.evaluate(rules, domain="google.cn")[0], "🇨🇳 China")
        self.assertEqual(self.evaluate(rules, domain="google.cn", protocol="quic", network="udp")[0], "🇨🇳 China")
        self.assertEqual(self.evaluate(rules, domain="unlisted.invalid", protocol="quic", network="udp")[0], "reject")

    def test_ipv6_tcp_guard_does_not_match_ipv4_or_udp(self):
        rules = [{"ip_version": 6, "network": "tcp", "action": "reject"},
                 {"action": "sniff"}, {"action": "route", "outbound": "proxy"}]
        self.assertEqual(self.evaluate(rules)[0], "proxy")
        self.assertEqual(self.evaluate(rules, ip_version=6)[0], "reject")
        actual, continued = self.evaluate(rules, ip_version=6, network="udp", protocol="quic")
        self.assertEqual(actual, "proxy")
        self.assertEqual(continued, ["sniff"])

    def test_ip_and_port_rules_need_matching_metadata(self):
        rules = [{"ip_cidr": "45.66.0.0/16", "action": "route", "outbound": "direct"},
                 {"port": 853, "action": "reject"}]
        self.assertEqual(self.evaluate(rules)[0], "fallback")
        self.assertEqual(self.evaluate(rules, destination_ip="8.8.8.8")[0], "fallback")
        self.assertEqual(self.evaluate(rules, destination_ip="45.66.1.2")[0], "direct")
        self.assertEqual(self.evaluate(rules, port=853)[0], "reject")

    def test_domain_and_ip_conditions_share_an_or_address_group(self):
        rules = [{"domain": "api.openai.com", "ip_cidr": "45.66.0.0/16",
                  "action": "route", "outbound": "proxy"}]
        self.assertEqual(self.evaluate(rules, destination_ip="8.8.8.8")[0], "proxy")
        self.assertEqual(self.evaluate(rules, domain="other.invalid", destination_ip="45.66.1.2")[0], "proxy")
        self.assertEqual(self.evaluate(rules, domain="other.invalid", destination_ip="8.8.8.8")[0], "fallback")

    def test_complex_ruleset_group_merge_is_reported_as_unsupported(self):
        rules = [{"rule_set": "geosite-openai", "domain": "other.invalid",
                  "action": "route", "outbound": "proxy"}]
        with self.assertRaisesRegex(probes.ProbeUnsupported, "mixed rule-set"):
            self.evaluate(rules)
        rules[0]["clash_mode"] = "global"
        self.assertEqual(self.evaluate(rules)[0], "fallback")

    def test_resolve_is_nonterminal_but_requires_known_result(self):
        rules = [{"type": "logical", "mode": "or", "rules": [
            {"domain_suffix": "ts.net"}, {"domain_regex": "^[^.]+$"}], "action": "resolve"},
            {"ip_cidr": "100.64.0.0/10", "action": "route", "outbound": "tailscale-direct"}]
        actual, continued = self.evaluate(rules, domain="peer.ts.net", destination_ip="100.64.1.1")
        self.assertEqual((actual, continued), ("tailscale-direct", ["resolve"]))
        with self.assertRaisesRegex(probes.ProbeUnsupported, "resolve action"):
            self.evaluate(rules, domain="peer.ts.net")

    def test_unknown_matching_condition_fails_instead_of_passing(self):
        rule = {"process_name": "browser", "action": "route", "outbound": "proxy"}
        with self.assertRaisesRegex(probes.ProbeUnsupported, "process_name"):
            self.evaluate([rule])
        rule["protocol"] = "quic"
        self.assertEqual(self.evaluate([rule])[0], "fallback")

    def test_geoip_set_does_not_match_a_domain_only_probe(self):
        with patch.object(probes, "rule_set_match", return_value=True) as match:
            self.assertFalse(probes.route_rule_set_match(Path("sing-box"), {"geoip-cn": Path("cn.srs")},
                                                        "geoip-cn", "example.com"))
            match.assert_not_called()
            self.assertTrue(probes.route_rule_set_match(Path("sing-box"), {"geoip-cn": Path("cn.srs")},
                                                       "geoip-cn", "example.com", destination_ip="1.2.3.4"))
            match.assert_called_once_with(Path("sing-box"), Path("cn.srs"), "1.2.3.4")

    def test_inbound_scope_prevents_unrelated_lan_acl_match(self):
        rules = [{"type": "logical", "mode": "and", "rules": [
            {"inbound": ["lan-mixed"]},
            {"source_ip_cidr": ["192.168.31.0/24"], "invert": True}], "action": "reject"}]
        self.assertEqual(self.evaluate(rules)[0], "fallback")
        self.assertEqual(self.evaluate(rules, inbound="lan-mixed", source_ip="192.168.31.2")[0], "fallback")
        self.assertEqual(self.evaluate(rules, inbound="lan-mixed", source_ip="8.8.8.8")[0], "reject")

    def test_missing_ruleset_is_an_error_row(self):
        document = {"route": {"rules": [{"rule_set": "geosite-openai", "action": "route", "outbound": "🤖 AI"}]}}
        rows = probes.route_probe(document, Path("unused-cli"), {},
                                  scenarios=[{"domain": "api.openai.com", "expected": "🤖 AI"}])
        self.assertIsNone(rows[0]["actual"])
        self.assertIn("unavailable", rows[0]["error"])


if __name__ == "__main__":
    unittest.main()
