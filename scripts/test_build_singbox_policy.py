#!/usr/bin/env python3
"""Regression checks for the shared template/iCloud service-policy builder."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.build_singbox_templates import (
    ADS_RULE_SET,
    AI_COUNTRY_TAGS,
    AI_RULE_SETS,
    AI_SELECTOR_TAG,
    DIRECT_SERVICE_RULE_SETS,
    PROXY_SERVICE_RULE_SETS,
    SIMPLIFIED_REMOVED_OUTBOUNDS,
    TemplateError,
    as_list,
    ensure_fakeip,
    ensure_simplified_policy,
    transform_document,
)


TEMPLATES = Path(__file__).resolve().parents[1] / "sing-box"
CANONICAL = (
    "country-auto", "country-select", "country-select-macos", "country-select-ios",
)


def load_template(stem: str = "country-select-macos") -> dict:
    return json.loads((TEMPLATES / (stem + ".json")).read_text(encoding="utf-8"))


def index_of(rules: list[dict], predicate) -> int:
    return next(index for index, rule in enumerate(rules) if predicate(rule))


def tagged(doc: dict, tag: str) -> dict:
    return next(outbound for outbound in doc["outbounds"] if outbound["tag"] == tag)


class SimplifiedPolicyTests(unittest.TestCase):
    def test_rule_mode_ai_precedes_ads_without_reordering_mode_overrides(self):
        doc = load_template()
        mode_rules = [copy.deepcopy(rule) for rule in doc["route"]["rules"]
                      if rule.get("clash_mode") in {"direct", "global"}]
        ensure_simplified_policy(doc)
        rules = doc["route"]["rules"]
        ai_index = index_of(rules, lambda rule: rule.get("outbound") == AI_SELECTOR_TAG)
        ads_index = index_of(rules, lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set")))
        ai = rules[ai_index]
        self.assertEqual(ai["clash_mode"], "rule")
        self.assertEqual(ai["rule_set"], list(AI_RULE_SETS))
        self.assertLess(ai_index, ads_index)
        self.assertLess(index_of(rules, lambda rule: rule.get("action") == "hijack-dns"), ai_index)
        self.assertEqual([rule for rule in rules
                          if rule.get("clash_mode") in {"direct", "global"}], mode_rules)
        for mode in ("direct", "global"):
            self.assertNotEqual(ai["clash_mode"], mode)

        dns_rules = doc["dns"]["rules"]
        ai_dns = [rule for rule in dns_rules if rule.get("rule_set") == list(AI_RULE_SETS)]
        self.assertEqual(len(ai_dns), 1)
        self.assertEqual(ai_dns[0]["clash_mode"], "rule")
        self.assertEqual(ai_dns[0]["query_type"], ["A", "AAAA"])
        self.assertEqual(ai_dns[0]["server"], "fakeip")
        self.assertLess(dns_rules.index(ai_dns[0]),
                        index_of(dns_rules, lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set"))))

    def test_ai_preserves_legal_default_and_removes_indirect_hong_kong_paths(self):
        for old_default, expected in (("🇸🇬 Singapore", "🇸🇬 Singapore"),
                                      ("🇺🇸 America", "🇺🇸 America"),
                                      ("direct", "🇺🇸 America"),
                                      ("🇭🇰 Hong Kong", "🇺🇸 America"),
                                      ("🛩️ NodeSelected", "🇺🇸 America")):
            with self.subTest(default=old_default):
                doc = load_template()
                tagged(doc, AI_SELECTOR_TAG)["default"] = old_default
                ensure_simplified_policy(doc)
                ai = tagged(doc, AI_SELECTOR_TAG)
                self.assertEqual(ai["outbounds"], list(AI_COUNTRY_TAGS))
                self.assertEqual(ai["default"], expected)

    def test_service_merges_and_domestic_priority_keep_steam_and_geoip_positions(self):
        doc = load_template()
        steam = copy.deepcopy(next(rule for rule in doc["route"]["rules"]
                                  if rule.get("rule_set") == "geosite-steam"))
        geoip = copy.deepcopy(next(rule for rule in doc["route"]["rules"]
                                  if "geoip-cn" in as_list(rule.get("rule_set"))
                                  and not rule.get("protocol")))
        ensure_simplified_policy(doc)
        rules = doc["route"]["rules"]
        cn_index = index_of(rules, lambda rule: rule.get("rule_set") == "geosite-cn")
        proxy_index = index_of(rules, lambda rule: set(PROXY_SERVICE_RULE_SETS)
                               .issubset(as_list(rule.get("rule_set"))))
        direct_index = index_of(rules, lambda rule: set(DIRECT_SERVICE_RULE_SETS)
                                .issubset(as_list(rule.get("rule_set"))))
        media_index = index_of(rules, lambda rule: rule.get("outbound") == "👀 ForeignMedia")
        self.assertEqual(rules[proxy_index]["outbound"], "🛩️ NodeSelected")
        self.assertEqual(rules[direct_index]["outbound"], "direct")
        self.assertLess(cn_index, proxy_index)
        self.assertLess(proxy_index, media_index)
        self.assertLess(rules.index(steam), cn_index)
        self.assertLess(media_index, rules.index(geoip))
        self.assertLess(index_of(rules, lambda rule: rule.get("clash_mode") == "global"), cn_index)
        for rule in rules:
            if "domain_keyword" in rule or ("ip_cidr" in rule and rule.get("outbound") == "direct"):
                self.assertLess(rules.index(rule), cn_index)

    def test_removed_group_references_migrate_without_touching_extensions(self):
        doc = load_template()
        # A profile can refer to a removed selector outside ordinary service
        # rules. These references must remain valid after the group removal.
        doc["outbounds"].append({
            "tag": "custom-policy", "type": "selector",
            "outbounds": ["🌐 Google", "Ⓜ️ Microsoft", "direct", "🍎 Apple"],
            "default": "🌐 Google", "interrupt_exist_connections": False,
        })
        doc["http_clients"].append({"tag": "custom-client", "detour": "Ⓜ️ Microsoft"})
        doc["experimental"]["clash_api"]["external_ui_download_detour"] = "🍎 Apple"
        doc["route"]["rules"].append({
            "domain_suffix": "custom.example", "action": "route", "outbound": "🌐 Google",
        })
        ensure_simplified_policy(doc)
        self.assertFalse(set(SIMPLIFIED_REMOVED_OUTBOUNDS)
                         & {outbound["tag"] for outbound in doc["outbounds"]})
        custom = tagged(doc, "custom-policy")
        self.assertEqual(custom["outbounds"], ["🛩️ NodeSelected", "direct"])
        self.assertEqual(custom["default"], "🛩️ NodeSelected")
        self.assertFalse(custom["interrupt_exist_connections"])
        self.assertEqual(doc["http_clients"][-1]["detour"], "🛩️ NodeSelected")
        self.assertEqual(doc["experimental"]["clash_api"]["external_ui_download_detour"], "direct")
        custom_route = next(rule for rule in doc["route"]["rules"]
                            if rule.get("domain_suffix") == "custom.example")
        self.assertEqual(custom_route["outbound"], "🛩️ NodeSelected")

    def test_public_helper_preserves_nodes_listeners_dns_and_platform_extensions(self):
        doc = load_template()
        node = {"tag": "test-node", "type": "trojan", "server": "proxy.invalid", "server_port": 443,
                "tls": {"enabled": True, "server_name": "proxy.invalid"}}
        doc["outbounds"].append(copy.deepcopy(node))
        doc["inbounds"].append({"type": "mixed", "tag": "extra-listener",
                                "listen": "127.0.0.1", "listen_port": 31234})
        doc["dns"]["rules"].insert(0, {"domain_suffix": "private.example", "server": "dns_resolver"})
        doc["route"]["rules"].insert(0, {"source_ip_cidr": "192.0.2.0/24", "action": "reject"})
        before = copy.deepcopy(doc)
        ensure_simplified_policy(doc)
        for key in ("inbounds", "log", "experimental", "http_clients"):
            self.assertEqual(doc[key], before[key])
        self.assertEqual(doc["dns"]["servers"], before["dns"]["servers"])
        for key in before["dns"]:
            if key != "rules":
                self.assertEqual(doc["dns"][key], before["dns"][key])
        self.assertEqual(tagged(doc, "test-node"), node)
        self.assertIn(before["dns"]["rules"][0], doc["dns"]["rules"])
        self.assertIn(before["route"]["rules"][0], doc["route"]["rules"])
        self.assertEqual(doc["route"]["rule_set"], before["route"]["rule_set"])
        self.assertEqual(doc["route"]["default_domain_resolver"], before["route"]["default_domain_resolver"])
        for tag in AI_COUNTRY_TAGS:
            self.assertEqual(tagged(doc, tag), tagged(before, tag))
        for rule in before["route"]["rules"]:
            if rule.get("action") in {"resolve", "reject"} or "ip_cidr" in rule or "domain_keyword" in rule:
                self.assertIn(rule, doc["route"]["rules"])

    def test_fakeip_only_deduplicates_unconditional_aaaa_rules(self):
        doc = load_template()
        scoped = {"query_type": ["A", "AAAA"], "rule_set": "geosite-openai",
                  "clash_mode": "rule", "server": "fakeip"}
        doc["dns"]["rules"].insert(0, scoped)
        doc["dns"]["rules"].append({"query_type": ["AAAA", "A"], "server": "fakeip", "action": "route"})
        ensure_fakeip(doc)
        self.assertIn(scoped, doc["dns"]["rules"])
        generic = [rule for rule in doc["dns"]["rules"]
                   if rule.get("server") == "fakeip"
                   and set(as_list(rule.get("query_type"))) == {"A", "AAAA"}
                   and set(rule) <= {"query_type", "server", "action"}]
        self.assertEqual(len(generic), 1)

    def test_policy_and_full_transform_are_idempotent_for_all_twelve_templates(self):
        for stem in CANONICAL:
            for suffix in ("", "-v4", "-v6"):
                with self.subTest(template=stem + suffix):
                    source = load_template(stem + suffix)
                    candidate = copy.deepcopy(source)
                    ensure_simplified_policy(candidate)
                    once = copy.deepcopy(candidate)
                    ensure_simplified_policy(candidate)
                    self.assertEqual(candidate, once)
                    variant = "v4" if suffix == "-v4" else "v6"
                    coexist = not stem.endswith("-ios")
                    transformed = transform_document(source, variant, tailscale_coexist=coexist)
                    self.assertEqual(transform_document(transformed, variant, tailscale_coexist=coexist),
                                     transformed)
                    canonical = transform_document(load_template(stem), variant, tailscale_coexist=coexist)
                    self.assertEqual(transformed, canonical)
                    # Country auto-testing is shared with non-AI policy. Its
                    # existing timing, tolerance, filters and membership stay.
                    for outbound in source["outbounds"]:
                        if outbound.get("type") == "urltest":
                            self.assertEqual(tagged(candidate, outbound["tag"]), outbound)

    def test_missing_ai_country_group_fails_without_partial_changes(self):
        doc = load_template()
        doc["outbounds"] = [outbound for outbound in doc["outbounds"]
                            if outbound.get("tag") != "🇺🇸 America"]
        before = copy.deepcopy(doc)
        with self.assertRaises(TemplateError):
            ensure_simplified_policy(doc)
        self.assertEqual(doc, before)


if __name__ == "__main__":
    unittest.main()
