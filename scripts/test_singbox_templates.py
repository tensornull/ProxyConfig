#!/usr/bin/env python3
"""Static, rule-set, and optional network probes for sing-box templates.

This tool deliberately reports counts and rule tags only.  It never reads a
provider URL or prints outbound node bodies.  Downloaded rule-sets, stripped
sing-box check inputs, and a compact JSON report are written below
``sing-box/.tmp/template-tests/<run>`` by default.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import platform
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable

if __package__:
    from . import build_singbox_templates as template_builder
    from .validate_singbox_subscription import REQUIRED_SERVICE_RULESETS, check_simplified_policy
else:
    import build_singbox_templates as template_builder
    from validate_singbox_subscription import REQUIRED_SERVICE_RULESETS, check_simplified_policy

ADS_RULE_SET = template_builder.ADS_RULE_SET
ADS_RULE_SET_URL = template_builder.ADS_RULE_SET_URL
ALLOWED_DOMAIN_VALUES = template_builder.ALLOWED_DOMAIN_VALUES
APP_DOMAIN_MARKERS = template_builder.APP_DOMAIN_MARKERS
DOMAIN_KEYS = template_builder.DOMAIN_KEYS
FAKEIP_INET4_RANGE = template_builder.FAKEIP_INET4_RANGE
FAKEIP_INET6_RANGE = template_builder.FAKEIP_INET6_RANGE
FAKEIP_QUERY_TYPES = template_builder.FAKEIP_QUERY_TYPES
FAKEIP_SERVER_TAG = template_builder.FAKEIP_SERVER_TAG
PROCESS_KEYS = template_builder.PROCESS_KEYS
as_list = template_builder.as_list
is_handwritten_app_or_ad_rule = template_builder.is_handwritten_app_or_ad_rule
load_json = template_builder.load_json


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATES_DIR = REPO_ROOT / "sing-box"
TEST_ROOT = REPO_ROOT / "sing-box" / ".tmp" / "template-tests"
WARNING_RE = re.compile(r"deprecated|legacy|warning|warn", re.IGNORECASE)
COUNTRY_TAGS = (
    "🇭🇰 Hong Kong",
    "🇯🇵 Japan",
    "🇹🇼 Taiwan",
    "🇸🇬 Singapore",
    "🇺🇸 America",
)
CANONICAL_TEMPLATES = {
    "country-auto.json",
    "country-select.json",
    "country-select-macos.json",
    "country-select-ios.json",
}
RULESET_PROBES = (
    ("geosite-cn", "login.weixin.qq.com", True),
    ("geosite-cn", "taobao.com", True),
    ("geosite-cn", "google.com", False),
    ("geosite-geolocation-!cn", "google.com", True),
    (ADS_RULE_SET, "ad.ozone.ru", True),
    (ADS_RULE_SET, "taobao.com", False),
    ("geosite-steam", "store.steampowered.com", True),
    ("geosite-openai", "api.openai.com", True),
    ("geosite-openai", "browser-intake-datadoghq.com", True),
    (ADS_RULE_SET, "browser-intake-datadoghq.com", True),
    ("geosite-anthropic", "api.anthropic.com", True),
    ("geosite-google-gemini", "gemini.google.com", True),
    ("geosite-google-gemini", "generativelanguage.googleapis.com", True),
    ("geosite-google", "www.google.com", True),
    ("geosite-cn", "google.cn", True),
    ("geosite-google", "google.cn", True),
    ("geosite-cn", "cn.bing.com", True),
    ("geosite-microsoft", "cn.bing.com", True),
    ("geosite-cn", "www.apple.com.cn", True),
    ("geosite-apple", "www.apple.com.cn", True),
    ("geosite-cn", "www.bilibili.com", True),
    ("geosite-bilibili", "www.bilibili.com", True),
    ("geoip-cn", "223.5.5.5", True),
)
ROUTE_PROBES = (
    ("login.weixin.qq.com", "🇨🇳 China"),
    ("taobao.com", "🇨🇳 China"),
    ("google.com", "🛩️ NodeSelected"),
    ("api.openai.com", "🤖 AI"),
    ("api.anthropic.com", "🤖 AI"),
    ("browser-intake-datadoghq.com", "🤖 AI"),
    ("gemini.google.com", "🤖 AI"),
    ("generativelanguage.googleapis.com", "🤖 AI"),
    ("google.cn", "🇨🇳 China"),
    ("cn.bing.com", "🇨🇳 China"),
    ("www.apple.com.cn", "🇨🇳 China"),
    ("www.bilibili.com", "🇨🇳 China"),
    ("www.microsoft.com", "🛩️ NodeSelected"),
    ("www.apple.com", "direct"),
    ("github.com", "🛩️ NodeSelected"),
    ("github.githubassets.com", "🛩️ NodeSelected"),
    ("store.steampowered.com", "🎮 Other"),
    ("ad.ozone.ru", "🌱 Purification"),
)
MODE_PROBES = (
    ("rule", "default", "😮‍💨 Final"),
    ("direct", "clash_mode=direct", "direct"),
    ("global", "clash_mode=global", "🛩️ NodeSelected"),
)
DNS_PROBES = (
    "login.weixin.qq.com",
    "taobao.com",
    "google.com",
    "api.openai.com",
)


class CheckResult:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.stats: dict[str, Any] = {}

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def walk_objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def string_values(value: Any) -> Iterable[str]:
    for item in as_list(value):
        if isinstance(item, str):
            yield item


def tags_in_rules(rules: Any) -> set[str]:
    tags: set[str] = set()
    if not isinstance(rules, list):
        return tags
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for value in as_list(rule.get("rule_set")):
            if isinstance(value, str):
                tags.add(value)
    return tags


def outbound_refs(rule: dict[str, Any]) -> Iterable[str]:
    for value in as_list(rule.get("outbound")):
        if isinstance(value, str):
            yield value


def find_sing_box(explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_path = os.environ.get("SING_BOX_BIN")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(
        REPO_ROOT
        / "sing-box"
        / ".tmp"
        / "tools"
        / "sing-box-1.14.2-darwin-arm64"
        / "sing-box"
    )
    path_candidate = shutil.which("sing-box")
    if path_candidate:
        candidates.append(Path(path_candidate))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def strip_filters(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_filters(child)
            for key, child in value.items()
            if key != "filter"
        }
    if isinstance(value, list):
        return [strip_filters(child) for child in value]
    return value


def check_selector_references(
    label: str, doc: dict[str, Any], result: CheckResult
) -> None:
    outbounds = doc.get("outbounds") or []
    tags = {
        item.get("tag")
        for item in outbounds
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    if len(tags) != len(outbounds):
        result.fail(f"{label}: duplicate or untagged outbound entries")
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        if outbound.get("type") not in {"selector", "urltest"}:
            continue
        owner = outbound.get("tag", "<untagged>")
        members = outbound.get("outbounds") or []
        if not isinstance(members, list):
            result.fail(f"{label}: {owner}: outbounds must be a list")
            continue
        for member in members:
            if not isinstance(member, str):
                result.fail(f"{label}: {owner}: non-string outbound member")
            elif not (member.startswith("{") and member.endswith("}")) and member not in tags:
                result.fail(f"{label}: {owner}: missing outbound {member}")
        default = outbound.get("default")
        if default is not None and (
            default not in members or default not in tags
        ):
            result.fail(f"{label}: {owner}: invalid default outbound")
    final = (doc.get("route") or {}).get("final")
    if final and final not in tags:
        result.fail(f"{label}: route.final references missing outbound")


def check_dns_references(
    label: str, doc: dict[str, Any], result: CheckResult
) -> None:
    dns = doc.get("dns") or {}
    servers = {
        item.get("tag")
        for item in dns.get("servers", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    final = dns.get("final")
    if final and final not in servers:
        result.fail(f"{label}: dns.final references missing server")
    for rule in dns.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        server = rule.get("server")
        if server and server not in servers:
            result.fail(f"{label}: DNS rule references missing server {server}")
        if "strategy" in rule:
            result.fail(f"{label}: DNS rule uses deprecated strategy field")


def first_index(rules: list[Any], predicate) -> int | None:
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and predicate(rule):
            return index
    return None


def check_route_references(
    label: str, doc: dict[str, Any], result: CheckResult
) -> None:
    route = doc.get("route") or {}
    rules = route.get("rules") or []
    outbounds = {
        item.get("tag")
        for item in doc.get("outbounds", []) or []
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    rule_sets = {
        item.get("tag")
        for item in route.get("rule_set", []) or []
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        refs = list(outbound_refs(rule))
        if refs and rule.get("action") != "route":
            result.fail(f"{label}: route rule {index} with outbound lacks action=route")
        for outbound in refs:
            if outbound not in outbounds:
                result.fail(f"{label}: route rule {index} missing outbound {outbound}")
        for tag in string_values(rule.get("rule_set")):
            if tag not in rule_sets:
                result.fail(f"{label}: route rule {index} missing rule-set {tag}")

    dns_rule_sets = tags_in_rules((doc.get("dns") or {}).get("rules"))
    for tag in dns_rule_sets:
        if tag not in rule_sets:
            result.fail(f"{label}: DNS rule missing rule-set {tag}")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if (
            rule.get("action") == "reject"
            and rule.get("network") == "udp"
            and 443 in as_list(rule.get("port"))
        ):
            result.fail(f"{label}: global UDP/443 reject present")

    cn_index = first_index(
        rules,
        lambda rule: "geosite-cn" in as_list(rule.get("rule_set")),
    )
    ads_index = first_index(
        rules,
        lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set"))
        and rule.get("action") == "route"
        and rule.get("outbound") == "🌱 Purification",
    )
    if ads_index is None:
        result.fail(f"{label}: route Purification rule missing")
    elif cn_index is not None and ads_index >= cn_index:
        result.fail(f"{label}: route Purification rule must precede geosite-cn")
    direct_index = first_index(
        rules,
        lambda rule: rule.get("clash_mode") == "direct",
    )
    global_index = first_index(
        rules,
        lambda rule: rule.get("clash_mode") == "global"
        and "rule_set" not in rule,
    )
    if direct_index is None or not (
        rules[direct_index].get("action") == "route"
        and rules[direct_index].get("outbound") == "direct"
    ):
        result.fail(f"{label}: clash_mode=direct route rule missing")
    if global_index is None or not (
        rules[global_index].get("action") == "route"
        and rules[global_index].get("outbound") == "🛩️ NodeSelected"
    ):
        result.fail(f"{label}: clash_mode=global route rule missing")
    if ads_index is not None and any(
        ads_index >= index
        for index in (direct_index, global_index)
        if index is not None
    ):
        result.fail(f"{label}: route Purification rule must precede direct/global mode rules")
    quic_allow = first_index(
        rules,
        lambda rule: rule.get("protocol") == "quic"
        and "geosite-cn" in as_list(rule.get("rule_set")),
    )
    quic_reject = first_index(
        rules,
        lambda rule: rule.get("protocol") == "quic"
        and rule.get("action") == "reject"
        and not rule.get("rule_set"),
    )
    if quic_allow is None or quic_reject is None or quic_allow >= quic_reject:
        result.fail(f"{label}: domestic QUIC allow must precede generic reject")
    for rule_set_name in ("geosite-github", "geosite-geolocation-!cn"):
        route_index = first_index(
            rules,
            lambda rule, name=rule_set_name: name in as_list(rule.get("rule_set"))
            and rule.get("action") == "route",
        )
        if route_index is not None and quic_reject is not None and quic_reject <= route_index:
            result.fail(
                f"{label}: generic QUIC reject must follow {rule_set_name} routing"
            )


def check_handwritten_rules(
    label: str, doc: dict[str, Any], result: CheckResult
) -> None:
    for obj in walk_objects(doc):
        if PROCESS_KEYS.intersection(obj):
            result.fail(f"{label}: process/package rule remains")
    for scope in ((doc.get("dns") or {}).get("rules", []), (doc.get("route") or {}).get("rules", [])):
        for rule in scope or []:
            if not isinstance(rule, dict) or "rule_set" in rule:
                continue
            if is_handwritten_app_or_ad_rule(rule):
                # User infrastructure exceptions are explicitly allowed.
                values = {
                    value.lower().strip(".")
                    for key in DOMAIN_KEYS
                    for value in string_values(rule.get(key))
                }
                if values & ALLOWED_DOMAIN_VALUES:
                    continue
                result.fail(f"{label}: handwritten app/ad domain rule remains")
    route_sets = (doc.get("route") or {}).get("rule_set", []) or []
    ads = next(
        (item for item in route_sets if isinstance(item, dict) and item.get("tag") == ADS_RULE_SET),
        None,
    )
    if not isinstance(ads, dict) or ads.get("url") != ADS_RULE_SET_URL:
        result.fail(f"{label}: remote {ADS_RULE_SET} definition missing or changed")


def check_ipv6_track(label: str, doc: dict[str, Any], result: CheckResult) -> None:
    path = Path(label)
    stem = path.stem
    if stem.endswith("-v6"):
        variant = "v6"
    elif stem.endswith("-v4"):
        variant = "v4"
    elif path.name in CANONICAL_TEMPLATES:
        # The unsuffixed entry points are synchronized IPv6-preferred aliases;
        # explicit -v4 files remain available as opt-in fallbacks.
        variant = "v6"
    else:
        variant = None
    if variant is None:
        result.warn(f"{label}: skipped track-specific checks for unsuffixed template")
        return
    dns = doc.get("dns") or {}
    route = doc.get("route") or {}
    rules = route.get("rules") or []
    if variant == "v4":
        if dns.get("strategy") != "ipv4_only":
            result.fail(f"{label}: v4 DNS strategy is not ipv4_only")
        if (route.get("default_domain_resolver") or {}).get("strategy") != "prefer_ipv4":
            result.fail(f"{label}: v4 resolver strategy is not prefer_ipv4")
        sniff_index = first_index(rules, lambda rule: rule.get("action") == "sniff")
        ipv6_reject_index = first_index(
            rules,
            lambda rule: rule.get("ip_version") == 6
            and rule.get("network") == "tcp"
            and rule.get("action") == "reject"
            and rule.get("no_drop") is True,
        )
        if ipv6_reject_index is None or (
            sniff_index is not None and ipv6_reject_index >= sniff_index
        ):
            result.fail(f"{label}: v4 pre-sniff IPv6 TCP reject missing")
    else:
        if dns.get("strategy") != "prefer_ipv6":
            result.fail(f"{label}: v6 DNS strategy is not prefer_ipv6")
        if (route.get("default_domain_resolver") or {}).get("strategy") != "prefer_ipv6":
            result.fail(f"{label}: v6 resolver strategy is not prefer_ipv6")
        sniff_index = first_index(rules, lambda rule: rule.get("action") == "sniff")
        if any(
            rule.get("ip_version") == 6
            and rule.get("network") == "tcp"
            and rule.get("action") == "reject"
            for rule in rules[: sniff_index if sniff_index is not None else len(rules)]
        ):
            result.fail(f"{label}: v6 still has a pre-sniff IPv6 TCP reject")

    tun_inbounds = [
        inbound
        for inbound in doc.get("inbounds", []) or []
        if isinstance(inbound, dict) and inbound.get("type") == "tun"
    ]
    if not any(
        any(":" in str(address) for address in as_list(inbound.get("address")))
        and "fc00::/7" in as_list(inbound.get("route_exclude_address"))
        for inbound in tun_inbounds
    ):
        result.fail(f"{label}: IPv6 TUN prefix/private exclusion missing")


def check_fakeip(label: str, doc: dict[str, Any], result: CheckResult) -> None:
    """Require the domain-preserving TUN path on every shipped track."""

    dns = doc.get("dns") or {}
    servers = dns.get("servers") or []
    fakeip = next(
        (
            server
            for server in servers
            if isinstance(server, dict) and server.get("tag") == FAKEIP_SERVER_TAG
        ),
        None,
    )
    if not isinstance(fakeip, dict):
        result.fail(f"{label}: fakeip DNS server missing")
    else:
        if fakeip.get("type") != "fakeip":
            result.fail(f"{label}: fakeip DNS server type is not fakeip")
        if fakeip.get("inet4_range") != FAKEIP_INET4_RANGE:
            result.fail(f"{label}: fakeip IPv4 range changed")
        if fakeip.get("inet6_range") != FAKEIP_INET6_RANGE:
            result.fail(f"{label}: fakeip IPv6 range changed")
    if dns.get("reverse_mapping") is not True:
        result.fail(f"{label}: DNS reverse_mapping must be enabled")
    fake_rule = next(
        (
            rule
            for rule in dns.get("rules", []) or []
            if isinstance(rule, dict)
            and rule.get("server") == FAKEIP_SERVER_TAG
            and set(as_list(rule.get("query_type"))) == set(FAKEIP_QUERY_TYPES)
            and set(rule) <= {"query_type", "server", "action"}
            and rule.get("action", "route") == "route"
        ),
        None,
    )
    if fake_rule is None:
        result.fail(f"{label}: A/AAAA fakeip DNS rule missing")
    else:
        dns_rules = [rule for rule in dns.get("rules", []) or [] if isinstance(rule, dict)]
        fake_index = dns_rules.index(fake_rule)
        real_dns_indices = [
            index
            for index, rule in enumerate(dns_rules)
            if "geosite-cn" in as_list(rule.get("rule_set"))
            or rule.get("clash_mode") == "direct"
        ]
        if real_dns_indices and fake_index <= max(real_dns_indices):
            result.fail(
                f"{label}: FakeIP A/AAAA rule must follow domestic/direct DNS rules"
            )
        proxy_dns_indices = [
            index
            for index, rule in enumerate(dns_rules)
            if "geosite-geolocation-!cn" in as_list(rule.get("rule_set"))
            or (rule.get("clash_mode") == "global" and "rule_set" not in rule)
        ]
        if proxy_dns_indices and fake_index >= min(proxy_dns_indices):
            result.fail(
                f"{label}: FakeIP A/AAAA rule must precede global/foreign DNS rules"
            )
    cache = (doc.get("experimental") or {}).get("cache_file") or {}
    if cache.get("enabled") is not True or cache.get("store_fakeip") is not True:
        result.fail(f"{label}: persistent fakeip cache is not enabled")
    route_rules = (doc.get("route") or {}).get("rules") or []
    if any(
        isinstance(rule, dict)
        and rule.get("action") == "resolve"
        and set(rule) <= {"action", "strategy"}
        for rule in route_rules
    ):
        result.fail(
            f"{label}: unconditional route.resolve would replace the proxy domain with a local IP"
        )


def check_document(label: str, doc: dict[str, Any]) -> CheckResult:
    result = CheckResult()
    route = doc.get("route") or {}
    route_sets = route.get("rule_set") or []
    tags = [
        item.get("tag")
        for item in route_sets
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    ]
    if len(tags) != len(set(tags)):
        result.fail(f"{label}: duplicate route rule-set tags")
    missing_services = sorted(set(REQUIRED_SERVICE_RULESETS) - set(tags))
    if missing_services:
        result.fail(f"{label}: missing service rule-sets: {', '.join(missing_services)}")

    dns_rules = (doc.get("dns") or {}).get("rules") or []
    dns_ads_index = first_index(
        dns_rules,
        lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set"))
        and rule.get("server") == "fakeip",
    )
    dns_cn_index = first_index(
        dns_rules,
        lambda rule: "geosite-cn" in as_list(rule.get("rule_set")),
    )
    if dns_ads_index is None:
        result.fail(f"{label}: DNS ad FakeIP rule missing")
    elif dns_cn_index is not None and dns_ads_index >= dns_cn_index:
        result.fail(f"{label}: DNS ad FakeIP rule must precede geosite-cn")

    check_selector_references(label, doc, result)
    check_dns_references(label, doc, result)
    check_route_references(label, doc, result)
    check_handwritten_rules(label, doc, result)
    check_ipv6_track(label, doc, result)
    check_fakeip(label, doc, result)
    result.failures.extend(check_simplified_policy(
        label, doc, allow_placeholders=True, require_real_nodes=False,
    ))

    outbounds = doc.get("outbounds") or []
    tags_out = {
        item.get("tag")
        for item in outbounds
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    china = next(
        (item for item in outbounds if isinstance(item, dict) and item.get("tag") == "🇨🇳 China"),
        None,
    )
    if not isinstance(china, dict):
        result.fail(f"{label}: China selector missing")
    else:
        members = china.get("outbounds") or []
        if china.get("default") != "direct" or not {"direct", "🛩️ NodeSelected"}.issubset(members):
            result.fail(f"{label}: China selector must keep direct default and NodeSelected")
    steam = next(
        (item for item in outbounds if isinstance(item, dict) and item.get("tag") == "🎮 Other"),
        None,
    )
    if not isinstance(steam, dict) or steam.get("default") != "🛩️ NodeSelected":
        result.fail(f"{label}: Steam selector/default missing")
    elif "🇯🇵 Japan" in (steam.get("outbounds") or []):
        result.fail(f"{label}: Steam selector unexpectedly includes Japan")
    purification = next(
        (
            item
            for item in outbounds
            if isinstance(item, dict) and item.get("tag") == "🌱 Purification"
        ),
        None,
    )
    if not isinstance(purification, dict) or purification.get("type") != "selector":
        result.fail(f"{label}: Purification selector missing")
    else:
        members = purification.get("outbounds") or []
        if purification.get("default") != "direct" or not {
            "direct",
            "reject",
            "🛩️ NodeSelected",
        }.issubset(members):
            result.fail(
                f"{label}: Purification selector must default to direct and expose "
                "reject/NodeSelected"
            )
    result.stats = {
        "outbound_count": len(outbounds),
        "rule_set_count": len(tags),
        "route_rule_count": len(route.get("rules") or []),
        "dns_rule_count": len(dns_rules),
        "track": Path(label).stem.rsplit("-", 1)[-1],
    }
    return result


class Redirect308Handler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(
            req, fp, 307 if code == 308 else code, msg, headers, newurl
        )

    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(Redirect308Handler())


def download_rule_sets(
    docs: list[dict[str, Any]], run_dir: Path, result: CheckResult
) -> dict[str, Path]:
    definitions: dict[str, dict[str, Any]] = {}
    for doc in docs:
        for item in (doc.get("route") or {}).get("rule_set", []) or []:
            if isinstance(item, dict) and isinstance(item.get("tag"), str):
                definitions.setdefault(item["tag"], item)
    rule_dir = run_dir / "rule-sets"
    rule_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    statuses: list[dict[str, Any]] = []
    client = opener()
    for tag, item in definitions.items():
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            result.fail(f"remote rule-set {tag} has no HTTP URL")
            continue
        path = rule_dir / f"{tag}.srs"
        status: dict[str, Any] = {"tag": tag}
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ProxyConfig-template-tests/1.0"},
            )
            with client.open(request, timeout=30) as response:
                body = response.read()
                status["http_status"] = response.status
            if not body:
                raise OSError("empty response")
            path.write_bytes(body)
            paths[tag] = path
            status["bytes"] = len(body)
        except Exception as exc:  # noqa: BLE001 - report network failures compactly
            status["error"] = type(exc).__name__
            result.fail(f"remote rule-set download failed: {tag}")
        statuses.append(status)
    (run_dir / "remote-rule-set-status.json").write_text(
        json.dumps(statuses, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return paths


def rule_set_match(sing_box: Path, path: Path, domain: str) -> bool:
    proc = subprocess.run(
        [str(sing_box), "rule-set", "match", "--format", "binary", str(path), domain],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("rule-set match failed")
    return "match rules." in (proc.stdout + proc.stderr)


def run_rule_set_probes(
    sing_box: Path | None,
    docs: list[dict[str, Any]],
    paths: dict[str, Path],
    result: CheckResult,
) -> list[dict[str, Any]]:
    if sing_box is None:
        result.warn("rule-set probes skipped: sing-box CLI not found")
        return []
    rows: list[dict[str, Any]] = []
    for tag, domain, expected in RULESET_PROBES:
        path = paths.get(tag)
        if path is None:
            result.fail(f"rule-set probe unavailable: {tag}")
            continue
        try:
            matched = rule_set_match(sing_box, path, domain)
        except RuntimeError:
            result.fail(f"rule-set probe command failed: {tag}")
            continue
        row = {"tag": tag, "domain": domain, "matched": matched, "expected": expected}
        rows.append(row)
        if matched != expected:
            result.fail(f"rule-set probe mismatch: {tag} / {domain}")
    return rows


def route_rule_set_match(
    sing_box: Path, rule_paths: dict[str, Path], tag: str, domain: str,
    *, destination_ip: str | None = None,
) -> bool:
    path = rule_paths.get(tag)
    if path is None:
        raise ProbeUnsupported("rule-set is unavailable")
    if tag.startswith("geoip-"):
        return bool(destination_ip) and rule_set_match(sing_box, path, destination_ip)
    if tag.startswith("geosite-"):
        return bool(domain) and rule_set_match(sing_box, path, domain)
    raise ProbeUnsupported("rule-set address scope is unknown")


class ProbeUnsupported(ValueError):
    """A static probe cannot decide a rule from the supplied packet metadata."""


def _route_rule_match(
    rule: dict[str, Any], context: dict[str, Any],
    match_rule_set: Callable[[str, dict[str, Any]], bool],
) -> tuple[bool | None, set[str]]:
    """Return unknown instead of silently matching unsupported conditions."""
    unsupported: set[str] = set()
    if rule.get("type") == "logical":
        children = rule.get("rules")
        mode = rule.get("mode")
        if not isinstance(children, list) or not children or mode not in {"and", "or"}:
            return None, {"invalid logical rule"}
        matches = [_route_rule_match(child, context, match_rule_set)
                   if isinstance(child, dict) else (None, {"invalid child rule"})
                   for child in children]
        values = [value for value, _ in matches]
        unsupported.update(problem for _, problems in matches for problem in problems)
        if mode == "and":
            matched = False if False in values else (None if None in values else True)
        else:
            matched = True if True in values else (None if None in values else False)
        supported = {"type", "mode", "rules"}
    else:
        checks: list[bool | None] = []
        address_checks: list[bool | None] = []
        supported = {
            "type", "clash_mode", "protocol", "network", "ip_version", "port",
            "port_range", "inbound", "source_port", "source_port_range",
            "ip_cidr", "ip_is_private", "source_ip_cidr", "source_ip_is_private",
            "domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set",
        }
        for key, context_key in (
            ("clash_mode", "mode"), ("protocol", "protocol"), ("network", "network"),
            ("ip_version", "ip_version"), ("inbound", "inbound"),
        ):
            if key in rule:
                checks.append(context.get(context_key) in as_list(rule[key]))
        scope_checks = list(checks)
        mixed_rule_set = "rule_set" in rule and bool(set(rule) & {
            "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr",
            "ip_is_private", "source_ip_cidr", "source_ip_is_private", "port", "port_range",
            "source_port", "source_port_range",
        })
        for key, range_key in (("port", "port_range"), ("source_port", "source_port_range")):
            if key not in rule and range_key not in rule:
                continue
            port = context.get(key)
            if port is None:
                checks.append(None)
                unsupported.add("missing " + key)
                continue
            match = port in as_list(rule.get(key))
            for value in as_list(rule.get(range_key)):
                try:
                    start, end = str(value).split(":", 1)
                    match |= int(start or 0) <= port <= int(end or 65535)
                except ValueError:
                    unsupported.add("invalid port range")
                    checks.append(None)
            checks.append(match)
        for prefix, context_key in (("", "destination_ip"), ("source_", "source_ip")):
            cidr_key, private_key = prefix + "ip_cidr", prefix + "ip_is_private"
            if cidr_key not in rule and private_key not in rule:
                continue
            address = context.get(context_key)
            if address is None:
                # Domain-only probes carry no resolved destination address.
                if prefix:
                    checks.append(None)
                    unsupported.add("missing source IP")
                else:
                    address_checks.append(False)
                continue
            ip = ipaddress.ip_address(address)
            match = rule.get(private_key) is True and (not ip.is_global or ip.is_multicast)
            try:
                match |= any(ip in ipaddress.ip_network(cidr, strict=False)
                             for cidr in as_list(rule.get(cidr_key)))
            except ValueError:
                unsupported.add("invalid IP prefix")
                checks.append(None)
            (checks if prefix else address_checks).append(match)
        domains: list[bool] = []
        domain = context.get("domain", "").lower().rstrip(".")
        for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            if key not in rule:
                continue
            values = list(string_values(rule[key]))
            if key == "domain":
                domains.append(domain in [value.lower().rstrip(".") for value in values])
            elif key == "domain_suffix":
                domains.append(any(domain == value.lower().strip(".")
                                   or domain.endswith("." + value.lower().strip("."))
                                   for value in values))
            elif key == "domain_keyword":
                domains.append(any(value.lower() in domain for value in values))
            else:
                try:
                    domains.append(any(re.search(value, domain) is not None for value in values))
                except re.error:
                    unsupported.add("invalid domain regexp")
                    checks.append(None)
        if domains:
            address_checks.append(any(domains))
        if mixed_rule_set:
            # Core merges rule-set address/port groups with outer conditions.
            # The CLI's standalone matcher cannot reconstruct that merge.
            checks = scope_checks + [None]
            unsupported.add("mixed rule-set address/port conditions")
        elif address_checks:
            checks.append(True if True in address_checks else
                          (None if None in address_checks else False))
        # Cheap scope mismatches also make an unknown condition irrelevant.
        if False not in checks and "rule_set" in rule and not mixed_rule_set:
            checks.append(any(match_rule_set(tag, context)
                              for tag in string_values(rule["rule_set"])))
        matched = False if False in checks else (None if None in checks else True)
    action_fields = {
        "action", "outbound", "invert", "no_drop", "method", "sniffer", "timeout",
        "strategy", "udp_disable_domain_unmapping", "udp_connect", "udp_timeout",
    }
    unsupported.update(set(rule) - supported - action_fields)
    if matched is not False and unsupported:
        matched = None
    if matched is not None and rule.get("invert"):
        matched = not matched
    return matched, unsupported


def evaluate_route(
    doc: dict[str, Any], context: dict[str, Any],
    match_rule_set: Callable[[str, dict[str, Any]], bool],
) -> tuple[str | None, list[str]]:
    """Evaluate known packet metadata; this does not run DNS or a proxy core."""
    continued: list[str] = []
    for rule in (doc.get("route") or {}).get("rules", []):
        if not isinstance(rule, dict):
            raise ProbeUnsupported("invalid route rule")
        matched, unsupported = _route_rule_match(rule, context, match_rule_set)
        if matched is None:
            raise ProbeUnsupported("unsupported route condition: " + ", ".join(sorted(unsupported)))
        if not matched:
            continue
        action = rule.get("action", "route")
        if action in {"sniff", "route-options"}:
            continued.append(action)
            continue
        if action == "resolve":
            if not context.get("destination_ip"):
                raise ProbeUnsupported("resolve action needs an explicit destination IP")
            continued.append(action)
            continue
        if action in {"reject", "hijack-dns"}:
            return action, continued
        if action == "route" and isinstance(rule.get("outbound"), str):
            return rule["outbound"], continued
        raise ProbeUnsupported("unsupported route action")
    return (doc.get("route") or {}).get("final"), continued


def route_probe(
    doc: dict[str, Any], sing_box: Path | None, paths: dict[str, Path],
    *, scenarios: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate explicit mode/protocol/IP scopes without starting a proxy."""
    if sing_box is None:
        return []
    if scenarios is None:
        cases = [{"domain": domain, "expected": expected} for domain, expected in ROUTE_PROBES]
        for mode, target in (("direct", "direct"), ("global", "🛩️ NodeSelected")):
            for domain in ("api.openai.com", "api.anthropic.com", "gemini.google.com",
                           "google.cn", "cn.bing.com", "www.apple.com.cn", "www.bilibili.com"):
                cases.append({"domain": domain, "mode": mode, "expected": target})
            cases.append({"domain": "browser-intake-datadoghq.com", "mode": mode,
                          "expected": "🌱 Purification"})
        cases.extend([
            {"domain": "login.weixin.qq.com", "protocol": "quic", "network": "udp",
             "expected": "🇨🇳 China"},
            {"domain": "gemini.google.com", "protocol": "quic", "network": "udp",
             "expected": "🤖 AI"},
            {"domain": "unlisted.invalid", "protocol": "quic", "network": "udp",
             "expected": "reject"},
            *({"domain": "unlisted.invalid", "destination_ip": "223.5.5.5", "mode": mode,
               "expected": target} for mode, target in (
                   ("rule", "🇨🇳 China"), ("direct", "direct"), ("global", "🛩️ NodeSelected"))),
        ])
    else:
        cases = list(scenarios)
    inbound = next((item.get("tag") for item in doc.get("inbounds", [])
                    if item.get("type") == "tun"), "tun-in")
    cache: dict[tuple[str, str], bool] = {}

    def match(tag: str, context: dict[str, Any]) -> bool:
        address = context.get("destination_ip", "") if tag.startswith("geoip-") else context["domain"]
        key = (tag, address)
        if key not in cache:
            cache[key] = route_rule_set_match(sing_box, paths, tag, context["domain"],
                                             destination_ip=context.get("destination_ip"))
        return cache[key]

    rows: list[dict[str, Any]] = []
    for scenario in cases:
        row = {"domain": "", "mode": "rule", "protocol": "tls", "network": "tcp",
               "port": 443, "ip_version": 4, "inbound": inbound, **scenario}
        if row.get("destination_ip"):
            row["ip_version"] = ipaddress.ip_address(row["destination_ip"]).version
        try:
            row["actual"], row["continued_actions"] = evaluate_route(doc, row, match)
        except (ProbeUnsupported, RuntimeError, ValueError) as error:
            row["actual"] = None
            row["error"] = str(error)
        rows.append(row)
    return rows


def run_sing_box_checks(
    sing_box: Path | None,
    templates: list[tuple[Path, dict[str, Any]]],
    run_dir: Path,
    result: CheckResult,
) -> None:
    if sing_box is None:
        result.warn("sing-box check skipped: CLI not found")
        return
    stripped_dir = run_dir / "stripped"
    stripped_dir.mkdir(parents=True, exist_ok=True)
    for path, doc in templates:
        stripped = stripped_dir / path.name
        stripped.write_text(
            json.dumps(strip_filters(doc), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [str(sing_box), "check", "-c", str(stripped)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        label = path.name
        if proc.returncode != 0:
            result.fail(f"{label}: sing-box check failed")
        if WARNING_RE.search(proc.stdout):
            result.fail(f"{label}: sing-box check emitted warning/deprecated output")


def connect_https(host: str, family: socket.AddressFamily) -> str:
    infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
    last_error: Exception | None = None
    context = ssl.create_default_context()
    for info in infos:
        address = info[4]
        sock = socket.socket(info[0], info[1], info[2])
        sock.settimeout(8)
        try:
            sock.connect(address)
            with context.wrap_socket(sock, server_hostname=host) as tls:
                tls.do_handshake()
                return str(tls.getpeername()[0])
        except Exception as exc:  # noqa: BLE001 - report only pass/fail
            last_error = exc
            try:
                sock.close()
            except OSError:
                pass
    raise OSError(type(last_error).__name__ if last_error else "no address")


def run_network_probes(
    result: CheckResult,
    ipv6_hosts: list[str],
    ipv4_hosts: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family, hosts, label in (
        (socket.AF_INET6, ipv6_hosts, "ipv6"),
        (socket.AF_INET, ipv4_hosts, "ipv4"),
    ):
        for host in hosts:
            row: dict[str, Any] = {"family": label, "host": host}
            try:
                row["remote_address"] = connect_https(host, family)
                row["ok"] = True
            except Exception as exc:  # noqa: BLE001 - no network details in output
                row["ok"] = False
                row["error"] = type(exc).__name__
                result.fail(f"{label} HTTPS probe failed: {host}")
            rows.append(row)
    if sum(1 for row in rows if row["family"] == "ipv6" and row.get("ok")) < 2:
        result.fail("fewer than two real IPv6 HTTPS probes passed")
    if not any(row["family"] == "ipv4" and row.get("ok") for row in rows):
        result.fail("no IPv4 HTTPS probe passed")
    return rows


def run_dns_probes(result: CheckResult, hosts: list[str]) -> list[dict[str, Any]]:
    """Resolve representative names through the host's active resolver.

    This intentionally uses the system resolver rather than assuming that a
    particular SFM DNS listener is reachable.  The result is useful alongside
    ``scutil --dns``/Tailscale inspection and avoids printing returned address
    lists in the terminal; the report records only address-family counts.
    """
    rows: list[dict[str, Any]] = []
    for host in hosts:
        row: dict[str, Any] = {"host": host}
        try:
            answers = socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM)
            families = {
                "ipv6" if info[0] == socket.AF_INET6 else "ipv4"
                for info in answers
                if info[0] in (socket.AF_INET, socket.AF_INET6)
            }
            row["address_family_count"] = {
                "ipv4": int("ipv4" in families),
                "ipv6": int("ipv6" in families),
            }
            row["ok"] = bool(families)
            if not row["ok"]:
                result.fail(f"DNS probe returned no addresses: {host}")
        except Exception as exc:  # noqa: BLE001 - keep report non-sensitive
            row["ok"] = False
            row["error"] = type(exc).__name__
            result.fail(f"DNS probe failed: {host}")
        rows.append(row)
    return rows


def run_mode_probes(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Record the three user-facing mode labels without starting a TUN.

    Rule mode uses the configured final outbound. Direct and Global are
    represented by their explicit route rules. A live SFM run can add packet
    evidence later, but this check guarantees the labels cannot silently fall
    back to the final rule when templates are regenerated.
    """

    route = doc.get("route") or {}
    rules = route.get("rules") or []
    rows: list[dict[str, Any]] = []
    for mode, selector, expected in MODE_PROBES:
        if mode == "rule":
            actual = route.get("final")
            present = isinstance(actual, str)
        else:
            matches = [
                rule
                for rule in rules
                if isinstance(rule, dict)
                and rule.get("clash_mode") == mode
                and rule.get("action") == "route"
            ]
            actual = matches[0].get("outbound") if matches else None
            present = actual == expected
        rows.append(
            {
                "mode": mode,
                "selector": selector,
                "expected": expected,
                "actual": actual,
                "ok": present,
            }
        )
    return rows


def run_macos_environment(result: CheckResult) -> dict[str, Any]:
    """Capture routing/DNS facts relevant to TUN and Tailscale bypasses."""

    if platform.system() != "Darwin":
        return {"platform": platform.system(), "skipped": True}

    commands = {
        "dns": ["scutil", "--dns"],
        "ipv6_default_route": ["route", "-n", "get", "-inet6", "default"],
        "wifi": ["networksetup", "-getinfo", "Wi-Fi"],
        "interfaces": ["ifconfig"],
    }
    outputs: dict[str, Any] = {"platform": "Darwin"}
    for name, command in commands.items():
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
            text = proc.stdout
            # Keep the report useful without copying resolver addresses or
            # unrelated interface payloads into the terminal output.
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            outputs[name] = {
                "returncode": proc.returncode,
                "line_count": len(lines),
                "has_tun": any("utun" in line for line in lines),
                "has_tailscale_dns": any("100.100.100.100" in line for line in lines),
                "has_ipv6_default": any("gateway:" in line and ":" in line for line in lines),
                "has_ipv6_address": any("inet6 " in line for line in lines),
            }
        except (OSError, subprocess.SubprocessError) as exc:
            outputs[name] = {"error": type(exc).__name__}
            result.warn(f"macOS environment command failed: {name}")
    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--templates-dir",
        type=Path,
        default=DEFAULT_TEMPLATES_DIR,
        help="directory containing *-v4.json and *-v6.json",
    )
    parser.add_argument(
        "--template",
        action="append",
        type=Path,
        dest="templates",
        help="check explicit template path(s) instead of scanning templates-dir",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        help="diagnostic directory (default: sing-box/.tmp/template-tests/<run>)",
    )
    parser.add_argument("--sing-box", help="sing-box 1.14.2 CLI path")
    parser.add_argument(
        "--skip-sing-box", action="store_true", help="skip CLI checks"
    )
    parser.add_argument(
        "--skip-remote", action="store_true", help="skip remote rule-set downloads/matches"
    )
    parser.add_argument(
        "--network-probes",
        action="store_true",
        help="run real HTTPS probes (v6 requires two successful hosts)",
    )
    parser.add_argument(
        "--dns-probes",
        action="store_true",
        help="resolve representative names with the active system resolver",
    )
    parser.add_argument(
        "--macos-environment",
        action="store_true",
        help="record scutil/route/networksetup facts relevant to TUN and Tailscale",
    )
    parser.add_argument(
        "--dns-host",
        action="append",
        dest="dns_hosts",
        default=list(DNS_PROBES),
        help="DNS probe host (repeatable)",
    )
    parser.add_argument(
        "--ipv6-host",
        action="append",
        dest="ipv6_hosts",
        default=["ipv6.google.com", "ipv6.icanhazip.com"],
        help="IPv6 HTTPS host (repeatable)",
    )
    parser.add_argument(
        "--ipv4-host",
        action="append",
        dest="ipv4_hosts",
        default=["ipv4.icanhazip.com"],
        help="IPv4 HTTPS host (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = CheckResult()
    if args.templates:
        paths = [path if path.is_absolute() else REPO_ROOT / path for path in args.templates]
    else:
        directory = args.templates_dir if args.templates_dir.is_absolute() else REPO_ROOT / args.templates_dir
        paths = sorted(directory.glob("*-v[46].json"))
        paths.extend(
            directory / name
            for name in sorted(CANONICAL_TEMPLATES)
            if (directory / name).is_file()
        )
    if not paths:
        result.fail("no tracked templates found")
        print("template_tests_ok=false")
        print("failure=no tracked templates found")
        return 1
    documents: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        try:
            document = load_json(path)
        except Exception as exc:  # noqa: BLE001 - compact failure
            result.fail(f"{path.name}: invalid JSON")
            continue
        documents.append((path.resolve(), document))
        document_result = check_document(path.name, document)
        result.failures.extend(document_result.failures)
        result.warnings.extend(document_result.warnings)
        result.stats[path.name] = document_result.stats

    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = args.run_dir or TEST_ROOT / f"{stamp}-{os.getpid()}"
    run_dir.mkdir(parents=True, exist_ok=True)
    sing_box = None if args.skip_sing_box else find_sing_box(args.sing_box)
    if not args.skip_sing_box and sing_box is None:
        result.warn("sing-box CLI not found")
    run_sing_box_checks(sing_box, documents, run_dir, result)

    rule_paths: dict[str, Path] = {}
    rule_rows: list[dict[str, Any]] = []
    route_rows: dict[str, list[dict[str, Any]]] = {}
    mode_rows: dict[str, list[dict[str, Any]]] = {
        path.name: run_mode_probes(document) for path, document in documents
    }
    for label, rows in mode_rows.items():
        if any(not row["ok"] for row in rows):
            result.fail(f"mode probe mismatch: {label}")
    if not args.skip_remote:
        rule_paths = download_rule_sets(
            [document for _, document in documents], run_dir, result
        )
        rule_rows = run_rule_set_probes(
            sing_box,
            [document for _, document in documents],
            rule_paths,
            result,
        )
        if sing_box is not None:
            for path, document in documents:
                route_rows[path.name] = route_probe(document, sing_box, rule_paths)
                for row in route_rows[path.name]:
                    if row.get("error") or row["actual"] != row["expected"]:
                        result.fail(f"route probe mismatch: {path.name} / {row['domain']}")
    else:
        result.warn("remote rule-set checks skipped")

    network_rows: list[dict[str, Any]] = []
    if args.network_probes:
        network_rows = run_network_probes(result, args.ipv6_hosts, args.ipv4_hosts)
    dns_rows: list[dict[str, Any]] = []
    if args.dns_probes or args.network_probes:
        dns_rows = run_dns_probes(result, args.dns_hosts)
    macos_environment = (
        run_macos_environment(result) if args.macos_environment else {}
    )

    report = {
        "templates": [path.name for path, _ in documents],
        "stats": result.stats,
        "rule_set_probes": rule_rows,
        "route_probes": route_rows,
        "mode_probes": mode_rows,
        "network_probes": network_rows,
        "dns_probes": dns_rows,
        "macos_environment": macos_environment,
        "warnings": result.warnings,
        "failures": result.failures,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"run_dir={run_dir}")
    print(f"templates_checked={len(documents)}")
    print(f"remote_rule_set_probe_count={len(rule_rows)}")
    print(f"network_probe_count={len(network_rows)}")
    print(f"dns_probe_count={len(dns_rows)}")
    print(f"warnings={len(result.warnings)}")
    print(f"failures={len(result.failures)}")
    if result.failures:
        for failure in result.failures:
            print(f"failure={failure}", file=sys.stderr)
        print("template_tests_ok=false")
        return 1
    print("template_tests_ok=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
