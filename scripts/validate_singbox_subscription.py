#!/usr/bin/env python3
"""Validate local sing-box templates and the final SFM subscription output."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_DIR = REPO_ROOT / "sing-box" / ".tmp" / "validate"
RUN_DIR = VALIDATE_DIR / f"run-{os.getpid()}"
DEFAULT_TEMPLATES = [
    REPO_ROOT / "sing-box" / "country-select.json",
    REPO_ROOT / "sing-box" / "country-auto.json",
    REPO_ROOT / "sing-box" / "country-select-macos.json",
    REPO_ROOT / "sing-box" / "country-select-ios.json",
]
COUNTRY_SELECTORS = [
    "🇭🇰 Hong Kong",
    "🇯🇵 Japan",
    "🇹🇼 Taiwan",
    "🇸🇬 Singapore",
    "🇺🇸 America",
]
CONTROL_OUTBOUND_TYPES = {"selector", "urltest", "direct", "block", "dns"}
FALLBACK_ONLY_TAGS = {"Proxy", "direct"}
PLACEHOLDER_RE = re.compile(r"^\{[^{}]+\}$")
WARNING_RE = re.compile(r"deprecated|legacy|warning|warn", re.IGNORECASE)


class ValidationFailure(Exception):
    """Raised when validation finds one or more blocking failures."""


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValidationFailure(f"{path}: root JSON value is not an object")
    return data


def walk_objects(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and PLACEHOLDER_RE.match(value) is not None


def port_includes_443(value: Any) -> bool:
    if value == 443:
        return True
    if isinstance(value, list):
        return 443 in value
    return False


def check_document(
    label: str,
    doc: dict[str, Any],
    *,
    allow_placeholders: bool,
    require_real_nodes: bool,
) -> tuple[list[str], dict[str, Any]]:
    failures: list[str] = []
    outbounds = doc.get("outbounds") or []
    dns = doc.get("dns") or {}
    route = doc.get("route") or {}
    dns_rules = dns.get("rules") or []
    route_rules = route.get("rules") or []
    route_rule_sets = route.get("rule_set") or []
    dns_servers = dns.get("servers") or []

    outbound_tags = [ob.get("tag") for ob in outbounds if isinstance(ob, dict)]
    outbound_tag_set = {tag for tag in outbound_tags if isinstance(tag, str)}
    dns_server_tags = {
        server.get("tag")
        for server in dns_servers
        if isinstance(server, dict) and isinstance(server.get("tag"), str)
    }
    rule_set_tags = {
        rule_set.get("tag")
        for rule_set in route_rule_sets
        if isinstance(rule_set, dict) and isinstance(rule_set.get("tag"), str)
    }

    if len(outbound_tags) != len(outbound_tag_set):
        failures.append(f"{label}: duplicate outbound tags exist")

    if any(
        isinstance(ob, dict) and ob.get("tag") == "Proxy" and ob.get("type") == "direct"
        for ob in outbounds
    ):
        failures.append(f"{label}: direct outbound fallback tag 'Proxy' is present")

    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        if ob.get("type") not in ("selector", "urltest"):
            continue
        owner = ob.get("tag", "<untagged>")
        members = ob.get("outbounds") or []
        if not isinstance(members, list):
            failures.append(f"{label}: {owner}: outbounds is not a list")
            continue
        for ref in members:
            if allow_placeholders and is_placeholder(ref):
                continue
            if is_placeholder(ref):
                failures.append(f"{label}: {owner}: unresolved placeholder {ref}")
            elif ref not in outbound_tag_set:
                failures.append(f"{label}: {owner}: missing outbound dependency {ref}")
        default = ob.get("default")
        if default is not None:
            if default not in outbound_tag_set:
                failures.append(f"{label}: {owner}: default outbound {default} is missing")
            if default not in members:
                failures.append(f"{label}: {owner}: default outbound {default} is not a member")

    route_final = route.get("final")
    if route_final and route_final not in outbound_tag_set:
        failures.append(f"{label}: route.final outbound {route_final} is missing")

    for obj in walk_objects(route_rules):
        outbound = obj.get("outbound") if isinstance(obj, dict) else None
        if outbound and outbound not in outbound_tag_set:
            failures.append(f"{label}: route outbound {outbound} is missing")

    dns_final = dns.get("final")
    if dns_final and dns_final not in dns_server_tags:
        failures.append(f"{label}: dns.final server {dns_final} is missing")

    for obj in walk_objects(dns_rules):
        if not isinstance(obj, dict):
            continue
        server = obj.get("server")
        if server and server not in dns_server_tags:
            failures.append(f"{label}: dns server {server} is missing")
        if "strategy" in obj:
            failures.append(f"{label}: dns.rules contains deprecated strategy")

    for scope, rules in (("route", route_rules), ("dns", dns_rules)):
        for obj in walk_objects(rules):
            if not isinstance(obj, dict) or "rule_set" not in obj:
                continue
            for rule_set in as_list(obj.get("rule_set")):
                if rule_set not in rule_set_tags:
                    failures.append(f"{label}: {scope} rule_set {rule_set} is missing")

    for rule in route_rules:
        if not isinstance(rule, dict):
            continue
        if (
            rule.get("network") == "udp"
            and port_includes_443(rule.get("port"))
            and rule.get("action") == "reject"
        ):
            failures.append(f"{label}: global udp/443 reject rule is present")

    first_quic_reject = next(
        (
            index
            for index, rule in enumerate(route_rules)
            if isinstance(rule, dict)
            and rule.get("protocol") == "quic"
            and rule.get("action") == "reject"
            and "rule_set" not in rule
            and "domain" not in rule
            and "domain_suffix" not in rule
            and "process_name" not in rule
        ),
        None,
    )
    if first_quic_reject is not None:
        wechat_quic_bypass = any(
            isinstance(rule, dict)
            and rule.get("protocol") == "quic"
            and rule.get("action") != "reject"
            and (
                "WeChat" in as_list(rule.get("process_name"))
                or "weixin.qq.com" in as_list(rule.get("domain_suffix"))
                or "geosite-cn" in as_list(rule.get("rule_set"))
            )
            for rule in route_rules[:first_quic_reject]
        )
        if not wechat_quic_bypass:
            failures.append(
                f"{label}: global quic reject is missing WeChat/geosite-cn bypass"
            )

    ads_reject_before_cn = False
    saw_geosite_cn = False
    for rule in dns_rules + route_rules:
        if not isinstance(rule, dict):
            continue
        rule_sets = as_list(rule.get("rule_set"))
        if "geosite-cn" in rule_sets and rule.get("action") != "reject":
            saw_geosite_cn = True
        if "geosite-category-ads-all" in rule_sets and rule.get("action") == "reject":
            if not saw_geosite_cn:
                ads_reject_before_cn = True
    if not ads_reject_before_cn:
        failures.append(
            f"{label}: geosite-category-ads-all reject is missing or after geosite-cn"
        )

    real_proxy_nodes = [
        ob
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("type") not in CONTROL_OUTBOUND_TYPES
    ]
    proxy_direct_count = sum(
        1
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("tag") == "Proxy" and ob.get("type") == "direct"
    )
    missing_country_groups: list[str] = []
    fallback_only_groups: list[str] = []
    for country in COUNTRY_SELECTORS:
        group = next(
            (
                ob
                for ob in outbounds
                if isinstance(ob, dict) and ob.get("tag") == country
            ),
            None,
        )
        if group is None:
            missing_country_groups.append(country)
            continue
        members = [
            member
            for member in group.get("outbounds", [])
            if isinstance(member, str) and not is_placeholder(member)
        ]
        real_members = [member for member in members if member not in FALLBACK_ONLY_TAGS]
        if not members or not real_members:
            shown = "|".join(members) if members else "<empty>"
            fallback_only_groups.append(f"{country}={shown}")

    if require_real_nodes:
        if not real_proxy_nodes:
            failures.append(f"{label}: real_proxy_node_count=0")
        if missing_country_groups:
            failures.append(
                f"{label}: missing country selectors: {', '.join(missing_country_groups)}"
            )
        if fallback_only_groups:
            failures.append(
                f"{label}: country selectors have no real members: "
                + ", ".join(fallback_only_groups)
            )

    stats = {
        "outbound_count": len(outbounds),
        "real_proxy_node_count": len(real_proxy_nodes),
        "proxy_direct_count": proxy_direct_count,
        "country_fallback_only_count": len(fallback_only_groups),
    }
    return failures, stats


def strip_filters(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_filters(v) for k, v in value.items() if k != "filter"}
    if isinstance(value, list):
        return [strip_filters(item) for item in value]
    return value


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
        / "sing-box-1.14.0-alpha.39-darwin-arm64"
        / "sing-box"
    )
    path_candidate = shutil.which("sing-box")
    if path_candidate:
        candidates.append(Path(path_candidate))

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def run_sing_box_check(
    sing_box: Path | None,
    label: str,
    doc: dict[str, Any],
    output_path: Path,
) -> list[str]:
    if sing_box is None:
        return []
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(strip_filters(doc), f, indent=2, ensure_ascii=False)

    proc = subprocess.run(
        [str(sing_box), "check", "-c", str(output_path)],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    failures: list[str] = []
    if proc.returncode != 0:
        failures.append(f"{label}: sing-box check failed")
    if WARNING_RE.search(proc.stdout):
        failures.append(f"{label}: sing-box check emitted warning/deprecated output")
    return failures


def fetch_subscription(url: str, output_path: Path) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ProxyConfig-Validation/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read()
    output_path.write_bytes(body)
    return load_json(output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate sing-box templates and SFM final subscription output."
    )
    parser.add_argument(
        "--subscription-url",
        default=os.environ.get("SINGBOX_SUBSCRIPTION_URL"),
        help="Final SFM subscription URL. May also be set via SINGBOX_SUBSCRIPTION_URL.",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Only validate local templates. Do not use this before publishing sing-box changes.",
    )
    parser.add_argument(
        "--sing-box",
        help="Optional sing-box CLI path. May also be set via SING_BOX_BIN.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    sing_box = find_sing_box(args.sing_box)

    template_stats: list[str] = []
    for template_path in DEFAULT_TEMPLATES:
        doc = load_json(template_path)
        label = str(template_path.relative_to(REPO_ROOT))
        doc_failures, stats = check_document(
            label,
            doc,
            allow_placeholders=True,
            require_real_nodes=False,
        )
        failures.extend(doc_failures)
        failures.extend(
            run_sing_box_check(
                sing_box,
                label,
                doc,
                RUN_DIR / "stripped" / template_path.name,
            )
        )
        template_stats.append(
            f"{label}: outbounds={stats['outbound_count']} "
            f"proxy_direct={stats['proxy_direct_count']}"
        )

    print("local_templates_json_ok=true")
    for line in template_stats:
        print(line)

    if args.local_only:
        print("final_subscription_check=skipped_local_only")
    else:
        if not args.subscription_url:
            failures.append(
                "final subscription URL is required; pass --subscription-url or "
                "SINGBOX_SUBSCRIPTION_URL"
            )
        else:
            final_doc = fetch_subscription(
                args.subscription_url,
                RUN_DIR / "final-subscription.json",
            )
            final_failures, final_stats = check_document(
                "final-subscription",
                final_doc,
                allow_placeholders=False,
                require_real_nodes=True,
            )
            failures.extend(final_failures)
            failures.extend(
                run_sing_box_check(
                    sing_box,
                    "final-subscription",
                    final_doc,
                    RUN_DIR / "stripped" / "final-subscription.json",
                )
            )
            print(
                "final_subscription_json_ok=true "
                f"outbounds={final_stats['outbound_count']} "
                f"real_proxy_node_count={final_stats['real_proxy_node_count']} "
                f"proxy_direct={final_stats['proxy_direct_count']} "
                f"country_fallback_only={final_stats['country_fallback_only_count']}"
            )

    if sing_box is None:
        print("sing_box_check=skipped_cli_not_found")
    else:
        print("sing_box_check=enabled")

    if failures:
        print("validation_failed=true")
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    print("validation_ok=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
