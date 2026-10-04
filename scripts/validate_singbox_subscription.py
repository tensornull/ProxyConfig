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
TEMPLATE_VARIANT_RE = re.compile(r"-(v4|v6)$", re.IGNORECASE)
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
ADS_RULE_SET = "geosite-category-ads-all"
REQUIRED_POLICY_RULE_SETS = {
    "geosite-cn",
    "geoip-cn",
    "geosite-geolocation-!cn",
    ADS_RULE_SET,
}
HAND_WRITTEN_APP_TERMS = re.compile(
    r"(?:^|[.\\/_-])(?:qq|tencent|wechat|weixin|taobao|tmall|alicdn|mmstat)(?:$|[.\\/_-])",
    re.IGNORECASE,
)
PROCESS_RULE_KEYS = {
    "process_name",
    "process_name_regex",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "user",
}
HAND_WRITTEN_DOMAIN_KEYS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "domain_regex_exclude",
)


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


def infer_template_variant(path: Path) -> str | None:
    """Return the v4/v6 suffix encoded in a template filename, if any.

    The four historical, unsuffixed entry points are v4 compatibility aliases
    after the rollout.  Treat those known names as v4 while leaving arbitrary
    caller-provided paths unclassified; callers can still use the generic
    policy checks for an unclassified template.
    """

    match = TEMPLATE_VARIANT_RE.search(path.stem)
    if match:
        return match.group(1).lower()
    if path.name in {template.name for template in DEFAULT_TEMPLATES}:
        return "v4"
    return None


def relative_label(path: Path) -> str:
    """Render a stable, non-secret label for command output."""

    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def rule_sets_in(rules: list[Any]) -> set[str]:
    tags: set[str] = set()
    for obj in walk_objects(rules):
        if not isinstance(obj, dict):
            continue
        for rule_set in as_list(obj.get("rule_set")):
            if isinstance(rule_set, str):
                tags.add(rule_set)
    return tags


def first_rule_index(rules: list[Any], predicate) -> int | None:
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and predicate(rule):
            return index
    return None


def has_pre_sniff_ipv6_tcp_reject(route_rules: list[Any]) -> bool:
    """Whether an IPv6 TCP reject appears before the first sniff action."""

    first_sniff = first_rule_index(
        route_rules,
        lambda rule: rule.get("action") == "sniff",
    )
    before_sniff = route_rules if first_sniff is None else route_rules[:first_sniff]
    return any(
        isinstance(rule, dict)
        and rule.get("ip_version") == 6
        and rule.get("network") in (None, "tcp")
        and rule.get("action") == "reject"
        and rule.get("no_drop") is True
        for rule in before_sniff
    )


def tun_inbounds(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        inbound
        for inbound in doc.get("inbounds") or []
        if isinstance(inbound, dict) and inbound.get("type") == "tun"
    ]


def has_ipv6_tun_prefix(doc: dict[str, Any]) -> bool:
    return any(
        any(":" in str(address) for address in as_list(inbound.get("address")))
        for inbound in tun_inbounds(doc)
    )


def has_ipv6_tun_route(doc: dict[str, Any]) -> bool:
    """Check that IPv6 traffic remains routed into the TUN.

    sing-box's ``auto_route`` installs the equivalent of ``::/0``.  Newer
    templates may express it explicitly via ``route_address``; accept either
    form while requiring an IPv6 TUN prefix.
    """

    for inbound in tun_inbounds(doc):
        if inbound.get("auto_route") is True:
            return True
        for address in as_list(inbound.get("route_address")):
            if address == "::/0":
                return True
    return False


def has_ipv6_private_exclusion(doc: dict[str, Any]) -> bool:
    return any(
        "fc00::/7" in as_list(inbound.get("route_exclude_address"))
        for inbound in tun_inbounds(doc)
    )


def check_document(
    label: str,
    doc: dict[str, Any],
    *,
    allow_placeholders: bool,
    require_real_nodes: bool,
    expected_variant: str | None = None,
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
    all_rule_sets = rule_sets_in(dns_rules) | rule_sets_in(route_rules)

    if len(outbound_tags) != len(outbound_tag_set):
        failures.append(f"{label}: duplicate outbound tags exist")

    if any(
        isinstance(ob, dict) and ob.get("tag") == "Proxy" and ob.get("type") == "direct"
        for ob in outbounds
    ):
        failures.append(f"{label}: direct outbound fallback tag 'Proxy' is present")

    # Since sing-box 1.11, a rule that selects an outbound must use the
    # explicit route action.  Keep this check recursive so a future logical
    # rule cannot silently reintroduce the deprecated shorthand.
    for obj in walk_objects(route_rules):
        if not isinstance(obj, dict) or not obj.get("outbound"):
            continue
        if obj.get("action") != "route":
            failures.append(
                f"{label}: route rule with outbound {obj.get('outbound')} "
                "must use action=route"
            )

    # Hand-maintained application lists are deliberately excluded from the
    # templates.  QQ/WeChat/Taobao and similar domestic services are covered by
    # the remote CN rule sets; process-name matching also bypasses DNS policy.
    for scope, rules in (("route", route_rules), ("dns", dns_rules)):
        for obj in walk_objects(rules):
            if not isinstance(obj, dict):
                continue
            process_keys = PROCESS_RULE_KEYS.intersection(obj)
            if process_keys:
                failures.append(
                    f"{label}: {scope} process rule is not allowed "
                    f"({','.join(sorted(process_keys))})"
                )
            for key in HAND_WRITTEN_DOMAIN_KEYS:
                for value in as_list(obj.get(key)):
                    if isinstance(value, str) and HAND_WRITTEN_APP_TERMS.search(value):
                        failures.append(
                            f"{label}: {scope} hand-written application domain {value}"
                        )
            if (
                obj.get("action") == "reject"
                and "rule_set" not in obj
                and any(key in obj for key in HAND_WRITTEN_DOMAIN_KEYS)
            ):
                failures.append(
                    f"{label}: {scope} hand-written domain reject is not allowed"
                )

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

    missing_policy_rule_sets = sorted(REQUIRED_POLICY_RULE_SETS - all_rule_sets)
    if missing_policy_rule_sets:
        failures.append(
            f"{label}: required policy rule-sets are missing: "
            + ", ".join(missing_policy_rule_sets)
        )

    ads_definitions = [
        rule_set
        for rule_set in route_rule_sets
        if isinstance(rule_set, dict) and rule_set.get("tag") == ADS_RULE_SET
    ]
    if ads_definitions and not any(
        definition.get("type") == "remote" for definition in ads_definitions
    ):
        failures.append(f"{label}: {ADS_RULE_SET} must be a remote rule-set")

    # The ad rule-set must be evaluated before CN routing in DNS and before
    # business/mode routing in the route table.  This leaves service-specific
    # remote rules intact while preventing a CN catch-all from winning first.
    for scope, rules in (("dns", dns_rules), ("route", route_rules)):
        ads_reject_indices = [
            index
            for index, rule in enumerate(rules)
            if isinstance(rule, dict)
            and ADS_RULE_SET in as_list(rule.get("rule_set"))
            and rule.get("action") == "reject"
        ]
        if not ads_reject_indices:
            failures.append(f"{label}: {scope} has no {ADS_RULE_SET} reject rule")
            continue
        ads_index = min(ads_reject_indices)
        if scope == "dns":
            cn_index = first_rule_index(
                rules,
                lambda rule: "geosite-cn" in as_list(rule.get("rule_set")),
            )
            if cn_index is not None and ads_index > cn_index:
                failures.append(
                    f"{label}: dns {ADS_RULE_SET} reject must precede geosite-cn"
                )
        else:
            business_index = first_rule_index(
                rules,
                lambda rule: bool(rule.get("outbound")) or bool(rule.get("clash_mode")),
            )
            if business_index is not None and ads_index > business_index:
                failures.append(
                    f"{label}: route {ADS_RULE_SET} reject must precede business/mode rules"
                )

    # Keep the three user-facing mode choices explicit.  Direct is required for
    # local testing and Global remains the existing NodeSelected override.
    mode_targets = {"direct": "direct", "global": "🛩️ NodeSelected"}
    for mode, target in mode_targets.items():
        if not any(
            isinstance(rule, dict)
            and rule.get("clash_mode") == mode
            and rule.get("outbound") == target
            and rule.get("action") == "route"
            for rule in route_rules
        ):
            failures.append(
                f"{label}: route clash_mode={mode} must explicitly route to {target}"
            )

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

    tun_has_ipv6 = has_ipv6_tun_prefix(doc)
    if expected_variant == "v4":
        if dns.get("strategy") != "ipv4_only":
            failures.append(f"{label}: v4 template must use dns.strategy=ipv4_only")
        if tun_has_ipv6 and not has_pre_sniff_ipv6_tcp_reject(route_rules):
            failures.append(
                f"{label}: v4 template requires pre-sniff ip_version=6 tcp reject (no_drop)"
            )
    elif expected_variant == "v6":
        if dns.get("strategy") != "prefer_ipv6":
            failures.append(f"{label}: v6 template must use dns.strategy=prefer_ipv6")
        resolver = route.get("default_domain_resolver") or {}
        if not isinstance(resolver, dict) or resolver.get("strategy") != "prefer_ipv6":
            failures.append(
                f"{label}: v6 template requires route.default_domain_resolver.strategy=prefer_ipv6"
            )
        if has_pre_sniff_ipv6_tcp_reject(route_rules):
            failures.append(
                f"{label}: v6 template must not pre-reject IPv6 TCP before sniff"
            )
        if not tun_has_ipv6:
            failures.append(f"{label}: v6 template must retain a TUN IPv6 prefix")
        if tun_has_ipv6 and not has_ipv6_tun_route(doc):
            failures.append(f"{label}: v6 template must route IPv6 ::/0 into the TUN")
        if tun_has_ipv6 and not has_ipv6_private_exclusion(doc):
            failures.append(f"{label}: v6 template must exclude fc00::/7 from the TUN")

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
        "variant": expected_variant or "unclassified",
        "dns_strategy": dns.get("strategy"),
        "rule_set_count": len(rule_set_tags),
        "ads_rule_set": ADS_RULE_SET in rule_set_tags,
        "pre_sniff_ipv6_tcp_reject": has_pre_sniff_ipv6_tcp_reject(route_rules),
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
        / "sing-box-1.14.2-darwin-arm64"
        / "sing-box"
    )
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
    with build_subscription_opener().open(request, timeout=30) as response:
        body = response.read()
    output_path.write_bytes(body)
    return load_json(output_path)


class Redirect308Handler(urllib.request.HTTPRedirectHandler):
    """Treat provider CDN 308 redirects like safe GET redirects on Python 3.9."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib's Python 3.9 handler does not dispatch 308 itself. Reuse its
        # normal redirect validation and method handling, changing only the code.
        return super().redirect_request(
            req, fp, 307 if code == 308 else code, msg, headers, newurl
        )

    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302


def build_subscription_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(Redirect308Handler())


def selected_templates(paths: list[str] | None) -> list[Path]:
    """Resolve ``--template`` paths, or use the repository defaults.

    Explicit paths are intentionally not globbed: a repeated option gives the
    caller a deterministic validation set and avoids accidentally consuming
    generated files under ``sing-box/.tmp``.  Once the v4/v6 rollout adds
    suffixed templates, discover those tracked entry points alongside the four
    historical files for the default invocation.
    """

    if paths:
        selected: list[Path] = []
        seen: set[Path] = set()
        for raw_path in paths:
            for item in raw_path.split(","):
                item = item.strip()
                if not item:
                    continue
                path = Path(item).expanduser()
                if path.is_dir():
                    # A directory argument is useful for validating the full
                    # template family without including generated .tmp files.
                    candidates = sorted(path.glob("country-*.json"))
                    if not candidates:
                        candidates = sorted(path.glob("*.json"))
                else:
                    candidates = [path]
                for candidate in candidates:
                    key = candidate.resolve() if candidate.exists() else candidate
                    if key not in seen:
                        seen.add(key)
                        selected.append(candidate)
        return selected
    templates = list(DEFAULT_TEMPLATES)
    for path in sorted((REPO_ROOT / "sing-box").glob("country-*.json")):
        if TEMPLATE_VARIANT_RE.search(path.stem):
            if path not in templates:
                templates.append(path)
    return templates


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
        "--template",
        dest="templates",
        action="append",
        metavar="PATH",
        help=(
            "Local template to validate; repeat or comma-separate paths (a directory "
            "selects country-*.json). "
            "Names ending in -v4/-v6 enable variant-specific assertions."
        ),
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
    templates = selected_templates(args.templates)
    if not templates:
        failures.append("no local templates were selected")
    for template_path in templates:
        label = relative_label(template_path)
        try:
            doc = load_json(template_path)
        except (OSError, json.JSONDecodeError, ValidationFailure) as exc:
            failures.append(f"{label}: cannot load template ({exc})")
            continue
        expected_variant = infer_template_variant(template_path)
        doc_failures, stats = check_document(
            label,
            doc,
            allow_placeholders=True,
            require_real_nodes=False,
            expected_variant=expected_variant,
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
            f"proxy_direct={stats['proxy_direct_count']} "
            f"variant={stats['variant']} "
            f"dns_strategy={stats['dns_strategy']}"
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
