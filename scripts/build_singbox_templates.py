#!/usr/bin/env python3
"""Build the IPv4 and IPv6 variants of a sing-box template.

The source templates contain SFM-only ``filter`` fields and may have been
written using sing-box's legacy ``outbound`` rule shorthand.  This builder
keeps the source intact and writes only suffixed files.  It is intentionally
small and deterministic so it can also be imported by the static test tool.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = REPO_ROOT / "sing-box" / "country-auto.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "sing-box"

ADS_RULE_SET = "geosite-category-ads-all"
ADS_RULE_SET_URL = (
    "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/"
    "geo/geosite/category-ads-all.srs"
)

# These are the app-specific rules that the templates previously accumulated.
# Remote geosite/geoip sets cover them; preserving the user's infrastructure
# exceptions is handled by ``ALLOWED_DOMAIN_VALUES`` below.
APP_DOMAIN_MARKERS = (
    "weixin",
    "wechat",
    "qq.com",
    "qqmail",
    "taobao",
    "tmall",
    "tencent",
    "alicdn",
    "mmstat",
)
AD_DOMAIN_MARKERS = (
    "ad.",
    "ads.",
    ".ads.",
    "advert",
    "doubleclick",
    "googlesyndication",
    "tracking",
    "analytics",
    "telemetry",
)
DOMAIN_KEYS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "domain_regex_exclude",
)
PROCESS_KEYS = {
    "process_name",
    "process_name_regex",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "user",
}
ALLOWED_DOMAIN_VALUES = {
    "vercel.app",
    "lggafw.com",
    "edu.cn",
    "worldquantbrain.com",
}


class TemplateError(ValueError):
    """Raised for an invalid source template or build request."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise TemplateError(f"cannot read JSON template {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TemplateError(f"{path}: root JSON value must be an object")
    return value


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def string_values(value: Any) -> Iterable[str]:
    for item in as_list(value):
        if isinstance(item, str):
            yield item


def contains_allowed_domain(rule: dict[str, Any]) -> bool:
    values = {
        value.lower().strip(".")
        for key in DOMAIN_KEYS
        for value in string_values(rule.get(key))
    }
    return bool(values & ALLOWED_DOMAIN_VALUES)


def is_handwritten_app_or_ad_rule(rule: Any) -> bool:
    """Return whether a rule is a local app/ad rule that should be removed.

    Rule-set based rules are always retained.  User-owned infrastructure
    domains are retained even when their rule also has a reject-like action.
    A domain rule with ``action: reject`` is considered a handwritten ad rule
    unless it uses the remote ad rule-set.  This makes the cleanup safe for
    older templates while leaving port/IP protections untouched.
    """

    if not isinstance(rule, dict):
        return False
    if "rule_set" in rule:
        return False
    if PROCESS_KEYS.intersection(rule):
        return True
    if contains_allowed_domain(rule):
        return False
    values = " ".join(
        value.lower()
        for key in DOMAIN_KEYS
        for value in string_values(rule.get(key))
    )
    if not values:
        return False
    if any(marker in values for marker in APP_DOMAIN_MARKERS):
        return True
    if rule.get("action") == "reject":
        return True
    return any(marker in values for marker in AD_DOMAIN_MARKERS)


def clean_rules(rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        return []
    return [
        rule
        for rule in rules
        if isinstance(rule, dict) and not is_handwritten_app_or_ad_rule(rule)
    ]


def has_rule_set(doc: dict[str, Any], tag: str) -> bool:
    route = doc.setdefault("route", {})
    return any(
        isinstance(item, dict) and item.get("tag") == tag
        for item in as_list(route.get("rule_set"))
    )


def ensure_ads_rule_set(doc: dict[str, Any]) -> None:
    route = doc.setdefault("route", {})
    rule_sets = route.setdefault("rule_set", [])
    if not isinstance(rule_sets, list):
        raise TemplateError("route.rule_set must be a list")
    if not has_rule_set(doc, ADS_RULE_SET):
        rule_sets.append(
            {
                "tag": ADS_RULE_SET,
                "type": "remote",
                "format": "binary",
                "url": ADS_RULE_SET_URL,
            }
        )


def normalize_route_actions(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use explicit route actions whenever a route rule selects an outbound."""

    normalized: list[dict[str, Any]] = []
    for original in rules:
        rule = copy.deepcopy(original)
        if "outbound" in rule:
            # ``outbound`` is retained as the route action's parameter for
            # compatibility with sing-box 1.14; the explicit action removes
            # the deprecated implicit-action form.
            rule["action"] = "route"
        normalized.append(rule)
    return normalized


def _remove_matching(rules: list[dict[str, Any]], predicate) -> list[dict[str, Any]]:
    return [rule for rule in rules if not predicate(rule)]


def ensure_ads_rules(doc: dict[str, Any]) -> None:
    """Insert remote ad rejection before CN and mode/business rules."""

    dns = doc.setdefault("dns", {})
    dns_rules = clean_rules(dns.get("rules", []))
    dns_rules = _remove_matching(
        dns_rules,
        lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set")),
    )
    # Keep user DNS exceptions after the ad block and before geosite-cn.
    dns_rules.insert(0, {"rule_set": ADS_RULE_SET, "action": "reject"})
    dns["rules"] = dns_rules

    route = doc.setdefault("route", {})
    route_rules = normalize_route_actions(clean_rules(route.get("rules", [])))
    route_rules = _remove_matching(
        route_rules,
        lambda rule: ADS_RULE_SET in as_list(rule.get("rule_set")),
    )

    # Put the ad reject after the sniff/DNS-hijack prefix.  It must be before
    # the first mode rule and all business rule-sets, while DNS hijack remains
    # the first handler for DNS packets.
    prefix_end = 0
    for index, rule in enumerate(route_rules):
        if rule.get("action") in {"sniff", "hijack-dns"}:
            prefix_end = index + 1
    route_rules.insert(prefix_end, {"rule_set": ADS_RULE_SET, "action": "reject"})
    route["rules"] = route_rules


def ensure_direct_mode_rule(doc: dict[str, Any]) -> None:
    route = doc.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not isinstance(rules, list):
        raise TemplateError("route.rules must be a list")
    rules = [
        rule
        for rule in rules
        if not (
            isinstance(rule, dict)
            and rule.get("clash_mode") == "direct"
            and "outbound" in rule
        )
    ]
    rule = {"clash_mode": "direct", "action": "route", "outbound": "direct"}
    first_global = next(
        (
            index
            for index, item in enumerate(rules)
            if isinstance(item, dict) and item.get("clash_mode") == "global"
        ),
        len(rules),
    )
    # Keep global's historical position, but make direct an earlier explicit
    # mode rule.  The domestic QUIC allow/reject pair stays in its original
    # relative order after the ad gate.
    rules.insert(first_global, rule)
    route["rules"] = rules


def ensure_ipv6_track(doc: dict[str, Any], variant: str) -> None:
    dns = doc.setdefault("dns", {})
    route = doc.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not isinstance(rules, list):
        raise TemplateError("route.rules must be a list")

    def is_ipv6_tcp_reject(rule: Any) -> bool:
        return (
            isinstance(rule, dict)
            and rule.get("ip_version") == 6
            and rule.get("network") == "tcp"
            and rule.get("action") == "reject"
        )

    rules = _remove_matching(rules, is_ipv6_tcp_reject)
    if variant == "v4":
        rules.insert(
            0,
            {
                "ip_version": 6,
                "network": "tcp",
                "action": "reject",
                "no_drop": True,
            },
        )
        dns["strategy"] = "ipv4_only"
        route.setdefault("default_domain_resolver", {})["strategy"] = "prefer_ipv4"
    elif variant == "v6":
        dns["strategy"] = "prefer_ipv6"
        route.setdefault("default_domain_resolver", {})["strategy"] = "prefer_ipv6"
    else:
        raise TemplateError(f"unknown variant: {variant}")

    route["rules"] = rules

    # The IPv6 TUN address and private-network exclusion are required by both
    # tracks.  Refuse to produce a misleading v6 experiment from a stripped
    # source template.
    tun_inbounds = [
        inbound
        for inbound in doc.get("inbounds", [])
        if isinstance(inbound, dict) and inbound.get("type") == "tun"
    ]
    if not any(
        any(":" in str(address) for address in as_list(inbound.get("address")))
        for inbound in tun_inbounds
    ):
        raise TemplateError("source template has no IPv6 TUN address")
    if not any(
        "fc00::/7" in as_list(inbound.get("route_exclude_address"))
        for inbound in tun_inbounds
    ):
        raise TemplateError("source template must exclude fc00::/7 from the TUN")


def transform_document(source: dict[str, Any], variant: str) -> dict[str, Any]:
    doc = copy.deepcopy(source)

    route = doc.setdefault("route", {})
    dns = doc.setdefault("dns", {})
    route["rules"] = normalize_route_actions(
        clean_rules(route.get("rules", []))
    )
    dns["rules"] = clean_rules(dns.get("rules", []))
    ensure_ads_rule_set(doc)
    ensure_ads_rules(doc)
    ensure_direct_mode_rule(doc)
    # ``ensure_ads_rules`` normalizes before inserting; normalize once more so
    # templates with a pre-existing direct/global rule are unambiguous.
    route["rules"] = normalize_route_actions(route.get("rules", []))
    ensure_ipv6_track(doc, variant)
    return doc


def base_stem(path: Path) -> str:
    return re.sub(r"-v[46]$", "", path.stem)


def build_variant(source_path: Path, output_dir: Path, variant: str) -> Path:
    source = load_json(source_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"{base_stem(source_path)}-{variant}.json"
    document = transform_document(source, variant)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return destination


def parse_variants(value: str) -> list[str]:
    variants = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not variants:
        raise argparse.ArgumentTypeError("at least one variant is required")
    unknown = set(variants) - {"v4", "v6"}
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown variant(s): {', '.join(sorted(unknown))}"
        )
    return list(dict.fromkeys(variants))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--template",
        action="append",
        dest="templates",
        type=Path,
        help="source template (repeat for a batch; defaults to country-auto.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory for suffixed outputs (default: sing-box)",
    )
    parser.add_argument(
        "--variants",
        type=parse_variants,
        default=["v4", "v6"],
        metavar="v4,v6",
        help="tracks to generate (default: v4,v6)",
    )
    parser.add_argument(
        "--pilot",
        action="store_true",
        help="generate only the country-auto pilot pair (default behavior)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "generate suffixed variants for all four platform templates; "
            "never overwrite unsuffixed files"
        ),
    )
    return parser.parse_args(argv)


def resolve_templates(args: argparse.Namespace) -> list[Path]:
    if args.all and args.templates:
        raise TemplateError("--all cannot be combined with --template")
    if args.all and args.pilot:
        raise TemplateError("--all cannot be combined with --pilot")
    if args.all:
        names = (
            "country-auto.json",
            "country-select.json",
            "country-select-macos.json",
            "country-select-ios.json",
        )
        templates = [DEFAULT_OUTPUT_DIR / name for name in names]
    elif args.templates:
        templates = args.templates
    else:
        templates = [DEFAULT_TEMPLATE]
    resolved: list[Path] = []
    for path in templates:
        if not path.is_absolute():
            path = REPO_ROOT / path
        resolved.append(path.resolve())
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        templates = resolve_templates(args)
        outputs = [
            build_variant(template, args.output_dir, variant)
            for template in templates
            for variant in args.variants
        ]
    except TemplateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot write template: {exc}", file=sys.stderr)
        return 2

    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
