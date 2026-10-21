#!/usr/bin/env python3
"""Render local SFM profiles from the shipped sing-box templates.

A local profile contributes only provider data: its real nodes, the
membership of the country groups and of provider-specific groups, and its
valid selector choices.  DNS, inbounds, route policy, rule-sets and the
IPv4/IPv6 track all come from the checked-in template, so re-rendering
cannot carry drift forward.

The profile name selects the track: a name ending in ``-IPv4Only`` uses the
explicit v4 fallback template; every other name uses the IPv6-preferred
default.  A ``Select`` name gets selector country groups and an ``Auto`` name
URL-test country groups; a name with neither keeps its current kind.  Both
expose the ``⚡️ Auto`` URL test.  The platform selects the template family:
macOS profiles use ``country-auto`` (loopback and LAN listeners plus the
external-Tailscale rules) and iOS profiles use ``country-select-ios``.
``--check`` renders without writing and fails when a profile has drifted.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

if __package__:
    from . import build_singbox_templates as builder
    from . import validate_singbox_subscription as validator
else:
    import build_singbox_templates as builder
    import validate_singbox_subscription as validator


TEMPLATES_DIR = builder.REPO_ROOT / "sing-box"
PLATFORM_FAMILIES = {"macos": "country-auto", "ios": "country-select-ios"}
URLTEST_FAMILY = "country-auto"
AUTO_TAG = "⚡️ Auto"
AUTO_PARENTS = ("🛩️ NodeSelected", "😮‍💨 Final")
COUNTRY_TAGS = tuple(validator.COUNTRY_SELECTORS)
GROUP_TYPES = {"selector", "urltest"}
URLTEST_KEYS = ("url", "interval", "tolerance", "idle_timeout")
IPV4_ONLY_NAME = re.compile(r"-IPv4Only$", re.IGNORECASE)
IPV6_ONLY_NAME = re.compile(r"-IPv6Only$", re.IGNORECASE)
SELECT_NAME = re.compile(r"(?:^|-)Select(?:-|$)")
AUTO_NAME = re.compile(r"(?:^|-)Auto(?:-|$)")


def profile_name(path: Path) -> str:
    return path.name[:-len(".json")] if path.name.endswith(".json") else path.name


def track_for(name: str) -> str:
    if IPV6_ONLY_NAME.search(name):
        raise builder.TemplateError(f"{name}: there is no IPv6-only track; "
                                    "the default is IPv6-preferred")
    return "v4" if IPV4_ONLY_NAME.search(name) else "v6"


def mode_for(name: str, source: dict[str, Any] | None = None) -> str:
    if SELECT_NAME.search(name):
        return "select"
    if AUTO_NAME.search(name) or source is None:
        return "auto"
    country = groups(source).get(COUNTRY_TAGS[0], {})
    return "select" if country.get("type") == "selector" else "auto"


def load_template(platform: str, track: str) -> dict[str, Any]:
    family = PLATFORM_FAMILIES[platform]
    suffix = "-v4" if track == "v4" else ""
    return builder.load_json(TEMPLATES_DIR / f"{family}{suffix}.json")


def groups(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        outbound["tag"]: outbound
        for outbound in doc.get("outbounds", [])
        if isinstance(outbound, dict) and outbound.get("type") in GROUP_TYPES
    }


def real_nodes(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        copy.deepcopy(outbound)
        for outbound in doc.get("outbounds", [])
        if isinstance(outbound, dict)
        and outbound.get("type") not in validator.CONTROL_OUTBOUND_TYPES
    ]


def filter_members(template_group: dict[str, Any], node_tags: list[str]) -> list[str]:
    """Expand a template ``{all}`` group the way the subscription converter does."""

    def patterns(action: str) -> list[str]:
        return [
            keyword
            for item in template_group.get("filter", [])
            if item.get("action") == action
            for keyword in item.get("keywords", [])
        ]

    includes, excludes = patterns("include"), patterns("exclude")
    return [
        tag for tag in node_tags
        if (not includes or any(re.search(p, tag) for p in includes))
        and not any(re.search(p, tag) for p in excludes)
    ]


def as_urltest(group: dict[str, Any], parameters: dict[str, Any]) -> None:
    group["type"] = "urltest"
    group.pop("default", None)
    for key in URLTEST_KEYS:
        if key in parameters:
            group[key] = copy.deepcopy(parameters[key])
    # Close connections held by the previous node when the test switches.
    group["interrupt_exist_connections"] = True


def as_selector(group: dict[str, Any]) -> None:
    group["type"] = "selector"
    for key in (*URLTEST_KEYS, "interrupt_exist_connections"):
        group.pop(key, None)


def render_profile(source: dict[str, Any], *, name: str, platform: str) -> dict[str, Any]:
    """Return the template for ``name`` filled with the profile's provider data."""

    if platform not in PLATFORM_FAMILIES:
        raise builder.TemplateError(f"unknown platform: {platform}")
    track, mode = track_for(name), mode_for(name, source)
    doc = load_template(platform, track)
    urltests = groups(load_template("macos", track))
    nodes = real_nodes(source)
    node_tags = [node["tag"] for node in nodes]
    provider_groups = groups(source)

    controls = [copy.deepcopy(item) for item in doc["outbounds"]
                if item.get("type") in GROUP_TYPES]
    others = [copy.deepcopy(item) for item in doc["outbounds"]
              if item.get("type") not in GROUP_TYPES]
    if AUTO_TAG not in {group["tag"] for group in controls}:
        controls.insert(1, copy.deepcopy(urltests[AUTO_TAG]))
    template_tags = {item["tag"] for item in controls + others}
    extras = [copy.deepcopy(group) for tag, group in provider_groups.items()
              if tag not in template_tags
              and tag not in builder.SIMPLIFIED_REMOVED_OUTBOUNDS]
    extra_tags = [group["tag"] for group in extras]
    available = set(node_tags) | set(extra_tags) | template_tags

    for group in controls + extras:
        tag = group["tag"]
        template_group = copy.deepcopy(group)
        group.pop("filter", None)
        if tag in COUNTRY_TAGS:
            members = [member for member in provider_groups.get(tag, {}).get("outbounds", [])
                       if member in available]
            if not members:
                members = filter_members(template_group, node_tags)
            if not members:
                raise builder.TemplateError(f"{name}: {tag} has no provider members")
        elif tag in extra_tags:
            members = [member for member in group.get("outbounds", []) if member in available]
            if not members:
                raise builder.TemplateError(f"{name}: provider group {tag} is empty")
        else:
            members = list(group["outbounds"])
            if tag in AUTO_PARENTS and AUTO_TAG not in members:
                members.insert(0, AUTO_TAG)
            if tag != builder.AI_SELECTOR_TAG:
                # Keep provider additions (extra groups, pinned nodes such as a
                # private server); never restore members the template omits.
                members += [member for member in provider_groups.get(tag, {}).get("outbounds", [])
                            if member not in members
                            and (member in node_tags or member in extra_tags)]
        group["outbounds"] = members

        automatic = tag == AUTO_TAG or (
            mode == "auto" and (tag in COUNTRY_TAGS or (
                tag in extra_tags and group.get("type") == "urltest")))
        if automatic:
            # Provider URL tests keep their own probe; shared groups use the template's.
            as_urltest(group, urltests.get(tag, group))
        elif tag in COUNTRY_TAGS or tag in extra_tags or group.get("type") == "selector":
            fallback = group.get("default")
            as_selector(group)
            choices = (provider_groups.get(tag, {}).get("default"), fallback)
            group["default"] = next((choice for choice in choices if choice in members),
                                    members[0])

    doc["outbounds"] = controls + extras + others + nodes

    stack = next((inbound.get("stack") for inbound in source.get("inbounds", [])
                  if inbound.get("type") == "tun" and inbound.get("stack")), None)
    if stack:
        for inbound in doc["inbounds"]:
            if inbound.get("type") == "tun":
                inbound["stack"] = stack
    return doc


def check_profile(name: str, doc: dict[str, Any], *, platform: str,
                  sing_box: Path | None, check_dir: Path) -> list[str]:
    track = track_for(name)
    failures, _ = validator.check_document(
        name, doc, allow_placeholders=False, require_real_nodes=True,
        expected_variant=track, require_simplified_policy=True,
    )
    if builder.transform_document(doc, track, tailscale_coexist=platform == "macos") != doc:
        failures.append(f"{name}: template transform would still change the profile")
    failures += validator.run_sing_box_check(sing_box, name, doc, check_dir / f"{name}.json")
    return failures


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", choices=sorted(PLATFORM_FAMILIES), required=True)
    parser.add_argument("--profile", action="append", type=Path, required=True,
                        help="existing local profile (repeatable)")
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir", type=Path,
                        help="draft directory; the same file names are written there")
    output.add_argument("--check", action="store_true",
                        help="write nothing; fail when a profile differs from its rendering")
    parser.add_argument("--sing-box", help="matching sing-box CLI for a warning-free check")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    os.umask(0o077)
    failed = False
    try:
        sing_box = None
        if args.output_dir:
            # A draft is only reviewable after the matching core accepts it.
            sing_box = validator.find_sing_box(args.sing_box)
            if sing_box is None or (args.sing_box and sing_box != Path(args.sing_box)):
                raise builder.TemplateError("matching sing-box CLI not found; pass --sing-box")
            args.output_dir.mkdir(parents=True, exist_ok=True)
        for path in args.profile:
            name = profile_name(path)
            source = builder.load_json(path)
            doc = render_profile(source, name=name, platform=args.platform)
            report = {"profile": path.name, "track": track_for(name),
                      "mode": mode_for(name, source), "nodes": len(real_nodes(doc))}
            if args.check:
                failures = [] if doc == source else [f"{path.name}: differs from its template rendering"]
                report["drifted"] = bool(failures)
            else:
                failures = check_profile(name, doc, platform=args.platform, sing_box=sing_box,
                                         check_dir=args.output_dir / ".checks")
                if not failures:
                    (args.output_dir / path.name).write_text(
                        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                report["written"] = not failures
            print(json.dumps(report, ensure_ascii=False))
            for failure in failures:
                print(f"FAIL {failure}", file=sys.stderr)
            failed = failed or bool(failures)
    except (builder.TemplateError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
