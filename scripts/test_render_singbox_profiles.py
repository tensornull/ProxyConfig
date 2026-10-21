#!/usr/bin/env python3
"""Regression checks for rendering local SFM profiles from the templates."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_singbox_templates import TemplateError, ensure_ipv6_track, transform_document
from scripts.render_singbox_profiles import (
    AUTO_TAG,
    COUNTRY_TAGS,
    load_template,
    main,
    mode_for,
    render_profile,
    track_for,
)
from scripts.validate_singbox_subscription import check_document


TEMPLATES = Path(__file__).resolve().parents[1] / "sing-box"
PRIVATE_NODE = "🇺🇸 Private NYC | Hysteria2"
PROVIDER_GROUP = "☁️ Edge"


def node(tag: str) -> dict:
    return {"type": "trojan", "tag": tag, "server": "proxy.invalid", "server_port": 443,
            "password": "placeholder", "tls": {"enabled": True, "server_name": "proxy.invalid"}}


def tagged(doc: dict, tag: str) -> dict:
    return next(outbound for outbound in doc["outbounds"] if outbound["tag"] == tag)


def local_profile(*, track: str = "v4", stack: str | None = None) -> dict:
    """A drifted local profile: old track, explicit members, a private node."""

    doc = json.loads((TEMPLATES / "country-auto.json").read_text(encoding="utf-8"))
    ensure_ipv6_track(doc, track)
    doc["route"]["rules"].append({"domain_suffix": "drift.example", "action": "route",
                                  "outbound": "direct"})
    nodes = [node(f"{country} | 0{index}") for country in COUNTRY_TAGS for index in (1, 2)]
    nodes.append(node(PRIVATE_NODE))
    for outbound in doc["outbounds"]:
        outbound.pop("filter", None)
        if outbound["tag"] in COUNTRY_TAGS:
            outbound.update(type="selector", outbounds=[f"{outbound['tag']} | 01",
                                                         f"{outbound['tag']} | 02"])
            for key in ("url", "interval", "tolerance"):
                outbound.pop(key)
            outbound["default"] = f"{outbound['tag']} | 02"
    tagged(doc, "🇺🇸 America")["outbounds"].append(PRIVATE_NODE)
    tagged(doc, "🛩️ NodeSelected")["outbounds"].append(PRIVATE_NODE)
    tagged(doc, "🛩️ NodeSelected")["default"] = "🇺🇸 America"
    tagged(doc, "🎮 Other")["outbounds"].append("🇯🇵 Japan")
    doc["outbounds"].insert(doc["outbounds"].index(tagged(doc, "direct")), {
        "tag": PROVIDER_GROUP, "type": "urltest", "url": "https://edge.invalid/204",
        "interval": "5m", "outbounds": ["🇭🇰 Hong Kong | 01", PRIVATE_NODE]})
    tagged(doc, "😮‍💨 Final")["outbounds"].append(PROVIDER_GROUP)
    doc["outbounds"].extend(nodes)
    if stack:
        next(inbound for inbound in doc["inbounds"] if inbound["type"] == "tun")["stack"] = stack
    return doc


class NameRuleTests(unittest.TestCase):
    def test_track_and_mode_follow_the_profile_name(self):
        self.assertEqual(track_for("ProviderA-Select"), "v6")
        self.assertEqual(track_for("ProviderB"), "v6")
        self.assertEqual(track_for("ProviderA-Select-IPv4Only"), "v4")
        self.assertEqual(track_for("ProviderB-Auto-IPv4Only"), "v4")
        self.assertEqual(mode_for("ProviderA-Select"), "select")
        self.assertEqual(mode_for("ProviderC-macOS-gVisor-Select"), "select")
        self.assertEqual(mode_for("ProviderB-Select-IPv4Only"), "select")
        self.assertEqual(mode_for("ProviderA-Auto-IPv4Only"), "auto")
        with self.assertRaises(TemplateError):
            track_for("ProviderA-Select-IPv6Only")

    def test_a_name_without_a_mode_keeps_the_profile_kind(self):
        selector_shaped = local_profile()
        self.assertEqual(mode_for("Provider", selector_shaped), "select")
        self.assertEqual(mode_for("Provider-Auto", selector_shaped), "auto")
        doc = render_profile(selector_shaped, name="Provider", platform="macos")
        self.assertEqual(tagged(doc, "🇭🇰 Hong Kong")["type"], "selector")
        self.assertEqual(mode_for("Provider", doc), "select")


class RenderTests(unittest.TestCase):
    def test_default_name_uses_the_ipv6_default_even_from_a_v4_profile(self):
        doc = render_profile(local_profile(track="v4"), name="Provider-Select", platform="macos")
        template = load_template("macos", "v6")
        for key in ("log", "experimental", "http_clients", "dns", "route", "inbounds"):
            self.assertEqual(doc[key], template[key], key)
        self.assertEqual(doc["dns"]["strategy"], "prefer_ipv6")

    def test_ipv4_only_name_uses_the_v4_template(self):
        doc = render_profile(local_profile(track="v6"), name="Provider-Auto-IPv4Only",
                             platform="macos")
        self.assertEqual(doc["route"], load_template("macos", "v4")["route"])
        self.assertEqual(doc["dns"]["strategy"], "ipv4_only")

    def test_provider_data_and_valid_selections_survive(self):
        source = local_profile()
        doc = render_profile(source, name="Provider-Select", platform="macos")
        source_nodes = [o for o in source["outbounds"] if o["type"] == "trojan"]
        self.assertEqual([o for o in doc["outbounds"] if o["type"] == "trojan"], source_nodes)
        america = tagged(doc, "🇺🇸 America")
        self.assertEqual(america["type"], "selector")
        self.assertIn(PRIVATE_NODE, america["outbounds"])
        self.assertEqual(america["default"], "🇺🇸 America | 02")
        selected = tagged(doc, "🛩️ NodeSelected")
        self.assertIn(PRIVATE_NODE, selected["outbounds"])
        self.assertEqual(selected["default"], "🇺🇸 America")
        self.assertNotIn("filter", selected)
        # Template omissions are not restored from the drifted profile.
        self.assertNotIn("🇯🇵 Japan", tagged(doc, "🎮 Other")["outbounds"])
        self.assertIn(PROVIDER_GROUP, tagged(doc, "😮‍💨 Final")["outbounds"])
        self.assertEqual(tagged(doc, PROVIDER_GROUP)["type"], "selector")

    def test_auto_mode_uses_template_url_tests_and_interrupts_old_connections(self):
        doc = render_profile(local_profile(), name="Provider-Auto", platform="macos")
        template = load_template("macos", "v6")
        for tag in (*COUNTRY_TAGS, AUTO_TAG):
            group = tagged(doc, tag)
            self.assertEqual(group["type"], "urltest", tag)
            self.assertNotIn("default", group)
            self.assertTrue(group["interrupt_exist_connections"])
            for key in ("url", "interval", "tolerance"):
                self.assertEqual(group[key], tagged(template, tag)[key])
        self.assertEqual(tagged(doc, PROVIDER_GROUP)["url"], "https://edge.invalid/204")

    def test_ios_profiles_use_the_ios_template_and_expose_auto(self):
        doc = render_profile(local_profile(stack="gvisor"), name="Provider-Select",
                             platform="ios")
        template = load_template("ios", "v6")
        self.assertEqual(doc["dns"], template["dns"])
        self.assertEqual(doc["route"], template["route"])
        self.assertFalse(any(o["tag"] == "tailscale-direct" for o in doc["outbounds"]))
        self.assertEqual(len(doc["inbounds"]), len(template["inbounds"]))
        self.assertEqual(next(i for i in doc["inbounds"] if i["type"] == "tun")["stack"], "gvisor")
        for parent in ("🛩️ NodeSelected", "😮‍💨 Final"):
            self.assertIn(AUTO_TAG, tagged(doc, parent)["outbounds"])
        self.assertEqual(tagged(doc, AUTO_TAG)["type"], "urltest")

    def test_select_keeps_every_own_country_member_the_auto_filter_would_drop(self):
        source = local_profile()
        source["outbounds"].append(node("🇭🇰 Bronze Hong Kong | 03"))
        tagged(source, "🇭🇰 Hong Kong")["outbounds"].append("🇭🇰 Bronze Hong Kong | 03")
        for platform in ("macos", "ios"):
            with self.subTest(platform=platform):
                doc = render_profile(source, name="Provider-Select", platform=platform)
                self.assertEqual(tagged(doc, "🇭🇰 Hong Kong")["outbounds"],
                                 tagged(source, "🇭🇰 Hong Kong")["outbounds"])

    def test_output_mode_refuses_to_skip_the_cli_check_or_write_failed_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Provider-Select"
            path.write_text(json.dumps(local_profile()), encoding="utf-8")
            out = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--platform", "macos", "--profile", str(path),
                                       "--output-dir", str(out),
                                       "--sing-box", str(Path(tmp) / "missing")]), 2)
            self.assertFalse(out.exists())
            failing = Path(tmp) / "fake-sing-box"
            failing.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            failing.chmod(0o700)
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["--platform", "macos", "--profile", str(path),
                                       "--output-dir", str(out), "--sing-box", str(failing)]), 1)
            self.assertIn("FAIL", errors.getvalue())
            self.assertFalse((out / "Provider-Select").exists())

    def test_check_mode_reports_drift_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Provider-Select"
            path.write_text(json.dumps(local_profile()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--platform", "macos", "--profile", str(path), "--check"]), 1)
            rendered = render_profile(local_profile(), name="Provider-Select", platform="macos")
            path.write_text(json.dumps(rendered), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--platform", "macos", "--profile", str(path), "--check"]), 0)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["Provider-Select"])

    def test_rendering_is_idempotent_validated_and_a_transform_fixed_point(self):
        for platform in ("macos", "ios"):
            for name in ("Provider-Auto", "Provider-Select", "Provider-Auto-IPv4Only",
                         "Provider-Select-IPv4Only"):
                with self.subTest(platform=platform, name=name):
                    doc = render_profile(local_profile(), name=name, platform=platform)
                    self.assertEqual(render_profile(copy.deepcopy(doc), name=name,
                                                    platform=platform), doc)
                    track = track_for(name)
                    self.assertEqual(transform_document(doc, track,
                                                        tailscale_coexist=platform == "macos"), doc)
                    failures, stats = check_document(
                        name, doc, allow_placeholders=False, require_real_nodes=True,
                        expected_variant=track, require_simplified_policy=True)
                    self.assertEqual(failures, [])
                    self.assertEqual(stats["real_proxy_node_count"], 2 * len(COUNTRY_TAGS) + 1)


if __name__ == "__main__":
    unittest.main()
