#!/usr/bin/env python3
"""
Clash Trojan -> sing-box converter.
Extracts Trojan nodes from a Clash YAML config and injects them into a
sing-box JSON template, expanding {all} placeholders with filter rules.

Usage examples:
  python clash_trojan_to_singbox.py clash.yaml
  python clash_trojan_to_singbox.py clash.yaml -o output.json
  python clash_trojan_to_singbox.py clash.yaml -t template.json
  python clash_trojan_to_singbox.py clash.yaml -t https://example.com/t.json -o result.json
"""

import argparse
import json
import os
import re
import sys
import urllib.request

import yaml

TEMPLATE_URL = (
    "https://raw.githubusercontent.com/tensornull/ProxyConfig"
    "/main/sing-box/country-select-macos.json"
)


# Fix incorrect flag emoji in node names (e.g. provider uses 🇨🇳 for Taiwan)
FLAG_FIXES = {
    re.compile(r"TW|tw|台湾|臺灣|台|Taiwan"): "🇹🇼",
}


def fix_flag(name):
    """Replace wrong flag emoji at the start of a node name."""
    for pattern, correct_flag in FLAG_FIXES.items():
        if pattern.search(name):
            # Strip existing regional indicator pair (flag) at the start
            if len(name) >= 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in name[:2]):
                return correct_flag + name[2:]
    return name


def convert_trojan(proxy):
    """Convert a Clash Trojan proxy to a sing-box outbound dict."""
    ob = {
        "type": "trojan",
        "tag": fix_flag(proxy["name"]),
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "password": proxy["password"],
        "tls": {
            "enabled": True,
            "insecure": proxy.get("skip-cert-verify", False),
        },
    }

    if proxy.get("sni"):
        ob["tls"]["server_name"] = proxy["sni"]
    if proxy.get("alpn"):
        alpn = proxy["alpn"]
        ob["tls"]["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    if proxy.get("client-fingerprint"):
        ob["tls"]["utls"] = {
            "enabled": True,
            "fingerprint": proxy["client-fingerprint"],
        }

    net = proxy.get("network", "tcp")
    if net == "ws":
        ws = proxy.get("ws-opts", {})
        ob["transport"] = {
            "type": "ws",
            "path": ws.get("path", "/"),
            "headers": ws.get("headers", {}),
        }
    elif net == "grpc":
        grpc = proxy.get("grpc-opts", {})
        ob["transport"] = {
            "type": "grpc",
            "service_name": grpc.get("grpc-service-name", ""),
        }

    return ob


def apply_filters(tags, filters):
    """Apply include/exclude keyword filters to a list of node tags."""
    result = list(tags)
    for f in filters:
        keywords = f.get("keywords", [])
        if not keywords:
            continue
        # Keywords are joined by | inside a single string, so flatten them
        pattern = re.compile("|".join(keywords))
        action = f.get("action", "")
        if action == "include":
            result = [t for t in result if pattern.search(t)]
        elif action == "exclude":
            result = [t for t in result if not pattern.search(t)]
    return result


def load_json(source):
    """Load JSON from a URL or local file path."""
    if source.startswith("http"):
        with urllib.request.urlopen(source, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    with open(source, "r", encoding="utf-8") as f:
        return json.load(f)


def inject_nodes(template, all_tags):
    """Expand {all} placeholders in selector/urltest outbounds with node tags."""
    outbounds = []
    for ob in template.get("outbounds", []):
        if ob.get("type") in ("selector", "urltest"):
            filters = ob.pop("filter", [])
            expanded = []
            for item in ob.get("outbounds", []):
                if (
                    isinstance(item, str)
                    and item.startswith("{")
                    and item.endswith("}")
                ):
                    expanded.extend(apply_filters(all_tags, filters))
                else:
                    expanded.append(item)
            ob["outbounds"] = expanded or ["direct"]
        outbounds.append(ob)
    return outbounds


def main():
    parser = argparse.ArgumentParser(
        description="Convert Clash Trojan proxies to sing-box JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python %(prog)s clash.yaml
  python %(prog)s clash.yaml -o output.json
  python %(prog)s clash.yaml -t template.json
  python %(prog)s clash.yaml -t https://example.com/t.json -o result.json""",
    )
    parser.add_argument("input", help="Clash YAML config file")
    parser.add_argument(
        "-t", "--template", default=TEMPLATE_URL, help="Template URL or path"
    )
    parser.add_argument(
        "-o", "--output", help="Output path (default: <input>-singbox.json)"
    )
    args = parser.parse_args()

    # Read Clash config
    with open(args.input, "r", encoding="utf-8") as f:
        clash = yaml.safe_load(f)
    proxies = clash.get("proxies", [])

    # Convert Trojan nodes only
    nodes = []
    for p in proxies:
        if p.get("type") == "trojan":
            nodes.append(convert_trojan(p))
        else:
            print(f"[skip] {p.get('type', '?')}: {p.get('name', '?')}", file=sys.stderr)

    all_tags = [n["tag"] for n in nodes]
    print(f"Converted {len(nodes)}/{len(proxies)} proxies (Trojan only)")

    # Load template and inject nodes
    template = load_json(args.template)
    template["outbounds"] = inject_nodes(template, all_tags) + nodes

    # Write output
    output = args.output or os.path.splitext(args.input)[0] + "-singbox.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    print(f"Saved to: {output}")


if __name__ == "__main__":
    main()
