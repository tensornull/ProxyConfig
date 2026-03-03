#!/usr/bin/env python3
"""
Clash Trojan → sing-box converter.
Extracts Trojan proxy nodes from a Clash YAML config and injects them
into a sing-box JSON template according to its filter rules.
"""
import json, re, sys, yaml, urllib.request, os, argparse


def convert_trojan(proxy):
    """Convert a single Clash Trojan proxy entry to a sing-box outbound."""
    ob = {
        "type": "trojan",
        "tag": proxy["name"],
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
    alpn = proxy.get("alpn")
    if alpn:
        ob["tls"]["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    fp = proxy.get("client-fingerprint")
    if fp:
        ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}

    net = proxy.get("network", "tcp")
    if net == "ws":
        ws_opts = proxy.get("ws-opts", {})
        ob["transport"] = {
            "type": "ws",
            "path": ws_opts.get("path", "/"),
            "headers": ws_opts.get("headers", {}),
        }
    elif net == "grpc":
        grpc_opts = proxy.get("grpc-opts", {})
        ob["transport"] = {
            "type": "grpc",
            "service_name": grpc_opts.get("grpc-service-name", ""),
        }
    return ob


def apply_filters(node_tags, filters):
    """Filter node tags using include/exclude keyword rules from the template."""
    result = list(node_tags)
    for f in filters:
        action = f.get("action", "")
        keywords = f.get("keywords", [])
        if not keywords:
            continue
        pattern = re.compile("|".join(re.escape(k) for k in keywords))
        if action == "include":
            result = [t for t in result if pattern.search(t)]
        elif action == "exclude":
            result = [t for t in result if not pattern.search(t)]
    return result


def main():
    default_template = (
        "https://raw.githubusercontent.com/tensornull/ProxyConfig"
        "/main/sing-box/country-select-macos.json"
    )

    parser = argparse.ArgumentParser(
        description="Convert Clash Trojan proxies to sing-box JSON config"
    )
    parser.add_argument("input", help="Path to Clash YAML config file")
    parser.add_argument(
        "-t", "--template",
        default=default_template,
        help="Template URL or file path (default: country-select-macos.json)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: <input>-singbox.json)",
    )
    args = parser.parse_args()

    clash_file = args.input
    template_source = args.template
    output_file = args.output

    # 1. Read Clash config
    print(f"Reading Clash config: {clash_file}")
    with open(clash_file, "r", encoding="utf-8") as f:
        clash = yaml.safe_load(f)
    proxies = clash.get("proxies", [])
    print(f"  Found {len(proxies)} proxies")

    # 2. Convert Trojan nodes (skip non-trojan)
    nodes = []
    for p in proxies:
        if p.get("type") != "trojan":
            print(
                f"  [skip] unsupported protocol: {p.get('type', '?')} "
                f"({p.get('name', '?')})",
                file=sys.stderr,
            )
            continue
        nodes.append(convert_trojan(p))
    print(f"  Converted {len(nodes)} Trojan nodes")
    all_tags = [n["tag"] for n in nodes]

    # 3. Load template
    print(f"Loading template: {template_source}")
    if template_source.startswith("http"):
        req = urllib.request.Request(
            template_source, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = urllib.request.urlopen(req, timeout=15)
        template = json.loads(resp.read().decode("utf-8"))
    else:
        with open(template_source, "r", encoding="utf-8") as f:
            template = json.load(f)

    # 4. Inject nodes into template outbounds
    print("Injecting nodes into template...")
    final_outbounds = []
    for ob in template.get("outbounds", []):
        if ob.get("type") not in ("selector", "urltest"):
            final_outbounds.append(ob)
            continue

        raw_outbounds = ob.get("outbounds", [])
        filters = ob.get("filter", [])
        new_outbounds = []

        for item in raw_outbounds:
            if isinstance(item, str) and item.startswith("{") and item.endswith("}"):
                # Placeholder like {all} — replace with matched nodes
                matched = apply_filters(all_tags, filters)
                new_outbounds.extend(matched)
            else:
                new_outbounds.append(item)

        if not new_outbounds:
            new_outbounds = ["direct"]

        ob["outbounds"] = new_outbounds
        ob.pop("filter", None)  # sing-box doesn't recognise this field
        tag = ob.get("tag", "?")
        # Count actual proxy nodes injected (exclude well-known group tags)
        non_group = [
            o for o in new_outbounds
            if o not in {
                "direct", "\U0001f1ed\U0001f1f0 Hong Kong",
                "\U0001f1f9\U0001f1fc Taiwan",
                "\U0001f1f8\U0001f1ec Singapore",
                "\U0001f1fa\U0001f1f8 America",
                "\U0001f6e9\ufe0f NodeSelected",
                "\U0001f440 ForeignMedia", "\U0001f34e Apple",
                "\u24c2\ufe0f Microsoft", "\U0001f310 Google",
                "\U0001f3af Foreign", "\U0001f1e8\U0001f1f3 China",
                "\U0001f916 AI", "\U0001f62e\u200d\U0001f4a8 Final",
            }
        ]
        if non_group:
            print(f"  {tag}: injected {len(non_group)} nodes")
        final_outbounds.append(ob)

    final_outbounds.extend(nodes)
    template["outbounds"] = final_outbounds

    # 5. Write output
    result = json.dumps(template, indent=2, ensure_ascii=False)
    if not output_file:
        output_file = os.path.splitext(clash_file)[0] + "-singbox.json"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result)
    print(f"\nSaved to: {output_file}")
    print(f"Done — {len(nodes)} Trojan proxy nodes converted.")


if __name__ == "__main__":
    main()
