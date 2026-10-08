#!/usr/bin/env python3
"""Prepare local SFM candidates without changing either running client.

The source must be an expanded configuration containing the real subscription
nodes. Outputs contain credentials and are written with mode 0600. No URL or
outbound node is logged. Tailnet names are discovered from the existing client.
"""

import argparse
import copy
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import urllib.request

from validate_singbox_subscription import (
    check_document,
    find_sing_box,
    strip_filters,
    WARNING_RE,
)


TAILSCALE_CLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
REPO = Path(__file__).resolve().parent.parent
OUTPUT_ROOT = REPO / "sing-box" / ".tmp" / "template-tests"
DNS_TAG = "tailscale-dns"
OUTBOUND_TAG = "tailscale-direct"
TAILNET_IPV4 = "100.64.0.0/10"
TAILNET_IPV6 = "fd7a:115c:a1e0::/48"


def tailscale_json(cli, *args):
    result = subprocess.run(
        [str(cli), *args, "--json"],
        env=dict(os.environ, TAILSCALE_BE_CLI="1"),
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return json.loads(result.stdout)


def after_ads(rules):
    return next(
        (index + 1 for index, rule in enumerate(rules)
         if rule.get("action") == "reject"
         and "geosite-category-ads-all" in (
             rule.get("rule_set") if isinstance(rule.get("rule_set"), list)
             else [rule.get("rule_set")]
         )),
        0,
    )


def covers_ts_net(rule):
    suffixes = rule.get("domain_suffix", [])
    if isinstance(suffixes, str):
        suffixes = [suffixes]
    return "ts.net" in suffixes or any(covers_ts_net(child) for child in rule.get("rules", []))


def split_dns_servers(routes, existing_tags, public_detour):
    """Preserve non-MagicDNS forwarding without depending on CorpDNS."""
    servers, rules = [], []
    ordered = sorted(routes.items(), key=lambda item: (-item[0].count("."),
                                                       -len(item[0]), item[0]))
    for index, (domain, resolvers) in enumerate(ordered):
        domain = domain.rstrip(".")
        if domain == "ts.net":
            # Tailscale's default public parent route need not use its
            # authoritative servers directly. Known MagicDNS names precede
            # this recursive-public-DNS rule, including shared peers.
            rules.append({"domain_suffix": domain, "action": "route",
                          "server": "dns_proxy"})
            continue
        if not domain or not resolvers:
            raise ValueError("unsupported empty split-DNS route")
        # This local candidate uses the first resolver from each split route.
        # Tailscale's concurrent redundant-resolver behavior is not reproduced.
        address = resolvers[0].get("Addr", "")
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise ValueError("non-IP split-DNS resolver needs separate review")
        tag = f"tailscale-split-{index + 1}"
        if tag in existing_tags:
            raise ValueError("source already has a split-DNS server tag")
        server = {"type": "udp", "tag": tag, "server": address,
                  "server_port": 53}
        if ip in ipaddress.ip_network(TAILNET_IPV4) or ip in ipaddress.ip_network(TAILNET_IPV6):
            server["detour"] = OUTBOUND_TAG
        elif ip.is_global:
            server["detour"] = public_detour
        # Private non-tailnet upstreams keep the ordinary direct DNS dialer.
        servers.append(server)
        rules.append({"domain_suffix": domain, "action": "route", "server": tag})
    return servers, rules


def transform(source, suffix, short_names, full_names, split_routes, real_dns, selections,
              tailscale_interface):
    doc = copy.deepcopy(source)
    if doc.get("endpoints"):
        raise ValueError("source already has endpoints; review it separately")
    doc["outbounds"] = [outbound for outbound in doc.get("outbounds", [])
                        if outbound.get("tag") != OUTBOUND_TAG]

    dns = doc["dns"]
    dns["servers"] = [server for server in dns["servers"] if server.get("tag") != DNS_TAG]
    # Another NetworkExtension's routes may be interface-scoped on macOS.
    # Bind to the discovered Tailscale interface rather than the physical
    # default or an unscoped route created by SFM's excludedRoutes.
    doc["outbounds"].append({
        "type": "direct",
        "tag": OUTBOUND_TAG,
        "bind_interface": tailscale_interface,
        "domain_resolver": {"server": DNS_TAG, "strategy": "prefer_ipv6"},
    })
    dns["servers"].append({
        "type": "udp",
        "tag": DNS_TAG,
        "server": "100.100.100.100",
        "server_port": 53,
        "detour": OUTBOUND_TAG,
    })
    split_servers, split_rules = split_dns_servers(
        split_routes, {server.get("tag") for server in dns["servers"]},
        next(server["detour"] for server in dns["servers"]
             if server.get("tag") == "dns_proxy" and server.get("detour")),
    )
    if any(rule.get("action") == "evaluate" and rule.get("server") == DNS_TAG
           and covers_ts_net(rule) for rule in dns["rules"]):
        # The shared template already probes all *.ts.net names and falls
        # back to public DNS. An earlier parent route would bypass that
        # probe for shared peers added after this snapshot was prepared.
        split_rules = [rule for rule in split_rules if rule.get("domain_suffix") != "ts.net"]
    dns["servers"].extend(split_servers)
    dns_rules = [
        {"domain_suffix": suffix, "action": "route", "server": DNS_TAG},
        {"domain": sorted(set(short_names + full_names)), "action": "route", "server": DNS_TAG},
        *split_rules,
    ]
    index = after_ads(dns["rules"])
    dns["rules"][index:index] = dns_rules

    for inbound in doc["inbounds"]:
        if inbound.get("type") == "tun":
            excluded = inbound.setdefault("route_exclude_address", [])
            # On Apple platforms excludedRoutes explicitly sends traffic to
            # the primary physical interface. Excluding 100/10 would steal
            # unscoped SSH traffic from Tailscale's scoped 100/10 route.
            excluded[:] = [prefix for prefix in excluded if prefix != TAILNET_IPV4]
            # Existing fc00::/7 already excludes Tailscale's IPv6 range.
            if "fc00::/7" not in excluded and TAILNET_IPV6 not in excluded:
                excluded.append(TAILNET_IPV6)

    routes = doc["route"]["rules"]
    index = after_ads(routes)
    routes[index:index] = [
        {"domain_suffix": suffix, "action": "route", "outbound": OUTBOUND_TAG},
        {"domain": sorted(set(short_names + full_names)), "action": "route", "outbound": OUTBOUND_TAG},
        {"ip_cidr": [TAILNET_IPV4, TAILNET_IPV6],
         "action": "route", "outbound": OUTBOUND_TAG},
    ]

    if real_dns:
        fake_tags = {server["tag"] for server in dns["servers"]
                     if server.get("type") == "fakeip"}
        if dns.get("final") in fake_tags:
            raise ValueError("source final DNS points at FakeIP; review separately")
        dns["servers"] = [server for server in dns["servers"]
                          if server.get("tag") not in fake_tags]
        dns["rules"] = [rule for rule in dns["rules"]
                        if rule.get("server") not in fake_tags]
        doc.setdefault("experimental", {}).setdefault("cache_file", {})[
            "store_fakeip"
        ] = False
    for outbound in doc["outbounds"]:
        if outbound.get("type") == "selector":
            chosen = selections.get(outbound.get("tag"))
            if chosen in outbound.get("outbounds", []):
                outbound["default"] = chosen
    return doc


def write_private(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
    finally:
        if fd is not None:
            os.close(fd)


def detect_tailscale_interface(tailscale_ips):
    expected = {ipaddress.ip_address(address) for address in tailscale_ips}
    if not expected:
        raise ValueError("existing Tailscale client has no local addresses")
    result = subprocess.run(["route", "-n", "get", "100.100.100.100"],
                            capture_output=True, text=True, check=True, timeout=5)
    for line in result.stdout.splitlines():
        key, separator, value = line.strip().partition(":")
        interface = value.strip()
        if (separator and key == "interface" and interface.startswith("utun")
                and interface[4:].isdigit()):
            addresses = subprocess.run(["ifconfig", interface], capture_output=True,
                                       text=True, check=True, timeout=5)
            actual = set()
            for entry in addresses.stdout.splitlines():
                fields = entry.split()
                if len(fields) >= 2 and fields[0] in ("inet", "inet6"):
                    actual.add(ipaddress.ip_address(fields[1].split("%", 1)[0]))
            if not actual.intersection(expected):
                raise ValueError("Quad100 route does not use the existing Tailscale interface")
            return interface
    raise ValueError("Quad100 does not have a Tailscale utun route; review routing first")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path,
                        help="Task directory under sing-box/.tmp/template-tests")
    parser.add_argument("--tailscale-cli", type=Path, default=Path(TAILSCALE_CLI))
    parser.add_argument("--sing-box", help="Optional matching sing-box CLI path")
    parser.add_argument("--preserve-current-selections", action="store_true",
                        help="Read local SFM Clash API to preserve selector choices")
    args = parser.parse_args()
    if args.output_dir is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        args.output_dir = OUTPUT_ROOT / f"tailscale-coexist-{stamp}"
    args.output_dir = args.output_dir.resolve()
    if OUTPUT_ROOT.resolve() not in args.output_dir.parents:
        parser.error("output-dir must be a task directory under sing-box/.tmp/template-tests")
    source = json.loads(args.source.read_text())
    controls = {"direct", "selector", "urltest", "block", "dns"}
    nodes = [outbound for outbound in source.get("outbounds", [])
             if outbound.get("type") not in controls]
    if not nodes or any("{all}" in outbound.get("outbounds", [])
                        for outbound in source.get("outbounds", [])):
        raise ValueError("source must contain expanded real proxy nodes")
    status = tailscale_json(args.tailscale_cli, "status")
    if status.get("BackendState") != "Running":
        raise ValueError("existing Tailscale client must be running")
    suffix = (status.get("MagicDNSSuffix") or "").rstrip(".")
    if not suffix or not status.get("CurrentTailnet", {}).get("MagicDNSEnabled"):
        raise ValueError("existing tailnet must have MagicDNS enabled")
    short_names = set()
    full_names = set()
    for peer in [status.get("Self", {}), *status.get("Peer", {}).values()]:
        name = peer.get("DNSName", "").rstrip(".").lower()
        if name:
            full_names.add(name)
        ending = "." + suffix.lower()
        if name.endswith(ending):
            short = name[:-len(ending)]
            if short and "." not in short:
                short_names.add(short)
    if not short_names:
        raise ValueError("MagicDNS short names could not be discovered")
    dns_status = tailscale_json(args.tailscale_cli, "dns", "status")
    for record in dns_status.get("ExtraRecords", []):
        if record.get("Type", "") not in ("", "A", "AAAA") or not record.get("Name"):
            continue
        try:
            address = ipaddress.ip_address(record.get("Value", ""))
        except ValueError:
            continue
        if (address not in ipaddress.ip_network(TAILNET_IPV4)
                and address not in ipaddress.ip_network(TAILNET_IPV6)):
            raise ValueError("non-tailnet ExtraRecords need separate DNS and route review")
        full_names.add(record["Name"].rstrip(".").lower())
    split_routes = dns_status.get("SplitDNSRoutes", {})
    tailscale_interface = detect_tailscale_interface(status.get("Self", {}).get("TailscaleIPs", []))
    selections = {}
    if args.preserve_current_selections:
        with urllib.request.urlopen("http://127.0.0.1:9090/proxies", timeout=5) as response:
            selections = {tag: proxy.get("now")
                          for tag, proxy in json.load(response)["proxies"].items()
                          if proxy.get("type") == "Selector"}
    args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.output_dir, 0o700)
    stripped_dir = args.output_dir / "stripped"
    if stripped_dir.is_symlink():
        raise ValueError("stripped output directory must not be a symbolic link")
    stripped_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(stripped_dir, 0o700)
    cli = find_sing_box(args.sing_box)
    if cli is None:
        raise ValueError("matching sing-box CLI is required for candidate validation")
    results = []
    for mode, real in [("real-dns", True), ("fakeip", False)]:
        doc = transform(source, suffix, sorted(short_names), sorted(full_names),
                        split_routes, real, selections, tailscale_interface)
        dest = args.output_dir / f"tailscale-coexist-{mode}.json"
        failures, stats = check_document(dest.name, doc,
                                         allow_placeholders=False,
                                         require_real_nodes=True)
        if failures:
            raise ValueError("candidate structural validation failed: " + "; ".join(failures))
        write_private(dest, doc)
        stripped = stripped_dir / dest.name
        write_private(stripped, strip_filters(doc))
        checked = subprocess.run([str(cli), "check", "-c", str(stripped)],
                                 capture_output=True, text=True, timeout=20, cwd=REPO)
        if checked.returncode or WARNING_RE.search(checked.stdout + checked.stderr):
            raise ValueError("candidate sing-box check failed or emitted a warning")
        results.append({"file": dest.name, "real_proxy_nodes": stats["real_proxy_node_count"],
                        "country_fallback_only": stats["country_fallback_only_count"],
                        "structural_validation_passed": True, "sing_box_check_passed": True})
        print(f"prepared={dest} real_proxy_nodes={len(nodes)} mode={mode} validation=passed")
    write_private(args.output_dir / "validation-results.json", results)


if __name__ == "__main__":
    main()
