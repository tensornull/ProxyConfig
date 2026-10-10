# ProxyConfig

This repository converts Clash Trojan subscriptions into sing-box templates.
The stable compatibility entry preserves IPv6 by default and keeps the TUN
IPv6 route and private-network exclusions. An explicit IPv4 fallback track is
available for node paths that cannot carry IPv6 destinations reliably.

## Template tracks

The target families are:

- `sing-box/country-auto.json` and `sing-box/country-auto-v6.json`: automatic
  country URL tests with `prefer_ipv6`; the unsuffixed file is the canonical
  default entry and the suffixed file is its explicit-track copy.
- `sing-box/country-auto-v4.json`: the explicit IPv4 fallback copy with
  `ipv4_only` and the pre-sniff IPv6 TCP fallback reject.
- `country-select*.json` and their `-v4`/`-v6` variants: the macOS, iOS, and
  generic selector templates. The unsuffixed files are synchronized v6
  defaults.

All service-specific routing stays in remote rule-sets. The templates keep the
remote `geosite-category-ads-all` set behind the `🌱 Purification` selector,
which defaults to `direct` and also exposes `reject` and `🛩️ NodeSelected` for
testing. The templates contain no
hand-written ad hosts, process rules, or WeChat/QQ/Taobao app lists. Domestic
traffic continues to use `geosite-cn`/`geoip-cn`, while
`geosite-geolocation-!cn` and the service rule-sets handle foreign traffic.

The IPv6-preferred tracks preserve domains across the TUN-to-proxy boundary
with a sing-box FakeIP server for A/AAAA queries. The synthetic IPv6 range is
`2001:2::/48`, which is intercepted by the TUN and avoids the private
`fc00::/7` exclusion. The FakeIP store restores the original domain before
route matching, so proxy outbounds send the domain to the remote side and let
that side choose a reachable CDN address. Persistent FakeIP mappings are
enabled so a restart does not strand browser connections. An unconditional
route `resolve` is deliberately absent: sing-box would turn the recovered
domain into a local IP literal before the proxy outbound, recreating the
failure this path is meant to avoid. Applications that use their own DoH/DoQ
resolver or hard-coded IPs remain outside TUN DNS interception.

## macOS: existing Tailscale client and SFM

The nine non-iOS templates include external-client coexistence rules for
sing-box 1.14 or newer. MagicDNS full names under `ts.net` and single-label
names are evaluated through Quad100 before public DNS and FakeIP rules.
A successful response is returned, including an empty successful AAAA answer;
errors, negative replies, and a one-second timeout fall back to the existing
public resolver for `ts.net` or `dns_resolver` for single-label names.
Tailnet addresses take the dedicated direct outbound before proxy mode rules.
The iOS templates do not include these rules.

On macOS, the shared `tailscale-direct` outbound is an unbound skeleton.
It keeps the ordinary dialer's default-interface protection, which does not
select another VPN's interface-scoped route. The preparation step below only
creates a private candidate and runs structural/sing-box checks; it does not
prove that SFM's NetworkExtension can send a second VPN's traffic through the
candidate. In particular, an activated SFM 1.14.2 profile can still log
`dial en0` for a `100.64.0.0/10` peer, and binding the peer's `utun` or source
address is not a portable fix. Treat the candidate as a diagnostic artifact
until an actual SFM activation test succeeds. The existing external client
must be running; these templates do not start a Tailscale node.

Keep the existing Tailscale client and its device identity. Let SFM handle the
system's public DNS, while its DNS rules send MagicDNS queries to the existing
client's `100.100.100.100` service. Disabling Tailscale's `accept-dns` preference
removes its system resolver configuration; it keeps the client connected and
the local MagicDNS query service available.

Prepare an expanded local SFM configuration with the existing real proxy nodes:

```sh
python3 scripts/prepare_singbox_tailscale.py \
  --source /path/to/expanded-sfm-config.json \
  --output-dir sing-box/.tmp/template-tests/tailscale-coexist-local \
  --preserve-current-selections
```

The script reads the running Tailscale client's tailnet suffix and peer names,
then produces two private local configurations. Use
`tailscale-coexist-fakeip.json` for the smallest change: it preserves public
FakeIP behavior and adds MagicDNS routing before the generic rules.
`tailscale-coexist-real-dns.json` is an optional alternative that sends public
queries to the existing real DNS servers. Both preserve IPv6 and proxy nodes.
The outputs contain subscription credentials, stay under the ignored task
directory, and have mode `0600`. The generator runs structural validation with
real-node requirements and `sing-box check`; it does not activate either client
or replace a remote subscription.

The local candidate can bind `tailscale-direct` to the existing Tailscale
interface discovered from the Quad100 route. The interface name is generated
locally and must not be hard-coded in shared templates. Regenerate the local
candidate if restarting either VPN changes that interface, then test both the
native OS path and the SFM SOCKS/TUN path; they are separate NetworkExtension
paths on macOS.

Do not put `100.64.0.0/10` in the TUN's `route_exclude_address` on macOS.
Apple's excluded routes explicitly send traffic to the primary physical
interface; they can override Tailscale's interface-scoped route and break
ordinary SSH to `100.x` peers. The generator removes that exclusion and retains
the existing IPv6 private range exclusion. Verify IPv4 and IPv6 peer connections
after activating SFM. Public traffic retains its existing dialer and proxy rules.

Public names under `ts.net`, such as Funnel names, are a narrow exception:
they are resolved to real addresses before normal proxy routing. Other public
domains retain their existing FakeIP behavior.

If the activation test succeeds, import the prepared configuration as a new
local profile in SFM and start it. Confirm that the MagicDNS full name and its
short name resolve through SFM, and that an existing tailnet service is
reachable. Then change only Tailscale's system DNS acceptance:

```sh
TAILSCALE_BE_CLI=1 /Applications/Tailscale.app/Contents/MacOS/Tailscale \
  set --accept-dns=false
```

After the switch, verify public HTTPS through the system TUN, MagicDNS full and
short names, and the existing tailnet connection. Check `scutil --dns` to ensure
Quad100 no longer owns the system's public DNS. On failure, restore DNS
acceptance before switching SFM back to its original profile:

```sh
TAILSCALE_BE_CLI=1 /Applications/Tailscale.app/Contents/MacOS/Tailscale \
  set --accept-dns=true
```

The local preparation adds exact short names and shared-peer full names from
the existing client's live peer list, including offline peers. With the new
templates, the generic Quad100 rules also cover newly added or renamed peers
without a list update. Other single-label names are tried against MagicDNS
before falling back to the template's `dns_resolver`; that public resolver
does not provide arbitrary LAN-only names. If a LAN device and a tailnet
device share a name, use their full names to distinguish them.

The standard public `ts.net` parent rule uses the existing public recursive DNS
server after known MagicDNS names. Other split DNS routes retain their first
bare-IP UDP resolver, with more specific suffixes matched first. Encrypted,
custom-port, empty-upstream, and redundant-resolver configurations need separate
review; the generator does not reproduce Tailscale's concurrent resolver races.
Extra A/AAAA records must point to tailnet addresses; public or LAN records
need separate DNS and route review, rather than being bound to Tailscale.
SFM's NetworkExtension needs actual activation testing in addition to CLI
checks, because its routing context differs from a standalone process.

The sing-box built-in [Tailscale endpoint](https://sing-box.sagernet.org/configuration/endpoint/tailscale/)
creates its own Tailscale node. Its [Tailscale DNS server](https://sing-box.sagernet.org/configuration/dns/server/tailscale/)
references that endpoint; it does not adopt the existing macOS client identity.
The external-client coexistence configuration uses a UDP DNS server instead.
See [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale) and
[MagicDNS](https://tailscale.com/docs/features/magicdns), sing-box's
[DNS evaluate/respond actions](https://sing-box.sagernet.org/configuration/dns/rule_action/)
and [interface binding](https://sing-box.sagernet.org/configuration/shared/dial/),
and Apple's [excluded routes](https://developer.apple.com/documentation/networkextension/neipv4settings/excludedroutes).

## Build and test

Generate a pilot pair from the automatic template:

```sh
python3 scripts/build_singbox_templates.py \
  --template sing-box/country-auto.json \
  --output-dir sing-box
```

The builder can reproduce both tracks for all four platforms in a temporary
directory:

```sh
python3 scripts/build_singbox_templates.py --all --output-dir sing-box/.tmp/template-tests/<run>/generated
```

The checked-in v6 files are the compatibility defaults. The builder never
overwrites unsuffixed files; promoting an explicit fallback remains an
explicit copy step after review.

Run static checks and the remote rule-set probes. Each run writes only
non-secret diagnostics under `sing-box/.tmp/template-tests/<run>/`:

```sh
python3 scripts/test_singbox_templates.py --templates-dir sing-box
```

On macOS, add `--macos-environment --dns-probes` to record the active TUN,
default IPv6 route, Wi-Fi state, resolver families, and possible Tailscale DNS
interception. Add `--network-probes` when evaluating an explicit fallback track.

The release gate still requires the real SFM final subscription URL (including
its redirect) and checks for real proxy nodes, populated country groups,
missing references, and `sing-box check` success:

```sh
SINGBOX_SUBSCRIPTION_URL='…' \
  python3 scripts/validate_singbox_subscription.py \
  --template sing-box/country-auto.json
```

Do not put subscription URLs, passwords, or complete node bodies in logs.

The checks follow the official sing-box references for [route rules](https://sing-box.sagernet.org/configuration/route/rule/), [route actions](https://sing-box.sagernet.org/configuration/route/rule_action/), [DNS](https://sing-box.sagernet.org/configuration/dns/), [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/), and [pre-match](https://sing-box.sagernet.org/configuration/shared/pre-match/).
