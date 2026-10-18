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

The three `country-auto` templates include native LAN sharing. They retain
`127.0.0.1:2080` and add a separate HTTP/SOCKS mixed listener on
`0.0.0.0:2080`, bound to the Wi-Fi interface `en0`. Both listeners use
`reuse_addr: true` so they can share the port. LAN clients use the device's
current Wi-Fi IP; the templates do not hard-code the Mac's address.
A rule scoped to the LAN inbound rejects reported sources outside
`192.168.31.0/24`; normal policy routing follows it. There is no separate
LAN template family. This is an application proxy listener, not a NAT
gateway for devices that have not configured an HTTP or SOCKS proxy.

SFM 1.14.2's HTTP handler honors `X-Forwarded-For` when deriving the source
address. A forged LAN address in that header bypassed the HTTP CIDR rule
in a local test. That rule is not equivalent to socat's socket-level
`range` filter and must not be treated as a firewall or authentication
boundary. The LAN listener is bound to `en0`; the loopback listener remains
separate.

Native loopback and Wi-Fi HTTP/SOCKS5 access was verified locally with SFM
1.14.2's NetworkExtension on 2026-10-17, with socat stopped. The old
`local.sfm-lan-proxy` LaunchAgent is disabled and its plist is backed up
outside `~/Library/LaunchAgents`. Access from another physical LAN device
still needs confirmation. Updates to the existing `country-auto.json` URL
carry the LAN listener once the reviewed templates are published; local
template edits do not change a converter's remote copy. The current local
profile and running SFM configuration include the native listeners without
changing their existing node policies.

For iCloud updates, inspect both
`~/Library/Mobile Documents/iCloud~io~nekohasekai~sfamt/Documents` and the
legacy `iCloud~io~nekohasekai~sfavt/Documents` directory. They are different
application containers, not reliable macOS/iOS labels. Identify the profile
file used on each device, back up each destination, preserve its own real
nodes, IPv4/IPv6 track and TUN stack, then validate and read back each write.
Shared files keep the loopback listener and use the interface-bound wildcard
LAN listener, avoiding a bind to another device's fixed IP. iCloud file
profiles do not refresh from repository templates automatically, and a local
readback does not confirm delivery to the iPhone. The 10 existing JSON
profiles in both containers are updated individually; their nodes and
platform-specific DNS, routing, IPv4/IPv6 track and TUN stack are preserved.

Before refreshing or activating an SFM profile, decode `selected_profile_id`
with SFM's BinaryCodable format. In SFM 1.14.2, `00 06` is Optional<Int64>(3),
not profile 6: the non-nil marker precedes a ZigZag varint. Resolve the actual
profile name, type and source path before using a subscription URL. Recheck
the selection before loading, then verify the running configuration against
that selected source, including its real-node identities.

All service-specific routing stays in remote rule-sets. Google and Microsoft
share `🛩️ NodeSelected`; Apple and Bilibili share a direct route. Their remote
sets remain present, while the Google, Microsoft and Apple selectors are
removed. `geosite-cn` precedes ordinary service rules; `geoip-cn` remains the
late fallback for available IP addresses. AI, Steam, mode and infrastructure
exceptions keep their intended priority, and Google's existing priority over
YouTube remains intact. No unconditional route `resolve` is added.

OpenAI, Claude and Gemini share `🤖 AI`. In rule mode, AI routes precede ads;
AI A/AAAA DNS rules also precede ads and domestic DNS and retain FakeIP. Other
DNS record types retain their existing behavior. Direct/global mode does not
use this AI exception. AI has only Japan, Singapore, Taiwan and America, with
America as the public-template default. Local profiles preserve a valid current
country and selected real node, including the current Singapore selection.
Shared country URL tests keep their existing parameters and can still switch
nodes within a country.

The remote `geosite-category-ads-all` set stays behind `🌱 Purification`,
which defaults to `direct` and exposes `reject` and `🛩️ NodeSelected` for
testing. The templates contain no hand-written ad hosts, process rules, or
WeChat/QQ/Taobao app lists. `🇨🇳 China` stays selectable and defaults to direct.

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
Its state directory holds that separate identity, and a fresh state requires
its own authentication. The external-client coexistence configuration uses a
UDP DNS server instead. This iteration keeps the external client; it does not
register or migrate to an embedded node.

The official [tsnet documentation](https://tailscale.com/docs/features/tsnet)
explains application-owned tailnet identities. Tailscale's official
[connection types](https://tailscale.com/docs/reference/connection-types)
describe direct UDP, peer relay and DERP paths. These capability documents do
not establish which client has a higher P2P success rate on this network.
No controlled comparison or verified community comparison is recorded here;
community anecdotes must be labeled with their version and network context.
See [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale) and
[MagicDNS](https://tailscale.com/docs/features/magicdns), sing-box's
[DNS evaluate/respond actions](https://sing-box.sagernet.org/configuration/dns/rule_action/)
and [interface binding](https://sing-box.sagernet.org/configuration/shared/dial/),
and Apple's [excluded routes](https://developer.apple.com/documentation/networkextension/neipv4settings/excludedroutes).

## Build and test

From the repository root, choose a private run directory and a CLI whose
`version` output matches SFM's core:

```sh
umask 077
SINGBOX_RUN_DIR="sing-box/.tmp/template-tests/$(date +%Y%m%d-%H%M%S)"
SINGBOX_CLI="/path/to/matching/sing-box"
"$SINGBOX_CLI" version
```

Generate a pilot pair in the draft directory:

```sh
python3 scripts/build_singbox_templates.py \
  --template sing-box/country-auto.json \
  --output-dir "$SINGBOX_RUN_DIR/generated"
```

The builder can reproduce both tracks for all four platforms in a temporary
directory:

```sh
python3 scripts/build_singbox_templates.py --all --output-dir "$SINGBOX_RUN_DIR/generated"
for family in country-auto country-select country-select-macos country-select-ios; do
  cp "$SINGBOX_RUN_DIR/generated/$family-v6.json" "$SINGBOX_RUN_DIR/generated/$family.json"
done
```

The checked-in v6 files are the compatibility defaults. The builder never
overwrites unsuffixed files; the copy step above creates their draft versions.
Validate all 12 drafts before copying them to the shipped directory. Promoting
a v4 fallback requires an explicit choice. Regenerate into a second draft
directory and compare the outputs to confirm that normalization is idempotent.

Run static checks and remote rule-set probes against the draft directory.
Use a CLI matching the installed SFM core (1.14.3 for this iteration), and keep
diagnostics under `sing-box/.tmp/template-tests/<run>/`:

```sh
python3 scripts/test_singbox_templates.py \
  --templates-dir "$SINGBOX_RUN_DIR/generated" \
  --run-dir "$SINGBOX_RUN_DIR/checks" \
  --sing-box "$SINGBOX_CLI"
```

On macOS, add `--macos-environment --dns-probes` to record the active TUN,
default IPv6 route, Wi-Fi state, resolver families, and possible Tailscale DNS
interception. `--dns-probes` and `--network-probes` observe the active system
network; they do not route through or prove the behavior of an unactivated
draft. Candidate traffic needs a separately running isolated instance.

The release gate still requires the real SFM final subscription URL (including
its redirect) and checks for real proxy nodes, populated country groups,
missing references, and `sing-box check` success. Supply the real final URL as
`SINGBOX_SUBSCRIPTION_URL` through the existing private credential interface:

```sh
python3 scripts/validate_singbox_subscription.py \
  --template "$SINGBOX_RUN_DIR/generated" \
  --sing-box "$SINGBOX_CLI"
```

If that URL still reads the old published GitHub template, a pass establishes
only the subscription chain and real-node baseline. Expand the draft with the
matching real nodes and validate that candidate separately. Do not describe
the new local policy as remotely deployed until a later authorized publication
and a fresh final-URL check confirm it.

## Configuration update SOP

1. Identify the actual selected SFM profile and source. Inventory all 12
   templates and JSON profiles in both iCloud containers. Back up each file,
   record its SHA-256, real-node identities and valid selections, and preserve
   its IPv4/IPv6 track, TUN stack and platform differences. Keep private backups
   and expanded drafts in an ignored run directory with files mode `0600`.
2. Build drafts, review the policy diff and repeat generation. Check for stale
   selector references, populated countries, AI paths limited to its four
   countries, unchanged URL-test parameters, and v6/default equality. Retain
   personal infrastructure rules, LAN sharing, FakeIP, QUIC and Tailscale rules.
3. Run structural checks, warning-free matching-version `sing-box check`, real
   remote-set matches and the real final-URL check above. Exercise rule/direct/
   global modes, AI/ad and China/service intersections, Steam, media and fallback
   routing. Match probes using mode, protocol and IP conditions explicitly.
4. Expand candidates with real nodes and run an isolated CLI instance. Remove
   its TUN and LAN listeners; bind only fresh loopback proxy/DNS/API ports,
   outside active 2080/9090, and use a separate cache. Probe candidate DNS and
   HTTP/SOCKS paths, record matched routes, and distinguish authentication or
   region restrictions from connection failures. Regress v4/v6, FakeIP, QUIC,
   ads, LAN structure, infrastructure and Tailscale; label OS/TUN, physical LAN
   and iPhone checks that an isolated CLI cannot prove. Stop only that instance.
5. After candidate checks pass, recheck every destination's original hash.
   Stop on concurrent edits or an uncertain write. Copy the reviewed templates
   and per-profile drafts to their destinations, preserving each profile's real
   nodes and valid selections; read back, hash and validate every destination.
   On a caused failure, restore only this run's affected files from backups and
   verify restoration. Do not restart, activate, change modes or refresh SFM
   during a file-only update.
6. Report file updates, remote publication and runtime activation separately.
   Read current runtime state without changing it to confirm the active tunnel
   stayed intact. File readback does not establish iCloud delivery or iPhone
   behavior. A later authorized activation needs its own SFM NetworkExtension
   DNS/route/connection checks and rollback using the recorded source/selection.

The current operation stops after validated file staging: SFM activation,
remote publication and iPhone live validation are separate steps. The Clash API
on 9090 is usable for observation, but sing-box 1.14.3's
[`PUT /configs` handler](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/clashapi/configs.go#L64)
only returns 204 and does not reload files. Do not treat that response as proof
of activation. Consult the run report for checks actually completed and their
limits; this SOP itself is not a test result.

Do not put subscription URLs, passwords, or complete node bodies in logs.

The checks follow the official sing-box references for [route rules](https://sing-box.sagernet.org/configuration/route/rule/), [route actions](https://sing-box.sagernet.org/configuration/route/rule_action/), [DNS](https://sing-box.sagernet.org/configuration/dns/), [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/), and [pre-match](https://sing-box.sagernet.org/configuration/shared/pre-match/).
