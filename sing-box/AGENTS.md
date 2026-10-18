This directory is a configuration file template for Singbox. Every detail must be carefully considered, with no assumptions or speculation.
https://sing-box.sagernet.org/configuration

## Subscription Conversion SOP

When converting a Clash YAML subscription into sing-box configs for testing unstable providers:

- Treat the provider YAML as temporary input. If it comes from outside the repo, copy it into `sing-box/.tmp/<Provider>.yaml` for traceability.
- Generate both `sing-box/.tmp/<provider>-auto.json` and `sing-box/.tmp/<provider>-select.json`.
- Use the current known-good `.tmp` auto/select configs as the base so DNS, inbounds, route policy, Clash API, and local fixes stay intact. If the user manually changed an output file, preserve that shape unless explicitly asked to overwrite it.
- Parse the YAML structure first. Do not guess country groups; read `proxy-groups` and build HK/JP/SG/TW/US membership from the provider's own `HK`, `JP`, `SG`, `TW`, and `US` groups when present.
- Convert only supported nodes, currently Clash `type: trojan`, into sing-box outbounds. Map `port` to `server_port`, `skip-cert-verify` to `tls.insecure`, and `sni` to `tls.server_name`; preserve supported `ws`/`grpc` transport options if present.
- Fix Taiwan node names from a wrong China flag to `🇹🇼` when the name indicates Taiwan.
- Keep all converted nodes as outbounds. First-class country groups are HK/JP/SG/TW/US: `🇭🇰 Hong Kong`, `🇯🇵 Japan`, `🇸🇬 Singapore`, `🇹🇼 Taiwan`, `🇺🇸 America`. Keep Japan in the remaining proxy policy groups. `🤖 AI` has exactly `["🇯🇵 Japan", "🇸🇬 Singapore", "🇹🇼 Taiwan", "🇺🇸 America"]`, default `🇺🇸 America` in public templates. Local profiles retain a valid current AI country and real-node selection; do not change shared country urltest parameters. Remove the Google, Microsoft and Apple selectors: Google/Microsoft route through `🛩️ NodeSelected`, Apple/Bilibili through `direct`.
- Auto country urltests may exclude `(?i)bronze|silver` for HK/SG/US. Do not apply that exclude to `🇹🇼 Taiwan` or `🇯🇵 Japan`, or providers that only have Bronze/Silver there will look empty.
- Preserve the Steam route fix: Steam is its own selector group. Add the `🎮 Other` selector outbound with members `["🛩️ NodeSelected", "direct", "🇭🇰 Hong Kong", "🇹🇼 Taiwan", "🇸🇬 Singapore", "🇺🇸 America"]` and `default` `🛩️ NodeSelected` (placed just before the `😮‍💨 Final` outbound; Steam stays without `🇯🇵 Japan`), add one route rule `{ "rule_set": "geosite-steam", "action": "route", "outbound": "🎮 Other" }` near the top of `route.rules`, and add the remote `geosite-steam` rule-set using `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/steam.srs`. (`🎮 Other` is the temporary name for the Steam group.)
- Preserve the Safari/system-HTTP QUIC fallback after sniffing, but never place a bare `{ "protocol": "quic", "action": "reject" }` first: `{ "protocol": "quic", "rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "🇨🇳 China" }` must come before the leftover QUIC reject. Do not replace this with a global `udp/443 reject`.
- Remote rule-set policy (2026-10-18): retain all existing remote service sets, including those whose selectors are merged. Route OpenAI/Claude/Gemini through `🤖 AI` before ads only in `clash_mode: "rule"`; their A/AAAA DNS rules likewise precede ads and domestic DNS while preserving FakeIP. Other DNS record types retain existing behavior. Keep direct/global mode semantics and the ad selector `🌱 Purification` (`["direct", "reject", "🛩️ NodeSelected"]`, default `direct`). Place `geosite-cn` before ordinary service routes while preserving AI, Steam, mode and infrastructure exceptions and Google's existing priority over YouTube; leave `geoip-cn` near the end as an available-IP fallback. No global resolve or hand-written telemetry list.
- Never delete the user's infrastructure rules (server `ip_cidr` direct ranges, `vercel.app`, `lggafw.com`, `edu.cn`, `worldquantbrain.com`, iOS `lggafw.com` DNS). Keep `🇨🇳 China` selectable (`["direct", "🛩️ NodeSelected", ...]`, default `direct`). Do not add hand-written ad hosts, `process_name` rules, or WeChat/QQ/Taobao app lists; use the remote sets.
- IPv4/IPv6 tracks (2026-10-06): the unsuffixed templates remain the IPv6-preferred defaults. They retain the TUN IPv6 prefix, automatic `::/0` route, and `fc00::/7` exclusion, with global `dns.strategy: "prefer_ipv6"` and `prefer_ipv6` resolver strategy. Keep `country-auto-v4.json` and explicit `*-v4.json` files as opt-in fallbacks; those add the pre-sniff `{ "ip_version": 6, "network": "tcp", "action": "reject", "no_drop": true }`, global `dns.strategy: "ipv4_only"`, and `prefer_ipv4` resolver strategy. `no_drop` avoids the 50-in-30s silent-drop fallback.
- TUN-to-proxy domain preservation (2026-10-06): every shipped track uses a `type: "fakeip"` DNS server for A/AAAA queries with `inet4_range: "198.18.0.0/15"` and `inet6_range: "2001:2::/48"`, `dns.reverse_mapping: true`, and `experimental.cache_file.store_fakeip: true`. The FakeIP store restores the original domain before route matching, so proxy outbounds send the domain to the remote side and let that side choose a reachable CDN address. Do not add an unconditional route `{ "action": "resolve" }`: sing-box's resolve action populates local `DestinationAddresses` and intentionally changes the proxy destination to an IP literal, which recreates the broken TUN IPv6 path. Use resolve only on a narrowly scoped local-IP/L3 branch when that tradeoff is required. Do not replace this with provider-specific host rules or a global IPv4-only strategy. FakeIP only covers A/AAAA queries that pass through TUN DNS hijacking; DoH/DoQ and hard-coded IPs remain outside this mechanism.
- Keep the bare `{ "protocol": "quic", "action": "reject" }` as the final protocol fallback, after service and geolocation rule-sets. This lets known foreign QUIC traffic use its normal selected outbound while still rejecting otherwise-unmatched QUIC; do not add provider- or domain-specific exceptions.
- Routing syntax (2026-10-03): every route rule that selects an outbound must use explicit `"action": "route"` with `"outbound"`; do not introduce the deprecated outer `outbound` form in new templates. Keep the domestic QUIC allow rule before the general QUIC reject, and keep explicit `clash_mode: "direct"` and `clash_mode: "global"` route actions.
- macOS + Tailscale: with "Use Tailscale DNS" on, the system resolver is `100.100.100.100` (MagicDNS forwarding to the router), so apps' DNS never reaches sing-box `dns.rules`. DNS-only fixes do not reach apps there; check `scutil --dns` / `/etc/resolv.conf` first.
- Validate after generation with `scripts/validate_singbox_subscription.py`.
  For any change under `sing-box/*.json`, local template checks are not enough:
  supply the real SFM final subscription URL with `--subscription-url` or
  `SINGBOX_SUBSCRIPTION_URL` so the script validates the converted output that
  SFM actually consumes. If the final URL still uses the old remote template,
  record it as a subscription/node baseline and validate the new draft expanded
  with real nodes separately; that pass does not publish or activate the draft.
- Release-blocking failures include: JSON parse errors, selector/urltest/default
  references to missing tags, missing DNS or route rule-set references, global
  `udp/443 reject`, deprecated `dns.rules[].strategy`, `real_proxy_node_count=0`
  in the final subscription, or country selectors (`🇭🇰 Hong Kong`,
  `🇯🇵 Japan`, `🇹🇼 Taiwan`, `🇸🇬 Singapore`, `🇺🇸 America`) containing only
  `Proxy`, `direct`, or no members.
- Do not add or rely on a `Proxy` direct fallback to make SFM start. That masks
  provider or subscription-conversion failures and can leave all country
  selectors without real nodes.
- Keep repeatable template-test output under `sing-box/.tmp/template-tests/<run>/`;
  include only rule-set status, route labels, counts, and probe results. Never
  write subscription URLs, passwords, cookies, or complete node bodies to those
  logs.
- Do not print proxy passwords or full node bodies in summaries; report only counts, group sizes, file paths, and validation status.

## Safe template and iCloud iteration

Follow the executable commands and update SOP in `README.md`:

1. Back up all destinations and record hashes, source profile, real-node identities
   and selections. Keep private files in the ignored run directory, mode `0600`.
2. Generate and review all 12 drafts, verify regeneration is idempotent and
   each unsuffixed draft equals its v6 counterpart before validation.
3. Run static/remote-set checks and warning-free checks with the installed core's
   matching CLI (1.14.3 for this iteration), plus the real final-URL validation.
   Cover mode/protocol/IP conditions and AI/ads and China/service intersections.
4. Validate expanded candidates in an isolated CLI with fresh loopback-only
   proxy/DNS/API ports and a private cache; remove TUN/LAN listeners. Active-network
   `--network-probes`/`--dns-probes` are baselines, not candidate execution.
5. After candidate checks pass, compare source hashes again, update templates and
   each iCloud file while preserving its own nodes/track/stack, then read back and
   validate. Stop on concurrent modification, a failed check or uncertain writes;
   restore affected files from the recorded backups if this update caused failure.
6. Keep file staging, remote publication, SFM activation and iPhone validation
   distinct. File-only work must not restart/activate/refresh SFM or change its
   mode/selections. Later activation needs actual NetworkExtension validation.

The 9090 Clash API does not imply file reload support: the sing-box 1.14.3
[`PUT /configs` implementation](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/clashapi/configs.go#L64)
only returns 204. Do not use it as activation evidence. Do not migrate the current
external Tailscale client to an embedded endpoint during this iteration; the
embedded endpoint creates an independent node identity (see `README.md`).

The local Python environment may lack PyYAML. Ruby's built-in `YAML` plus `JSON`
is the reliable fallback for one-off conversions in this workspace.
