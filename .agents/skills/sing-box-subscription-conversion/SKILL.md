---
name: sing-box-subscription-conversion
description: Convert Clash YAML subscriptions into sing-box test configs in ProxyConfig/sing-box. Use when the user asks to convert, inspect, validate, or repair provider subscription YAML, sing-box auto/select configs, route rules, selector groups, node tags, or geosite-steam handling.
---

# sing-box Subscription Conversion

Use this skill for `ProxyConfig/sing-box` subscription conversion work.

## Workflow

1. Read `sing-box/AGENTS.md` before changing files.
2. Treat provider YAML as temporary input. If it came from outside the repo, copy it to `sing-box/.tmp/<Provider>.yaml` for traceability.
3. Parse YAML structurally. Do not infer country groups from node names when `proxy-groups` provide `HK`, `JP`, `SG`, `TW`, or `US` membership.
4. Generate both:
   - `sing-box/.tmp/<provider>-auto.json`
   - `sing-box/.tmp/<provider>-select.json`
5. Use the current known-good `.tmp` auto/select configs as the base so DNS, inbounds, route policy, Clash API, and local fixes stay intact.
6. Convert only supported node types. For Clash `trojan`, map `port` to `server_port`, `skip-cert-verify` to `tls.insecure`, and `sni` to `tls.server_name`; preserve supported `ws` and `grpc` transport options. Use the canonical `country-auto.json` (synchronized IPv6-preferred default) unless an explicit v4 fallback track is requested.
7. Preserve all converted nodes as outbounds. First-class country groups are HK/JP/SG/TW/US. Keep Japan in the remaining proxy policy groups; AI is limited to JP/SG/TW/US with a US public-template default, preserving valid local country/node choices and existing shared urltest parameters. Google/Microsoft share `🛩️ NodeSelected`, Apple/Bilibili share `direct`; remove the three old selectors but keep their remote sets. Auto may exclude `(?i)bronze|silver` for HK/SG/US only — never for `🇹🇼 Taiwan` or `🇯🇵 Japan`.
8. Preserve the Steam route fix:
   - Add the `🎮 Other` selector outbound: members `["🛩️ NodeSelected", "direct", "🇭🇰 Hong Kong", "🇹🇼 Taiwan", "🇸🇬 Singapore", "🇺🇸 America"]`, `default` `🛩️ NodeSelected` (placed just before `😮‍💨 Final`). Steam stays without `🇯🇵 Japan`.
   - Add `{ "rule_set": "geosite-steam", "action": "route", "outbound": "🎮 Other" }` near the top of `route.rules`.
   - Add the remote `geosite-steam` rule-set URL from `sing-box/AGENTS.md`.
9. Preserve the Safari/system-HTTP QUIC fallback after sniffing, but keep the bare `{ "protocol": "quic", "action": "reject" }` after service and geolocation rule-sets: `{ "protocol": "quic", "rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "🇨🇳 China" }` and known foreign routes go before it. Do not use a global `udp/443 reject`.
10. Keep all remote service sets and `geosite-category-ads-all` behind the existing `🌱 Purification` selector. In rule mode only, AI routes and AI A/AAAA FakeIP DNS rules precede ads and domestic rules; other DNS record types retain existing behavior. Place `geosite-cn` before ordinary services while preserving AI, Steam, mode and infrastructure exceptions and Google's existing priority over YouTube. Keep `geoip-cn` as a late available-IP fallback. Preserve user infrastructure and selectable `🇨🇳 China`; do not add hand-written app/telemetry/ads lists or process rules. See `sing-box/AGENTS.md` for the exact policy.
11. Generate paired tracks. The unsuffixed templates are the IPv6-preferred defaults: they retain the TUN IPv6 prefix, automatic `::/0` route, and `fc00::/7` exclusion, and use `prefer_ipv6` for DNS and the default domain resolver. Preserve the generic FakeIP A/AAAA rule, `reverse_mapping`, and persistent FakeIP cache so the TUN path restores domains before proxy routing. Do not add an unconditional route `resolve`: in sing-box it converts the recovered domain into local address literals and sends those literals to proxy outbounds. Use resolve only on a narrowly scoped local-IP/L3 branch when that tradeoff is required. Keep `country-auto-v4.json` and explicit `*-v4.json` files as opt-in fallbacks with the pre-sniff IPv6 TCP reject and `ipv4_only` strategy. Keep the generic QUIC reject after service/geolocation rules in both tracks (see `sing-box/AGENTS.md`).
12. Use explicit route actions for outbound selection: `{ "action": "route", "outbound": "..." }`; the legacy outer `outbound` field is deprecated in new templates. Keep `clash_mode: "direct"` and `clash_mode: "global"` route rules explicit.

## Validation

- Run `scripts/validate_singbox_subscription.py` after changing `sing-box/*.json`.
  Supply the real SFM final subscription URL via `--subscription-url` or
  `SINGBOX_SUBSCRIPTION_URL`; local template validation alone is not sufficient.
  An old published template at that URL validates only the subscription/node
  baseline; separately expand the draft with real nodes and check it. A baseline
  pass does not establish new-policy publication or activation.
- The script must confirm JSON parsing, selector/urltest/default references,
  DNS server references, route and DNS rule-set references, no global
  `udp/443 reject`, and no deprecated `dns.rules[].strategy`.
- The final subscription output must have `missing_refs == 0`,
  `real_proxy_node_count > 0`, and real members in `🇭🇰 Hong Kong`,
  `🇯🇵 Japan`, `🇹🇼 Taiwan`, `🇸🇬 Singapore`, and `🇺🇸 America`.
- `real_proxy_node_count == 0`, country selectors containing only `Proxy` or
  `direct`, or a `Proxy` direct fallback are release-blocking failures.
- If a matching `sing-box` CLI is available, the script strips SFM-only
  `filter` fields into `.tmp` and runs `sing-box check`; any warning or
  deprecated output is a failure.
- Taiwan node names use the Taiwan flag when the name indicates Taiwan.
- Stale provider hostnames are absent unless intentionally retained.
- Follow `README.md`'s update SOP: backup/hashes → draft/review → static and real
  final-URL checks → isolated real-node candidate tests → guarded file updates
  and readback → separately authorized runtime validation. Check regeneration
  idempotence and the equality of all four unsuffixed templates to their v6 files.
- Use the installed core's matching CLI (1.14.3 for this iteration). Candidate
  instances use fresh loopback-only proxy/DNS/API ports and a separate cache,
  with TUN/LAN listeners removed. `--dns-probes` and `--network-probes` observe
  the current system network and cannot validate an unactivated draft.
- Cover rule/direct/global modes, AI/ad and China/service intersections, Steam,
  media, fallback, v4/v6, FakeIP, QUIC, ads, LAN structure, infrastructure and
  Tailscale. Label OS/TUN, physical LAN and iPhone validation limits explicitly.
- Preserve per-profile nodes, selections, IPv4/IPv6 track and TUN stack when
  updating both iCloud containers. Recheck hashes before writing, stop on races
  or uncertain writes, and read back/validate each destination. File-only work
  must not activate, restart, refresh or change SFM modes/selections.
- A 204 from 1.14.3 `PUT /configs` is not a reload; see the source link in
  `README.md`. Keep the external Tailscale client and identity this iteration.

## Reporting

Do not print proxy passwords or full node bodies. Report only input path, output paths, node counts, group sizes, validation status, and blockers.

If Python lacks PyYAML, use Ruby `YAML` plus `JSON` as the fallback parser.
