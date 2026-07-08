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
6. Convert only supported node types. For Clash `trojan`, map `port` to `server_port`, `skip-cert-verify` to `tls.insecure`, and `sni` to `tls.server_name`; preserve supported `ws` and `grpc` transport options.
7. Preserve all converted nodes as outbounds, even when only HK/JP/SG/TW/US are exposed through main selectors.
8. Preserve the Steam route fix:
   - Add the `🎮 Other` selector outbound: members `["🛩️ NodeSelected", "direct", "🇭🇰 Hong Kong", "🇹🇼 Taiwan", "🇸🇬 Singapore", "🇺🇸 America"]`, `default` `🛩️ NodeSelected` (placed just before `😮‍💨 Final`).
   - Add `{ "rule_set": "geosite-steam", "outbound": "🎮 Other" }` near the top of `route.rules`.
   - Add the remote `geosite-steam` rule-set URL from `sing-box/AGENTS.md`.

## Validation

- Run `scripts/validate_singbox_subscription.py` after changing `sing-box/*.json`.
  Supply the real SFM final subscription URL via `--subscription-url` or
  `SINGBOX_SUBSCRIPTION_URL`; local template validation alone is not sufficient.
- The script must confirm JSON parsing, selector/urltest/default references,
  DNS server references, route and DNS rule-set references, no global
  `udp/443 reject`, and no deprecated `dns.rules[].strategy`.
- The final subscription output must have `missing_refs == 0`,
  `real_proxy_node_count > 0`, and real members in `🇭🇰 Hong Kong`,
  `🇹🇼 Taiwan`, `🇸🇬 Singapore`, and `🇺🇸 America`.
- `real_proxy_node_count == 0`, country selectors containing only `Proxy` or
  `direct`, or a `Proxy` direct fallback are release-blocking failures.
- If a matching `sing-box` CLI is available, the script strips SFM-only
  `filter` fields into `.tmp` and runs `sing-box check`; any warning or
  deprecated output is a failure.
- Taiwan node names use the Taiwan flag when the name indicates Taiwan.
- Stale provider hostnames are absent unless intentionally retained.

## Reporting

Do not print proxy passwords or full node bodies. Report only input path, output paths, node counts, group sizes, validation status, and blockers.

If Python lacks PyYAML, use Ruby `YAML` plus `JSON` as the fallback parser.
