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
- Keep all converted nodes as outbounds, even if only HK/JP/SG/TW/US are exposed through the main country selectors.
- Preserve the Steam route fix: Steam is its own selector group. Add the `🎮 Other` selector outbound with members `["🛩️ NodeSelected", "direct", "🇭🇰 Hong Kong", "🇹🇼 Taiwan", "🇸🇬 Singapore", "🇺🇸 America"]` and `default` `🛩️ NodeSelected` (placed just before the `😮‍💨 Final` outbound), add one route rule `{ "rule_set": "geosite-steam", "outbound": "🎮 Other" }` near the top of `route.rules`, and add the remote `geosite-steam` rule-set using `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/steam.srs`. (`🎮 Other` is the temporary name for the Steam group.)
- Preserve the Safari/system-HTTP QUIC fallback after sniffing, but never place a bare `{ "protocol": "quic", "action": "reject" }` first. WeChat / `mp.weixin.qq.com` need QUIC exceptions first: geosite-cn, WeChat/Weixin/QQ process names, and weixin/qq suffixes must go to `🇨🇳 China` before the leftover QUIC reject. Do not replace this with a global `udp/443 reject`.
- Keep ad blocking before `geosite-cn`: reject `geosite-category-ads-all` plus WeChat/GDT ad hosts (`wxsnsdy.wxs.qq.com`, `getappmsgad.mp.weixin.qq.com`, `gdt.qq.com`) at the top of both `dns.rules` and `route.rules`. A late ads reject after `geosite-cn` will never fire for domestic ad domains.
- Validate after generation with `scripts/validate_singbox_subscription.py`.
  For any change under `sing-box/*.json`, local template checks are not enough:
  supply the real SFM final subscription URL with `--subscription-url` or
  `SINGBOX_SUBSCRIPTION_URL` so the script validates the converted output that
  SFM actually consumes.
- Release-blocking failures include: JSON parse errors, selector/urltest/default
  references to missing tags, missing DNS or route rule-set references, global
  `udp/443 reject`, deprecated `dns.rules[].strategy`, `real_proxy_node_count=0`
  in the final subscription, or country selectors (`🇭🇰 Hong Kong`,
  `🇹🇼 Taiwan`, `🇸🇬 Singapore`, `🇺🇸 America`) containing only `Proxy`, `direct`,
  or no members.
- Do not add or rely on a `Proxy` direct fallback to make SFM start. That masks
  provider or subscription-conversion failures and can leave all country
  selectors without real nodes.
- Do not print proxy passwords or full node bodies in summaries; report only counts, group sizes, file paths, and validation status.
- The local Python environment may lack PyYAML. Ruby's built-in `YAML` plus `JSON` is the reliable fallback for one-off conversions in this workspace.
