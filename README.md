# ProxyConfig

This repository converts Clash Trojan subscriptions into sing-box templates.
The stable compatibility entry is now the IPv6 track. The automatic IPv4
template remains as the single rollback copy.

## Template tracks

The target families are:

- `sing-box/country-auto.json` and `sing-box/country-auto-v6.json`: automatic
  country URL tests with `prefer_ipv6`; the unsuffixed file is the canonical
  default entry and the suffixed file is its explicit-track copy.
- `sing-box/country-auto-v4.json`: the single IPv4 rollback copy with
  `ipv4_only` and the pre-sniff IPv6 TCP fallback reject.
- `country-select*.json` and their `-v6` variants: the macOS, iOS, and generic
  selector templates. The four unsuffixed files are synchronized v6 aliases.

All service-specific routing stays in remote rule-sets. The templates keep the
remote `geosite-category-ads-all` set for optional ad rejection, but contain no
hand-written ad hosts, process rules, or WeChat/QQ/Taobao app lists. Domestic
traffic continues to use `geosite-cn`/`geoip-cn`, while
`geosite-geolocation-!cn` and the service rule-sets handle foreign traffic.

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

The checked-in v6 files are the result of the user's successful end-to-end
test. The builder never overwrites unsuffixed files; promotion is an explicit
copy step after review.

Run static checks and the remote rule-set probes. Each run writes only
non-secret diagnostics under `sing-box/.tmp/template-tests/<run>/`:

```sh
python3 scripts/test_singbox_templates.py --templates-dir sing-box
```

On macOS, add `--macos-environment --dns-probes` to record the active TUN,
default IPv6 route, Wi-Fi state, resolver families, and possible Tailscale DNS
interception. Add `--network-probes` to apply the v6 promotion gate.

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
