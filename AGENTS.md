# ProxyConfig Agent Instructions

This repository contains proxy configuration workspaces. Directory-specific
rules live close to the files they govern.

## Routing

- For sing-box subscription conversion or validation, use
  `.agents/skills/sing-box-subscription-conversion/SKILL.md`.
- Before editing files under `sing-box/`, read `sing-box/AGENTS.md`.

## Safety

- Do not print proxy passwords, full node bodies, cookies, or raw provider
  subscription secrets in summaries.
- Keep generated test configs under the task-specific `.tmp` locations described
  by the relevant directory instructions.

## Required Validation

- After changing `sing-box/*.json`, run
  `scripts/validate_singbox_subscription.py` with the real SFM final
  subscription URL supplied via `--subscription-url` or
  `SINGBOX_SUBSCRIPTION_URL`.
- Do not treat local JSON parsing or `sing-box check` alone as sufficient.
  The final subscription output must contain real proxy nodes and country
  selectors with real members.
- `--local-only` is for draft inspection only and is not a release gate.
