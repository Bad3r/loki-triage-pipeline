#!/usr/bin/env bash
set -euo pipefail

key="${VTCLI_APIKEY:-}"

if [[ -z "$key" && -f "$HOME/.vt.toml" ]]; then
  key="$(sed -n 's/^apikey=\"\(.*\)\"/\1/p' "$HOME/.vt.toml")"
fi

if [[ -z "$key" ]]; then
  echo "No VirusTotal API key found in VTCLI_APIKEY or ~/.vt.toml" >&2
  exit 1
fi

vt user "$key" --format json | jq '
  .[] | {
    daily: .quotas.api_requests_daily,
    hourly: .quotas.api_requests_hourly,
    monthly: .quotas.api_requests_monthly
  }
'
