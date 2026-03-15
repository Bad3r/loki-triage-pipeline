#!/bin/env bash
KEY=$(sed -n 's/^apikey="\(.*\)"/\1/p' ~/.vt.toml)
vt user "$KEY" --format json | jq '.[] | {daily: .quotas.api_requests_daily,\
 hourly: .quotas.api_requests_hourly, monthly: .quotas.api_requests_monthly}'
