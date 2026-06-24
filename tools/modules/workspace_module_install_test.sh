#!/usr/bin/env bash
set -euo pipefail

resolve_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    printf '%s/%s\n' "$(cd "$(dirname "$path")" && pwd)" "$(basename "$path")"
    return
  fi
  if [[ -e "$PWD/$path" ]]; then
    printf '%s\n' "$PWD/$path"
    return
  fi
  echo "missing runfile: $path" >&2
  exit 1
}

find_runfile() {
  local rel="$1"
  for candidate in \
    "$PWD/$rel" \
    "${TEST_SRCDIR:-}/_main/$rel" \
    "${TEST_SRCDIR:-}/hovel/$rel"; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "missing runfile: $rel" >&2
  exit 1
}

write_command_package() {
  local name="$1"
  local module_type="$2"
  local binary="$3"
  local root="$packages/$name"
  mkdir -p "$root/bin"
  cat >"$root/hovel-module.yaml" <<YAML
apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: $name
  version: 0.1.0
  moduleType: $module_type
  summary: In-tree functional test package for $name
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/$name"]
YAML
  cat >"$root/bin/$name" <<SH
#!/usr/bin/env bash
set -euo pipefail
exec "$binary" "\$@"
SH
  chmod +x "$root/bin/$name"
}

write_python_package() {
  local name="$1"
  local module_type="$2"
  local project_dir="$3"
  local module="$4"
  local root="$packages/$name"
  mkdir -p "$root/bin"
  cat >"$root/hovel-module.yaml" <<YAML
apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: $name
  version: 0.1.0
  moduleType: $module_type
  summary: In-tree functional test package for $name
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/$name"]
YAML
  cat >"$root/bin/$name" <<SH
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$sdk_root:$project_dir\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m "$module" "\$@"
SH
  chmod +x "$root/bin/$name"
}

hovel_bin="$(resolve_path "${1:?missing hovel binary}")"
shift

tmp="$(mktemp -d "/tmp/hovel-workspace-module-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
workspace="$tmp/workspace"
packages="$tmp/packages"
mkdir -p "$packages"

python_root="$(find_runfile examples/python)"
sdk_root="$(find_runfile sdk/python)"
empty_config="$tmp/empty-modules.json"
printf '{"modules":[]}\n' >"$empty_config"
export HOVEL_MODULE_CONFIG="$empty_config"
export HOVEL_PYTHON_SDK_ROOT="$sdk_root"

"$hovel_bin" init --workspace "$workspace" --json >"$tmp/init.json"

write_python_package "etro-survey" "survey" "$python_root/etro_survey" "hovel_etro_survey"
write_python_package "etro-exploit" "exploit" "$python_root/etro_exploit" "hovel_etro_exploit"
write_python_package "mock-survey" "survey" "$python_root/mock_survey" "hovel_example_survey"
write_python_package "mock-exploit" "exploit" "$python_root/mock_exploit" "hovel_example_exploit"
write_python_package "mock-exploit-session" "exploit" "$python_root/mock_exploit_session" "hovel_example_exploit_session"
write_command_package "mock-survey-go" "survey" "$(resolve_path "$1")"
write_command_package "mock-exploit-go" "exploit" "$(resolve_path "$2")"
write_command_package "mock-exploit-session-go" "exploit" "$(resolve_path "$3")"
write_command_package "mock-survey-rust" "survey" "$(resolve_path "$4")"
write_command_package "mock-exploit-rust" "exploit" "$(resolve_path "$5")"
write_command_package "mock-exploit-session-rust" "exploit" "$(resolve_path "$6")"
write_command_package "squatter" "payload_provider" "$(resolve_path "$7")"

for package_root in "$packages"/*; do
  "$hovel_bin" module install --link "$package_root" --workspace "$workspace"
done

if [[ ! -f "$workspace/module-lock.yaml" ]]; then
  echo "module lock was not written" >&2
  exit 1
fi
lock_count="$(grep -c '^[[:space:]]*- name:' "$workspace/module-lock.yaml" || true)"
if [[ "$lock_count" != "12" ]]; then
  echo "module lock contains $lock_count modules, want 12" >&2
  cat "$workspace/module-lock.yaml" >&2
  exit 1
fi

list_out="$("$hovel_bin" module list --workspace "$workspace")"
printf '%s\n' "$list_out"
for name in \
  etro-survey \
  etro-exploit \
  mock-survey \
  mock-exploit \
  mock-exploit-session \
  mock-survey-go \
  mock-exploit-go \
  mock-exploit-session-go \
  mock-survey-rust \
  mock-exploit-rust \
  mock-exploit-session-rust \
  squatter; do
  grep -q "$name@0.1.0" <<<"$list_out"
done

check_out="$("$hovel_bin" module check --all --workspace "$workspace")"
printf '%s\n' "$check_out"
grep -q "MODULE CHECKS" <<<"$check_out"
grep -q "12 passed" <<<"$check_out"
