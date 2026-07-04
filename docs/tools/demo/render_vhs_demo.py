#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Render one VHS tape with declared Bazel inputs.")
    parser.add_argument("--tape", required=True, type=Path)
    parser.add_argument("--tape-rel", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--hovel-bin", required=True, type=Path)
    parser.add_argument("--agent-bin", required=True, type=Path)
    parser.add_argument("--mock-survey-go", required=True, type=Path)
    parser.add_argument("--mock-exploit-session-go", required=True, type=Path)
    parser.add_argument("--chain-file", required=True, type=Path)
    parser.add_argument("--setup-script", required=True, type=Path)
    parser.add_argument("--tmux-script", required=True, type=Path)
    parser.add_argument("--duration-checker", required=True, type=Path)
    parser.add_argument("--vhs-bin", required=True, type=Path)
    parser.add_argument("--vhs-version-file", type=Path)
    parser.add_argument("--chrome-bin", required=True, type=Path)
    parser.add_argument("--ffmpeg-bin", required=True, type=Path)
    parser.add_argument("--ttyd-bin", required=True, type=Path)
    parser.add_argument("--squatter-provider", type=Path)
    parser.add_argument("--squatter-exe", type=Path)
    parser.add_argument("--dockerfile", type=Path)
    parser.add_argument("--docker-entrypoint", type=Path)
    parser.add_argument("--docker-runner", type=Path)
    parser.add_argument("--wine", action="store_true")
    args = parser.parse_args()

    vhs = executable_path(args.vhs_bin)
    ffmpeg = executable_path(args.ffmpeg_bin)
    ttyd = executable_path(args.ttyd_bin)
    verify_vhs_version(vhs, args.vhs_version_file)
    require_command("tmux")
    if args.wine:
        require_command("docker")
        require_wine_inputs(args)

    with tempfile.TemporaryDirectory(prefix="hovel-vhs-", dir=os.environ.get("TMPDIR")) as work_raw:
        work = Path(work_raw)
        repo = work / "repo"
        build_synthetic_repo(repo, args)
        chrome_wrapper = write_chrome_wrapper(repo / "demo/tmp/chrome-bin/chrome", executable_path(args.chrome_bin))
        env = os.environ | {
            "TMPDIR": str(repo / "demo/tmp/vhs-tmp"),
            "HOME": str(repo / "demo/tmp/home"),
            "XDG_CACHE_HOME": str(repo / "demo/tmp/cache"),
            "HOVEL_REPO_ROOT": str(repo),
            "HOVEL_DEMO_HOVEL_BIN": str(repo / "demo/tmp/hovel"),
            "HOVEL_DEMO_AGENT_BIN": str(repo / "demo/tmp/hovel-mock-agent"),
            "PATH": tool_path(chrome_wrapper.parent, Path(vhs).parent, Path(ffmpeg).parent, Path(ttyd).parent),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        run_vhs(vhs, args.tape_rel, repo, env)
        rendered = rendered_output(repo, repo / args.tape_rel)
        if not rendered.is_file() or rendered.stat().st_size == 0:
            raise SystemExit(f"expected demo output was not generated: {rendered}")
        subprocess.run([sys.executable, str(repo / "tools/demo/check_gif_duration.py"), str(rendered)], check=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(rendered, args.output)
    return 0


def run_vhs(vhs: str, tape_rel: str, repo: Path, env: dict[str, str]) -> None:
    result = subprocess.run(
        [vhs, tape_rel],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return
    if result.stdout:
        sys.stderr.write(result.stdout)
        if not result.stdout.endswith("\n"):
            sys.stderr.write("\n")
    print_demo_diagnostics(repo)
    raise SystemExit(f"vhs failed rendering {tape_rel} with exit code {result.returncode}")


def print_demo_diagnostics(repo: Path) -> None:
    logs = sorted((repo / "demo/tmp").rglob("*.log"))
    for log in logs[:10]:
        rel = log.relative_to(repo)
        sys.stderr.write(f"\n--- {rel} ---\n")
        lines = log.read_text(errors="replace").splitlines()
        for line in lines[:120]:
            sys.stderr.write(line + "\n")
        if len(lines) > 120:
            sys.stderr.write(f"... omitted {len(lines) - 120} line(s) ...\n")


def build_synthetic_repo(repo: Path, args: argparse.Namespace) -> None:
    for rel in (
        Path(args.tape_rel).parent,
        Path("demo/chains"),
        Path("demo/out"),
        Path("demo/tmp/cache"),
        Path("demo/tmp/home"),
        Path("demo/tmp/vhs-tmp"),
        Path("examples/bin"),
        Path("modules/examples/bin"),
        Path("scripts"),
        Path("tools/demo"),
        Path("tools/docker/squatter-wine"),
    ):
        (repo / rel).mkdir(parents=True, exist_ok=True)

    install(args.tape, repo / args.tape_rel, executable=False)
    install(args.chain_file, repo / "demo/chains/mock-survey-exploit.chain.yaml", executable=False)
    install(args.setup_script, repo / "scripts/demo-step-setup.sh")
    install(args.tmux_script, repo / "scripts/demo-mcp-agent-tmux.sh")
    install(args.duration_checker, repo / "tools/demo/check_gif_duration.py")
    install(args.hovel_bin, repo / "demo/tmp/hovel")
    install(args.agent_bin, repo / "demo/tmp/hovel-mock-agent")
    install(args.mock_survey_go, repo / "modules/examples/bin/mock-survey-go")
    install(args.mock_exploit_session_go, repo / "modules/examples/bin/mock-exploit-session-go")
    write_module_config(
        repo / "modules/examples/hovel-modules.json",
        [
            {"id": "mock-survey-go", "runtime": "jsonrpc-stdio", "command": ["bin/mock-survey-go"]},
            {
                "id": "mock-exploit-session-go",
                "runtime": "jsonrpc-stdio",
                "command": ["bin/mock-exploit-session-go"],
            },
        ],
    )

    if args.wine:
        install(args.squatter_provider, repo / "modules/examples/bin/squatter-provider")
        install(args.squatter_exe, repo / "modules/examples/bin/squatter.exe")
        install(args.squatter_exe, repo / "examples/bin/squatter.exe")
        install(args.dockerfile, repo / "tools/docker/squatter-wine/Dockerfile", executable=False)
        install(args.docker_entrypoint, repo / "tools/docker/squatter-wine/entrypoint.sh")
        install(args.docker_runner, repo / "tools/docker/squatter-wine/run.sh")
        write_module_config(
            repo / "modules/examples/hovel-modules.json",
            [{"id": "squatter", "runtime": "jsonrpc-stdio", "command": ["bin/squatter-provider"]}],
        )
        image = os.environ.get("HOVEL_SQUATTER_WINE_IMAGE", "hovel/squatter-wine:latest")
        subprocess.run(
            ["docker", "build", "-t", image, "-f", str(repo / "tools/docker/squatter-wine/Dockerfile"), str(repo / "tools/docker/squatter-wine")],
            check=True,
        )
        os.environ["HOVEL_SQUATTER_WINE_BUILD"] = "0"


def install(src: Path, dest: Path, executable: bool = True) -> None:
    if not src.exists():
        raise SystemExit(f"missing path: {src}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    dest.chmod(0o755 if executable else 0o644)


def write_module_config(path: Path, modules: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"modules": modules}, indent=2) + "\n")


def write_chrome_wrapper(path: Path, chrome: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import sys\n"
        f"chrome = {chrome!r}\n"
        "flags = [\n"
        "    '--no-sandbox',\n"
        "    '--disable-dev-shm-usage',\n"
        "    '--disable-gpu',\n"
        "]\n"
        "os.execv(chrome, [chrome, *flags, *sys.argv[1:]])\n"
    )
    path.chmod(0o755)
    return path


def rendered_output(repo: Path, tape: Path) -> Path:
    for line in tape.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "Output":
            return (repo / parts[1]).resolve()
    raise SystemExit(f"could not find Output directive in {tape}")


def verify_vhs_version(vhs: str, version_file: Path | None) -> None:
    if not version_file:
        return
    expected = version_file.read_text().strip()
    actual = subprocess.run([vhs, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False).stdout
    if expected not in actual:
        raise SystemExit(f"expected VHS {expected}, got: {actual}")


def require_wine_inputs(args: argparse.Namespace) -> None:
    missing = [
        name
        for name in ("squatter_provider", "squatter_exe", "dockerfile", "docker_entrypoint", "docker_runner")
        if getattr(args, name) is None
    ]
    if missing:
        raise SystemExit(f"--wine requires: {', '.join('--' + item.replace('_', '-') for item in missing)}")


def require_command(name: str) -> None:
    if not shutil.which(name):
        raise SystemExit(f"{name} is required for VHS demo rendering")


def executable_path(path: Path) -> str:
    if path.is_file() and os.access(path, os.X_OK):
        return str(path.resolve())
    raise SystemExit(f"missing executable: {path}")


def tool_path(*prepend: Path) -> str:
    entries = [
        *[str(path) for path in prepend],
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/home/user/go/bin",
        "/home/runner/go/bin",
        "/home/user/.local/bin",
        "/home/runner/.local/bin",
    ]
    current = os.environ.get("PATH")
    if current:
        entries.append(current)
    return os.pathsep.join(entries)


if __name__ == "__main__":
    raise SystemExit(main())
