"""Operate the Docker service through Aspect with a checked package lock."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from tools.wine.environment import image_ref

BASE = "ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
IMAGE = "ghcr.io/vibepwners/hovel-ci-wine"
RESOLVE = r"""
export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture i386
apt-get update >&2
apt-get install -y --no-install-recommends ca-certificates wget gnupg >&2
install -d -m 0755 /etc/apt/keyrings
wget -qO /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
wget -qNP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources
apt-get update >&2
apt-get --print-uris --yes --download-only --reinstall install $(dpkg-query -W -f='${binary:Package}\n') winehq-stable
"""


def download(package: dict, cache: Path) -> Path:
    expected = package.get("sha256")
    destination = cache / (expected or hashlib.sha256(package["url"].encode()).hexdigest())
    if destination.exists() and (not expected or hashlib.sha256(destination.read_bytes()).hexdigest() == expected):
        return destination
    for attempt in range(4):
        try:
            with urllib.request.urlopen(package["url"], timeout=180) as response:
                data = response.read()
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    digest = hashlib.sha256(data).hexdigest()
    if expected and expected != digest:
        raise ValueError("package checksum mismatch: " + package["filename"])
    destination.write_bytes(data)
    return destination


def validate_lock(lock: dict) -> None:
    if lock.get("schema_version") != "hovel.wine-image/v1" or not re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", lock.get("base", "")):
        raise ValueError("image base must be digest-pinned")
    seen = set()
    for package in lock["packages"]:
        filename = package["filename"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+%:~_-]*\.deb", filename) or filename in seen:
            raise ValueError("invalid or duplicate package filename")
        seen.add(filename)
        if not package["url"].startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}", package["sha256"]):
            raise ValueError("package must use HTTPS and SHA-256")
    if not seen:
        raise ValueError("empty package lock")


def resolve(cache: Path) -> dict:
    output = subprocess.check_output(["docker", "run", "--rm", "--platform=linux/amd64", BASE, "bash", "-ec", RESOLVE], text=True)
    packages = []
    for line in output.splitlines():
        match = re.match(r"'([^']+)' (\S+\.deb) (\d+) \S+", line)
        if match:
            url, filename, size = match.groups()
            # Ubuntu mirrors support TLS; do not retain plain HTTP package URLs.
            url = url.replace("http://", "https://", 1)
            packages.append({"url": url, "filename": filename, "size": int(size)})
    if not packages:
        raise ValueError("apt returned no package inputs")
    def pin(package):
        path = download(package, cache)
        package["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != package["size"]:
            raise ValueError("unexpected package size")
        path.rename(cache / package["sha256"])
        return package
    with ThreadPoolExecutor(max_workers=6) as pool:
        packages = list(pool.map(pin, packages))
    return {"schema_version": "hovel.wine-image/v1", "base": BASE, "packages": sorted(packages, key=lambda p: p["filename"])}


def build(root: Path, cache: Path, lock: dict, tag: str) -> None:
    with tempfile.TemporaryDirectory(prefix="hovel-wine-image-") as tmp:
        context = Path(tmp)
        packages = context / "packages"
        packages.mkdir()
        def stage(package):
            shutil.copyfile(download(package, cache), packages / package["filename"])
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(stage, lock["packages"]))
        shutil.copyfile(root / "modules/docker/squatter-wine/entrypoint.sh", context / "entrypoint.sh")
        dockerfile = (root / "tools/wine/image.Dockerfile").read_text().replace("@BASE@", lock["base"])
        (context / "Dockerfile").write_text(dockerfile)
        subprocess.run(["docker", "build", "--platform=linux/amd64", "--network=none", "--tag", tag, str(context)], check=True)


def registry_transfer(operation: str, image: str) -> None:
    """Use ephemeral GHCR credentials, preserving local Docker login otherwise."""
    env = dict(os.environ)
    token = env.pop("GITHUB_TOKEN", "")
    if operation == "push" and not token:
        raise ValueError("Publishing requires GITHUB_TOKEN")
    if token and image.startswith("ghcr.io/"):
        with tempfile.TemporaryDirectory(prefix="hovel-registry-auth-") as config:
            env["DOCKER_CONFIG"] = config
            subprocess.run(["docker", "login", "ghcr.io", "--username", env["GITHUB_ACTOR"], "--password-stdin"], input=token, text=True, env=env, check=True)
            subprocess.run(["docker", operation, image], env=env, check=True)
    else:
        subprocess.run(["docker", operation, image], env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["lock", "build", "publish", "verify", "prepare"])
    args = parser.parse_args()
    root = Path(os.environ["BUILD_WORKSPACE_DIRECTORY"])
    if args.operation == "prepare":
        image = image_ref()
        exists = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if not exists:
            registry_transfer("pull", image)
        print("Pinned Wine runtime:", image)
        return 0
    cache = Path(os.environ.get("HOVEL_IMAGE_CACHE", str(Path.home() / ".cache/hovel-wine-packages")))
    cache.mkdir(parents=True, exist_ok=True)
    path = root / "tools/wine/packages.lock.json"
    if args.operation == "lock":
        path.write_text(json.dumps(resolve(cache), indent=2) + "\n")
        print("Updated package lock")
        return 0
    lock = json.loads(path.read_text())
    validate_lock(lock)
    digest = hashlib.sha256(path.read_bytes() + (root / "tools/wine/image.Dockerfile").read_bytes() + (root / "modules/docker/squatter-wine/entrypoint.sh").read_bytes()).hexdigest()
    tag = IMAGE + ":inputs-" + digest
    if args.operation in ["build", "publish"]:
        build(root, cache, lock, tag)
    subprocess.run(["docker", "run", "--rm", "--network=none", "--entrypoint=wine", tag, "--version"], check=True)
    subprocess.run(["docker", "run", "--rm", "--network=none", "--entrypoint=/bin/test", tag, "-x", "/usr/local/bin/squatter-wine-entrypoint"], check=True)
    if args.operation == "publish":
        registry_transfer("push", tag)
        output = subprocess.check_output(["docker", "image", "inspect", "--format={{index .RepoDigests 0}}", tag], text=True).strip()
        if not re.fullmatch(IMAGE + r"@sha256:[a-f0-9]{64}", output):
            raise ValueError("registry did not return the expected digest")
        print("Published " + output)
        if destination := os.environ.get("GITHUB_OUTPUT"):
            with Path(destination).open("a") as f:
                f.write("image=" + output + "\n")
    print("Wine environment:", tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
