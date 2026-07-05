# picblobs development environment — Fedora 43
#
# Always targets linux/amd64 — Bazel, Bootlin toolchains, and the
# cross-compiled blob runners are x86_64 binaries.  On Apple Silicon
# this runs under Rosetta / QEMU transparently via Docker Desktop.
#
# Build:
#   docker build --platform linux/amd64 -t picblobs-dev -f ci/Dockerfile .
#
# Run interactive:
#   docker run --platform linux/amd64 --rm -it -v "$PWD":/workspace picblobs-dev
#
# Run full CI check:
#   docker run --platform linux/amd64 --rm -v "$PWD":/workspace picblobs-dev bash -c \
#     'cd /workspace && python tools/generate.py --check && python tools/fmt.py --check && python tools/stage_blobs.py && python -m pytest python/tests/ -v'

# check=skip=FromPlatformFlagConstDisallowed
FROM --platform=linux/amd64 registry.fedoraproject.org/fedora:43

# Avoid interactive prompts during install.
ENV DNFP="dnf -y --setopt=install_weak_deps=False"

# ── System packages ──────────────────────────────────────────────
RUN $DNFP install \
        # Core build tools
        gcc gcc-c++ make patch \
        # Bazel runtime deps
        java-21-openjdk-headless zip unzip \
        # QEMU user-static for cross-arch blob execution
        qemu-user-static \
        # C linting and formatting
        clang-tools-extra \
        # Python (Fedora 43 ships 3.14)
        python3 python3-pip python3-devel \
        # General utilities
        git curl wget xz findutils diffutils which \
    && dnf clean all

# ── Bazel 9 ──────────────────────────────────────────────────────
ARG BAZEL_VERSION=9.0.1
RUN curl -fSL -o /usr/local/bin/bazel \
        "https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64" \
    && chmod +x /usr/local/bin/bazel \
    && bazel --version

# ── uv (fast Python package manager) ─────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# ── Python dev dependencies ──────────────────────────────────────
COPY python/pyproject.toml /tmp/pyproject.toml
COPY python/requirements.txt /tmp/requirements.txt
RUN pip install --break-system-packages \
        pyelftools pycparser pytest pygments ruff \
    && pip install --break-system-packages -r /tmp/requirements.txt \
    && rm /tmp/pyproject.toml /tmp/requirements.txt

# ── QEMU binfmt verification ─────────────────────────────────────
# Verify the QEMU binaries we need are present.
RUN for bin in \
        qemu-x86_64-static qemu-i386-static qemu-aarch64-static \
        qemu-arm-static qemu-mipsel-static qemu-mips-static \
        qemu-s390x-static; do \
        which "$bin" || echo "WARNING: $bin not found"; \
    done

# ── Bazel env ─────────────────────────────────────────────────────
# Bootlin toolchain SHA256 hashes are not yet pinned in MODULE.bazel.
# Allow unpinned fetches so Bazel can download the cross-compilers.
ENV PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS=1

# Let `python -m picblobs` and `import picblobs` work from the project root
# without requiring `cd python/` or `pip install -e`.
ENV PYTHONPATH=/workspace/python

# ── Non-root user ────────────────────────────────────────────────
# dev.sh maps the container UID/GID to match the host user so that
# files created inside the container are owned correctly on the host.
ARG UID=1000
ARG GID=1000
RUN groupadd -g "$GID" dev 2>/dev/null || true \
    && useradd -m -u "$UID" -g "$GID" -s /bin/bash dev
USER dev

# ── Workspace ─────────────────────────────────────────────────────
WORKDIR /workspace

CMD ["/bin/bash"]
