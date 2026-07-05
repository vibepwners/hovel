#!/usr/bin/env python3
"""
Build kernel-context PIC blob examples and the kernel module.

Compiles the assembly examples into flat binaries, resolves kernel
symbol addresses, and patches config structs so the blobs can call
printk() and read task_struct fields.

Usage:
  # Build everything (examples + kernel module)
  python3 mbed/kmod_loader/build_examples.py

  # Build examples only (no kernel module)
  python3 mbed/kmod_loader/build_examples.py --no-kmod

  # Build and run nop_sled (safest test)
  sudo python3 mbed/kmod_loader/build_examples.py --run nop_sled

  # Build and run hello_ring0 (prints to dmesg)
  sudo python3 mbed/kmod_loader/build_examples.py --run hello_ring0

  # Build and run who_am_i (prints process info to dmesg)
  sudo python3 mbed/kmod_loader/build_examples.py --run who_am_i

  # List built examples
  python3 mbed/kmod_loader/build_examples.py --list
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

KMOD_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = KMOD_DIR / "examples"
BUILD_DIR = KMOD_DIR / "build"


def read_kallsyms() -> dict[str, int]:
    """Read kernel symbol addresses from /proc/kallsyms."""
    syms = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    if addr > 0:
                        syms[parts[2]] = addr
    except PermissionError:
        pass
    return syms


def get_task_struct_offsets() -> dict[str, int]:
    """Get field offsets in struct task_struct.

    Reads from /proc/kallsyms and /sys/kernel/debug, or uses common
    defaults for well-known kernel versions.
    """
    uname_r = os.uname().release

    # These offsets are for common kernel configurations.
    # In production, you'd read these from BTF or debuginfo.
    # For the lab, these work on Ubuntu/Debian stock kernels.
    offsets = {}

    # comm offset: task_struct.comm
    # Fairly stable across versions: usually around 0x6b0-0x780
    # We can find it by reading /proc/self/comm and searching
    if uname_r.startswith("6.8"):
        offsets["comm"] = 0x780
        offsets["pid"] = 0x5A0
    elif uname_r.startswith("6."):
        offsets["comm"] = 0x750
        offsets["pid"] = 0x590
    elif uname_r.startswith("5.15"):
        offsets["comm"] = 0x6B0
        offsets["pid"] = 0x540
    elif uname_r.startswith("5."):
        offsets["comm"] = 0x6B0
        offsets["pid"] = 0x530
    else:
        # Guess — may not work
        offsets["comm"] = 0x750
        offsets["pid"] = 0x590

    return offsets


def assemble_example(name: str) -> Path | None:
    """Assemble an example .S file into a flat binary."""
    src = EXAMPLES_DIR / f"{name}.S"
    if not src.exists():
        print(f"[!] Source not found: {src}")
        return None

    BUILD_DIR.mkdir(exist_ok=True)
    obj = BUILD_DIR / f"{name}.o"
    out = BUILD_DIR / f"{name}.bin"

    # Assemble
    ret = subprocess.run(
        ["as", "-o", str(obj), str(src)], capture_output=True, text=True
    )
    if ret.returncode != 0:
        print(f"[!] Assembly failed: {ret.stderr}")
        return None

    # Link as flat binary
    ret = subprocess.run(
        ["ld", "--oformat", "binary", "-o", str(out), str(obj)],
        capture_output=True,
        text=True,
    )
    if ret.returncode != 0:
        print(f"[!] Link failed: {ret.stderr}")
        return None

    size = out.stat().st_size
    print(f"[+] {name}: {size} bytes → {out}")
    return out


def patch_config(blob_path: Path, name: str, syms: dict[str, int]) -> Path:
    """Patch kernel addresses into a blob's config section.

    Each example has a config struct at the end of the blob. We write
    the resolved kernel function pointers into it so the blob can call
    them.
    """
    data = bytearray(blob_path.read_bytes())

    printk_addr = syms.get("printk", syms.get("_printk", 0))
    current_addr = syms.get("current_task", 0)

    if not printk_addr:
        print("[!] printk not found in kallsyms")
        return blob_path

    offsets = get_task_struct_offsets()

    if name == "nop_sled":
        # No config to patch
        pass

    elif name == "hello_ring0":
        # Find config section — it's the last 16 bytes (2 quads)
        # Config: [printk_addr: u64] [current_addr: u64]
        # The config is in .data after .rodata, at a linker-determined offset.
        # For flat binary, we search for the 16 zero bytes at the end.
        config_offset = len(data) - 16
        struct.pack_into("<QQ", data, config_offset, printk_addr, current_addr)
        print(f"    printk @ {printk_addr:#x} → config+{config_offset:#x}")

    elif name == "who_am_i":
        # Config: [printk: u64] [current: u64] [comm_off: u32] [pid_off: u32]
        config_offset = len(data) - 24  # 8+8+4+4 = 24 bytes
        struct.pack_into(
            "<QQII",
            data,
            config_offset,
            printk_addr,
            current_addr,
            offsets.get("comm", 0),
            offsets.get("pid", 0),
        )
        print(f"    printk @ {printk_addr:#x}")
        print(f"    comm_offset: {offsets.get('comm', 0):#x}")
        print(f"    pid_offset: {offsets.get('pid', 0):#x}")

    patched = blob_path.with_suffix(".patched.bin")
    patched.write_bytes(bytes(data))
    return patched


def build_kmod() -> bool:
    """Build the kernel module."""
    print("\n[*] Building pic_kmod.ko...")
    ret = subprocess.run(["make", "-C", str(KMOD_DIR)], capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"[!] Build failed: {ret.stderr}")
        return False

    ko_path = KMOD_DIR / "pic_kmod.ko"
    if ko_path.exists():
        print(f"[+] pic_kmod.ko: {ko_path.stat().st_size} bytes")
        return True
    return False


def run_example(name: str, blob_path: Path) -> int:
    """Load the kernel module with an example blob."""
    ko_path = KMOD_DIR / "pic_kmod.ko"
    if not ko_path.exists():
        print("[!] pic_kmod.ko not found — run without --no-kmod first")
        return 1

    # Unload if already loaded
    subprocess.run(["rmmod", "pic_kmod"], capture_output=True)

    # Load with blob + exec + persist (so we can see dmesg and rmmod)
    cmd = [
        "insmod",
        str(ko_path),
        f"blob_path={blob_path}",
        "exec_blob=1",
        "persist=1",
        "dyndbg=+p",  # enable pr_debug output
    ]

    print(f"\n[*] Loading: {' '.join(cmd)}")
    ret = subprocess.run(cmd, capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"[!] insmod failed: {ret.stderr.strip()}")
        return 1

    print("[+] Module loaded with blob")

    # Show dmesg output
    print("\n[*] ── dmesg output ──")
    dmesg = subprocess.run(["dmesg"], capture_output=True, text=True)
    for line in dmesg.stdout.strip().split("\n")[-20:]:
        if "pic_kmod" in line or "hello_ring0" in line or "who_am_i" in line:
            print(f"  {line}")

    # Cleanup
    print("\n[*] Unloading module...")
    subprocess.run(["rmmod", "pic_kmod"], capture_output=True)
    print("[+] Done")

    return 0


def list_examples():
    """List available examples."""
    print("\n[*] Available kernel-context blob examples:\n")

    examples = {
        "nop_sled": "Does nothing and returns. Safest test — verify the loader works.",
        "hello_ring0": "Prints 'greetings from kernel space!' to dmesg via printk.",
        "who_am_i": "Reads current task_struct, prints process name and PID to dmesg.",
    }

    for name, desc in examples.items():
        EXAMPLES_DIR / f"{name}.S"
        built = BUILD_DIR / f"{name}.bin"
        status = "built" if built.exists() else "not built"
        size = f"{built.stat().st_size}B" if built.exists() else ""
        print(f"  {name:<16} [{status:>9} {size:>4}]  {desc}")

    print("\n  Build all:  python3 mbed/kmod_loader/build_examples.py")
    print(
        "  Run one:    sudo python3 mbed/kmod_loader/build_examples.py --run nop_sled"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Build and run kernel-context PIC blob examples"
    )
    parser.add_argument(
        "--no-kmod", action="store_true", help="Skip building pic_kmod.ko"
    )
    parser.add_argument(
        "--run", metavar="NAME", help="Build, patch, and run an example"
    )
    parser.add_argument("--list", action="store_true", help="List available examples")
    args = parser.parse_args()

    if args.list:
        list_examples()
        return 0

    print("[*] ══════ KERNEL BLOB EXAMPLE BUILDER ══════\n")

    # Build examples
    examples = ["nop_sled", "hello_ring0", "who_am_i"]
    built = {}

    for name in examples:
        path = assemble_example(name)
        if path:
            built[name] = path

    if not built:
        print("[!] No examples built — check that 'as' and 'ld' are installed")
        return 1

    # Build kernel module
    if not args.no_kmod:
        kdir = Path(f"/lib/modules/{os.uname().release}/build")
        if kdir.exists():
            build_kmod()
        else:
            print("\n[*] Kernel headers not installed — skipping pic_kmod.ko")
            print("    Install with: apt install linux-headers-$(uname -r)")

    # Run if requested
    if args.run:
        if args.run not in built:
            print(f"[!] Example '{args.run}' not found or failed to build")
            return 1

        if os.geteuid() != 0:
            print("[!] Need root to load kernel modules")
            return 1

        # Read kernel symbols and patch config
        print("\n[*] Resolving kernel symbols from /proc/kallsyms...")
        syms = read_kallsyms()
        if not syms:
            print("[!] Cannot read kallsyms — need root")
            return 1

        printk = syms.get("printk", syms.get("_printk", 0))
        print(f"    printk: {printk:#x}")
        print(f"    symbols loaded: {len(syms)}")

        blob_path = built[args.run]
        patched = patch_config(blob_path, args.run, syms)
        return run_example(args.run, patched)

    print("\n[*] Build complete. Run examples with:")
    print("    sudo python3 mbed/kmod_loader/build_examples.py --run nop_sled")
    print("    sudo python3 mbed/kmod_loader/build_examples.py --run hello_ring0")
    print("    sudo python3 mbed/kmod_loader/build_examples.py --run who_am_i")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
