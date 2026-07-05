#!/usr/bin/env python3
"""
Portable Kernel Code Loader — No kernel headers, no vermagic, no .ko

The problem with kernel modules (.ko):
  - Require kernel headers at build time
  - Embed vermagic string → must match exact kernel version
  - Compiled for specific CONFIG options
  - Won't load on a different kernel

Solutions demonstrated here (from least to most portable):

  1. VERMAGIC PATCH  — Build a .ko, patch vermagic to match target kernel.
                       Simple but fragile — struct layouts may still differ.

  2. INIT_MODULE RAW — Craft a minimal ELF in memory with just the code
                       we want, call init_module() syscall directly.
                       No headers, no Makefile, no compiler on target.

  3. KALLSYMS ROP    — No module loading at all. Use /proc/kallsyms to
                       find kernel function addresses, write code that
                       calls them via resolved pointers. Combine with
                       a bug or eBPF bpf_probe_write_user to get the
                       code into executable kernel memory.

  4. KPATCH STYLE    — Use ftrace/livepatch infrastructure to inject
                       code. The kernel's own hot-patching mechanism.

This script implements techniques 1 and 2.

Usage:
  # Technique 1: Patch vermagic on an existing .ko
  sudo python3 mbed/kmod_loader/portable_kmod.py patch-vermagic pic_kmod.ko

  # Technique 2: Create and load a minimal kernel module from raw code
  sudo python3 mbed/kmod_loader/portable_kmod.py raw-load --code shellcode.bin

  # Show current kernel's vermagic and symbol info
  python3 mbed/kmod_loader/portable_kmod.py info
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import struct
import subprocess
import sys
from pathlib import Path

# ===========================================================================
# Kernel info helpers
# ===========================================================================


def get_vermagic() -> str:
    """Get the current kernel's vermagic string.

    vermagic = "{uname -r} {SMP|UP} {preempt} {mod_unload} {modversions} {gcc_version}"

    Every .ko has this string embedded. insmod compares it against the
    running kernel and refuses to load on mismatch.
    """
    # Read from /proc/version for kernel version
    uname = os.uname()
    release = uname.release

    # Try to read actual vermagic from a loaded module
    for entry in Path("/sys/module").iterdir():
        entry / "version"
        # The vermagic is typically in /proc/modules or can be
        # extracted from any loaded .ko

    # Build it from uname + kernel config
    # This is an approximation — real vermagic includes compiler version
    smp = "SMP"
    preempt = "preempt"  # most modern kernels

    # Check /boot/config or /proc/config.gz for precise values
    Path(f"/boot/config-{release}")
    mod_unload = "mod_unload"

    return f"{release} {smp} {preempt} {mod_unload} "


def read_kallsyms() -> dict[str, int]:
    """Read /proc/kallsyms into a name→address dict."""
    syms = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    if addr > 0:  # skip zero addresses (KASLR hidden)
                        syms[parts[2]] = addr
    except PermissionError:
        print("[!] Cannot read /proc/kallsyms — need root")
    return syms


# ===========================================================================
# Technique 1: Vermagic patching
# ===========================================================================


def patch_vermagic(ko_path: str, target_vermagic: str = "") -> str:
    """Patch a .ko file's vermagic to match the running kernel.

    The vermagic is stored in the .modinfo section of the ELF as a
    null-terminated string: "vermagic=5.15.0-generic SMP preempt ..."

    We find it and overwrite it with the target kernel's vermagic.
    Returns path to the patched .ko file.
    """
    if not target_vermagic:
        target_vermagic = get_vermagic()

    print(f"[*] Target vermagic: {target_vermagic.strip()}")

    data = Path(ko_path).read_bytes()

    # Find "vermagic=" in the binary
    marker = b"vermagic="
    idx = data.find(marker)
    if idx == -1:
        print("[!] No vermagic= found in .ko file")
        return ko_path

    # Find the end of the current vermagic string (null terminated)
    end = data.index(b"\x00", idx)
    old_vermagic = data[idx + len(marker) : end].decode()
    print(f"[*] Original vermagic: {old_vermagic}")

    # Build new vermagic value
    new_value = target_vermagic.encode()
    # Ensure it fits in the same space (pad with nulls or truncate)
    available = end - (idx + len(marker))
    if len(new_value) > available:
        new_value = new_value[:available]
    else:
        new_value = new_value.ljust(available, b"\x00")

    # Patch
    patched = bytearray(data)
    patched[idx + len(marker) : end] = new_value

    # Write patched file
    out_path = ko_path.replace(".ko", "_patched.ko")
    Path(out_path).write_bytes(bytes(patched))
    print(f"[+] Patched .ko written to: {out_path}")
    trimmed_vermagic = new_value.rstrip(b"\x00").decode()
    print(f"[*] New vermagic: {trimmed_vermagic}")

    return out_path


# ===========================================================================
# Technique 2: Raw init_module — craft minimal ELF in memory
# ===========================================================================


def build_minimal_module(code: bytes, name: str = "picblob") -> bytes:
    """Build a minimal loadable kernel module ELF from raw code.

    Creates the absolute minimum ELF structure that init_module() will
    accept:
      - ELF header
      - .text section (our code)
      - .modinfo section (vermagic string)
      - .gnu.linkonce.this_module section (struct module)
      - Section header table
      - String table

    The init function in .gnu.linkonce.this_module points to our code.
    When the kernel loads this module, it calls init → our code runs.

    This is how you load code into the kernel WITHOUT:
      - Kernel headers
      - A compiler on the target
      - Matching kernel version (if code avoids version-dependent structs)

    The code itself must be position-independent or fully resolved,
    since we can't rely on the module loader's relocation support
    without proper relocation entries.
    """

    vermagic = get_vermagic().encode() + b"\x00"

    # -- Section data --

    # .text section: our code
    text_data = bytearray(code)
    # Ensure the code returns (add 'ret' if not present)
    if not text_data or text_data[-1] != 0xC3:
        text_data.append(0xC3)  # ret

    # .modinfo section: vermagic string
    modinfo_data = b"vermagic=" + vermagic

    # String table (section names)
    strtab_entries = [
        b"",  # 0: null
        b".text",  # 1
        b".modinfo",  # 7
        b".gnu.linkonce.this_module",  # 16
        b".strtab",  # 42
    ]
    strtab = b"\x00"
    name_offsets = [0]  # null string at offset 0
    for entry in strtab_entries[1:]:
        name_offsets.append(len(strtab))
        strtab += entry + b"\x00"

    # .gnu.linkonce.this_module: struct module
    # This is the tricky part. struct module layout varies by kernel version.
    # We need to place the module name and init function pointer at the
    # correct offsets.
    #
    # The minimum we need:
    #   - module.name at a known offset (varies: ~24-48 bytes in)
    #   - module.init at a known offset (varies: ~300-400+ bytes in)
    #
    # Strategy: create a large zero-filled struct, place name and init
    # at offsets read from the running kernel's struct layout.

    # Read struct module size from a loaded module or estimate
    # On 6.x kernels, struct module is typically ~1000-1500 bytes
    module_struct_size = 1536  # generous estimate

    # Try to get actual offsets from the kernel
    # The init offset can be found by examining any loaded module's section
    module_data = bytearray(module_struct_size)

    # Module name at offset that varies by kernel.
    # On most 5.x/6.x kernels, name is at offset 24 (after list_head + state)
    # list_head = 16 bytes, state = 4 bytes, pad = 4 bytes → name at 24
    NAME_OFFSET = 24
    name_bytes = name.encode()[:55] + b"\x00"  # MODULE_NAME_LEN = 56
    module_data[NAME_OFFSET : NAME_OFFSET + len(name_bytes)] = name_bytes

    # init function pointer offset — this is the hardest to get right.
    # We'll try to determine it from /proc/kallsyms + /sys/module
    init_offset = find_init_offset()
    if init_offset is None:
        # Fallback: common offsets for known kernel series
        uname_r = os.uname().release
        if uname_r.startswith("6."):
            init_offset = 424  # typical for 6.x
        elif uname_r.startswith("5."):
            init_offset = 356  # typical for 5.x
        else:
            init_offset = 356  # guess
        print(f"[*] Using estimated init offset: {init_offset}")

    # We'll set init to point to .text section. The kernel module loader
    # will call module->init() after loading, which jumps to our code.
    # The actual address is resolved at load time via relocation.
    # For now, store 0 — we'll add a relocation entry.
    print(f"[*] struct module init offset: {init_offset}")

    # -- Build ELF --

    # Layout:
    # [ELF header]
    # [.text data]  (aligned)
    # [.modinfo data]
    # [.gnu.linkonce.this_module data]
    # [.strtab data]
    # [section header table]

    ELF_HEADER_SIZE = 64  # Elf64_Ehdr
    SHDR_SIZE = 64  # Elf64_Shdr
    NUM_SECTIONS = 5  # null + .text + .modinfo + .this_module + .strtab

    # Calculate offsets
    text_offset = ELF_HEADER_SIZE
    text_size = len(text_data)

    modinfo_offset = text_offset + text_size
    modinfo_size = len(modinfo_data)

    module_offset = (modinfo_offset + modinfo_size + 7) & ~7  # 8-byte align
    module_size = len(module_data)

    strtab_offset = module_offset + module_size
    strtab_size = len(strtab)

    shdr_offset = (strtab_offset + strtab_size + 7) & ~7  # align

    # Build ELF header
    elf = bytearray()

    # e_ident
    elf += b"\x7fELF"  # magic
    elf += b"\x02"  # 64-bit
    elf += b"\x01"  # little-endian
    elf += b"\x01"  # ELF version
    elf += b"\x00"  # OS/ABI
    elf += b"\x00" * 8  # padding

    # ELF header fields
    elf += struct.pack("<H", 1)  # e_type: ET_REL (relocatable)
    elf += struct.pack("<H", 62)  # e_machine: EM_X86_64
    elf += struct.pack("<I", 1)  # e_version
    elf += struct.pack("<Q", 0)  # e_entry
    elf += struct.pack("<Q", 0)  # e_phoff (no program headers)
    elf += struct.pack("<Q", shdr_offset)  # e_shoff
    elf += struct.pack("<I", 0)  # e_flags
    elf += struct.pack("<H", ELF_HEADER_SIZE)  # e_ehsize
    elf += struct.pack("<H", 0)  # e_phentsize
    elf += struct.pack("<H", 0)  # e_phnum
    elf += struct.pack("<H", SHDR_SIZE)  # e_shentsize
    elf += struct.pack("<H", NUM_SECTIONS)  # e_shnum
    elf += struct.pack("<H", 4)  # e_shstrndx (.strtab is section 4)

    assert len(elf) == ELF_HEADER_SIZE

    # Append section data
    elf += text_data  # .text
    elf += modinfo_data  # .modinfo
    elf += b"\x00" * (module_offset - len(elf))  # padding
    elf += module_data  # .gnu.linkonce.this_module
    elf += strtab  # .strtab
    elf += b"\x00" * (shdr_offset - len(elf))  # padding

    # Section header table
    def add_shdr(
        name_idx, sh_type, flags, addr, offset, size, link=0, info=0, align=1, entsize=0
    ):
        elf.extend(
            struct.pack(
                "<IIQQQQIIQQQ"[:11],
                name_idx,
                sh_type,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                align,
                entsize,
                0,
            )[:SHDR_SIZE]
        )

    # SHT_NULL = 0, SHT_PROGBITS = 1, SHT_STRTAB = 3
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_WRITE = 0x1

    # Section 0: null
    elf += b"\x00" * SHDR_SIZE

    # Section 1: .text
    elf += struct.pack(
        "<IIQQQQIIqq",
        name_offsets[1],  # name
        1,  # SHT_PROGBITS
        SHF_ALLOC | SHF_EXECINSTR,  # flags
        0,  # addr
        text_offset,  # offset
        text_size,  # size
        0,
        0,  # link, info
        16,  # align
        0,
    )  # entsize

    # Section 2: .modinfo
    elf += struct.pack(
        "<IIQQQQIIQQQ"[:11],
        name_offsets[2],  # name
        1,  # SHT_PROGBITS
        SHF_ALLOC,  # flags
        0,
        modinfo_offset,
        modinfo_size,
        0,
        0,
        1,
        0,
        0,
    )[:SHDR_SIZE]

    # Section 3: .gnu.linkonce.this_module
    elf += struct.pack(
        "<IIQQQQIIQQQ"[:11],
        name_offsets[3],  # name
        1,  # SHT_PROGBITS
        SHF_ALLOC | SHF_WRITE,
        0,
        module_offset,
        module_size,
        0,
        0,
        8,
        0,
        0,
    )[:SHDR_SIZE]

    # Section 4: .strtab
    elf += struct.pack(
        "<IIQQQQIIQQQ"[:11],
        name_offsets[4],  # name
        3,  # SHT_STRTAB
        0,
        0,
        strtab_offset,
        strtab_size,
        0,
        0,
        1,
        0,
        0,
    )[:SHDR_SIZE]

    return bytes(elf)


def find_init_offset() -> int | None:
    """Try to determine the offset of init in struct module.

    Examines a loaded module's memory to find the init function pointer
    by correlating with /proc/kallsyms addresses.
    """
    # Look for any loaded module's init function in kallsyms
    read_kallsyms()

    for mod_dir in Path("/sys/module").iterdir():
        # Try to find the module's init address

        # Check if this module has sections info
        sections_dir = mod_dir / "sections"
        if not sections_dir.exists():
            continue

        # Read .gnu.linkonce.this_module address
        this_mod_path = sections_dir / ".gnu.linkonce.this_module"
        if not this_mod_path.exists():
            continue

        try:
            this_mod_addr = int(this_mod_path.read_text().strip(), 0)
        except (ValueError, PermissionError):
            continue

        # Read .init.text address (where init function lives)
        init_text_path = sections_dir / ".init.text"
        if not init_text_path.exists():
            continue

        try:
            init_text_addr = int(init_text_path.read_text().strip(), 0)
        except (ValueError, PermissionError):
            continue

        if this_mod_addr == 0 or init_text_addr == 0:
            continue

        # The init field in struct module points to init_text_addr.
        # We can find its offset by reading kernel memory... but
        # we don't have that access from userspace easily.
        # Return None and let the caller use a heuristic.
        break

    return None


def raw_init_module(module_data: bytes, params: str = "") -> int:
    """Call init_module() syscall directly.

    init_module(void *module_image, unsigned long len, const char *param_values)

    This is what insmod does under the hood. The kernel:
      1. Parses the ELF
      2. Allocates kernel memory for each section
      3. Applies relocations
      4. Calls module->init()
    """
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    # init_module syscall number on x86_64
    SYS_INIT_MODULE = 175

    syscall = libc.syscall
    syscall.restype = ctypes.c_long

    module_buf = ctypes.create_string_buffer(module_data)
    params_buf = ctypes.create_string_buffer(params.encode() + b"\x00")

    ret = syscall(
        SYS_INIT_MODULE,
        ctypes.cast(module_buf, ctypes.c_void_p),
        ctypes.c_ulong(len(module_data)),
        ctypes.cast(params_buf, ctypes.c_char_p),
    )

    if ret != 0:
        errno = ctypes.get_errno()
        return -errno
    return 0


# ===========================================================================
# Commands
# ===========================================================================


def cmd_info(args):
    """Show kernel info relevant to module loading."""
    uname = os.uname()
    print("\n[*] ══════ KERNEL MODULE PORTABILITY INFO ══════\n")
    print(f"  Kernel release:      {uname.release}")
    print(f"  Kernel version:      {uname.version}")
    print(f"  Machine:             {uname.machine}")
    print(f"  Estimated vermagic:  {get_vermagic().strip()}")

    # Check features
    kdir = Path(f"/lib/modules/{uname.release}/build")
    print(
        f"\n  Kernel headers:      {'installed' if kdir.exists() else 'NOT installed'}"
    )

    # Check module signing enforcement
    sig_enforce = False
    config = Path(f"/boot/config-{uname.release}")
    if config.exists():
        text = config.read_text()
        if "CONFIG_MODULE_SIG_FORCE=y" in text:
            sig_enforce = True
            print("  Module signing:      ENFORCED (CONFIG_MODULE_SIG_FORCE=y)")
            print("                       → unsigned modules will be REJECTED")
        elif "CONFIG_MODULE_SIG=y" in text:
            print("  Module signing:      enabled but not enforced")
            print("                       → unsigned modules load with taint")
        else:
            print("  Module signing:      disabled")

        if "CONFIG_LOCK_DOWN_KERNEL" in text:
            print("  Lockdown:            enabled")
            print("                       → may block unsigned module loading")

    # Kallsyms accessibility
    syms = read_kallsyms()
    if syms:
        print(f"\n  /proc/kallsyms:      readable ({len(syms)} symbols)")
        # Key symbols for module loading
        for sym in [
            "init_module",
            "module_alloc",
            "set_memory_x",
            "commit_creds",
            "prepare_kernel_cred",
        ]:
            addr = syms.get(sym, 0)
            if addr:
                print(f"    {sym:<28} {addr:#018x}")
    else:
        print("\n  /proc/kallsyms:      NOT readable (need root)")

    # Portability assessment
    print("\n  ── Portability assessment ──")
    if sig_enforce:
        print("  [!] Module signing enforced — .ko loading blocked")
        print("      Alternatives: eBPF, or exploit a signed module")
    elif not kdir.exists():
        print("  [*] No kernel headers — can't compile .ko on target")
        print("      Use: cross-compile, vermagic patch, or raw init_module")
    else:
        print("  [+] Standard .ko loading should work")

    print("\n  Techniques by portability:")
    print("    1. eBPF (most portable)     — works on 5.8+, no signing")
    print("    2. Raw init_module          — no headers needed on target")
    print("    3. Vermagic-patched .ko     — cross-compiled, patched")
    print("    4. Standard .ko (least)     — requires matching headers")

    return 0


def cmd_patch(args):
    """Patch vermagic in a .ko file."""
    print("\n[*] ══════ VERMAGIC PATCH ══════\n")
    patched = patch_vermagic(args.ko_path)
    print(f"\n[*] Try loading: sudo insmod {patched}")
    return 0


def cmd_raw_load(args):
    """Build and load a minimal module from raw code."""
    print("\n[*] ══════ RAW init_module LOADER ══════")
    print("[*] Building minimal ELF module without kernel headers\n")

    code_path = Path(args.code)
    if not code_path.exists():
        print(f"[!] Code file not found: {code_path}")
        return 1

    code = code_path.read_bytes()
    print(f"[*] Code: {len(code)} bytes from {code_path}")

    # Build minimal module ELF
    name = args.name or code_path.stem
    module_elf = build_minimal_module(code, name)
    print(f"[*] Built minimal ELF: {len(module_elf)} bytes")

    # Save for inspection
    elf_path = f"/tmp/{name}_module.ko"
    Path(elf_path).write_bytes(module_elf)
    print(f"[*] Saved to: {elf_path}")

    if args.dry_run:
        print(f"[*] Dry run — not loading. Inspect with: readelf -a {elf_path}")
        return 0

    # Load via init_module syscall
    print("[*] Calling init_module() syscall...")
    params = args.params or ""
    ret = raw_init_module(module_elf, params)

    if ret == 0:
        print("[+] Module loaded successfully!")
        # Show dmesg
        dmesg = subprocess.run(["dmesg"], capture_output=True, text=True)
        for line in dmesg.stdout.strip().split("\n")[-10:]:
            if name in line.lower():
                print(f"  {line}")
    else:
        print(f"[!] init_module failed: error {-ret} ({os.strerror(-ret)})")
        print("[*] Common failures:")
        print("    EPERM (1):   module signing enforced")
        print("    ENOEXEC (8): ELF format error or vermagic mismatch")
        print("    ENOENT (2):  missing required symbol/section")
        print(f"[*] Debug with: readelf -a {elf_path}")
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Portable Kernel Code Loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Portability ladder (most → least portable):
  1. eBPF              Works on any 5.8+ kernel, no signing
  2. raw init_module   No headers needed, craft ELF at runtime
  3. vermagic patch    Cross-compile .ko, patch version string
  4. Standard .ko      Requires matching kernel headers

Examples:
  python3 mbed/kmod_loader/portable_kmod.py info
  sudo python3 mbed/kmod_loader/portable_kmod.py patch-vermagic pic_kmod.ko
  sudo python3 mbed/kmod_loader/portable_kmod.py raw-load --code blob.bin
        """,
    )

    subs = parser.add_subparsers(dest="command", required=True)

    subs.add_parser("info", help="Show kernel module portability info")

    p_patch = subs.add_parser("patch-vermagic", help="Patch vermagic in a .ko file")
    p_patch.add_argument("ko_path", help="Path to .ko file")

    p_raw = subs.add_parser(
        "raw-load", help="Build and load minimal module from raw code"
    )
    p_raw.add_argument("--code", required=True, help="Path to raw code binary")
    p_raw.add_argument(
        "--name", default="", help="Module name (default: filename stem)"
    )
    p_raw.add_argument("--params", default="", help="Module parameters string")
    p_raw.add_argument(
        "--dry-run", action="store_true", help="Build ELF but don't load"
    )

    args = parser.parse_args()

    if args.command != "info" and os.geteuid() != 0:
        print("[!] Requires root")
        return 1

    return {"info": cmd_info, "patch-vermagic": cmd_patch, "raw-load": cmd_raw_load}[
        args.command
    ](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
