"""Rust link inputs and flags for Windows cross builds."""

_MINGW_AARCH64 = "//tools/windows_rust:llvm_mingw_aarch64_libs"
_MINGW_X86_64 = "//tools/windows_rust:llvm_mingw_x86_64_libs"

def windows_rust_compile_data():
    return select({
        "//platforms:is_windows_aarch64": [_MINGW_AARCH64],
        "//platforms:is_windows_x86_64": [_MINGW_X86_64],
        "//conditions:default": [],
    })

def _mingw_flags(label, emulation, builtins):
    lib_dir = "$(execpath {})/lib".format(label)
    clang_dir = "$(execpath {})/clang".format(label)
    return [
        "-Clink-arg=-m",
        "-Clink-arg={}".format(emulation),
        "-Clink-arg=-Bdynamic",
        "-Clink-arg={}/crt2.o".format(lib_dir),
        "-Clink-arg={}/crtbegin.o".format(lib_dir),
        "-Clink-arg=-L{}".format(lib_dir),
        "-Clink-arg=-L{}".format(clang_dir),
        "-Clink-arg=-lmingw32",
        "-Clink-arg={}/{}".format(clang_dir, builtins),
        "-Clink-arg=-lunwind",
        "-Clink-arg=-lmoldname",
        "-Clink-arg=-lmingwex",
        "-Clink-arg=-lmsvcrt",
        "-Clink-arg=-ladvapi32",
        "-Clink-arg=-lshell32",
        "-Clink-arg=-luser32",
        "-Clink-arg=-lkernel32",
        "-Clink-arg=-lmingw32",
        "-Clink-arg={}/{}".format(clang_dir, builtins),
        "-Clink-arg=-lunwind",
        "-Clink-arg=-lmoldname",
        "-Clink-arg=-lmingwex",
        "-Clink-arg=-lmsvcrt",
        "-Clink-arg=-lkernel32",
        "-Clink-arg={}/crtend.o".format(lib_dir),
    ]

def windows_rustc_flags():
    return select({
        "//platforms:is_windows_aarch64": _mingw_flags(
            _MINGW_AARCH64,
            "arm64pe",
            "libclang_rt.builtins-aarch64.a",
        ),
        "//platforms:is_windows_x86_64": _mingw_flags(
            _MINGW_X86_64,
            "i386pep",
            "libclang_rt.builtins-x86_64.a",
        ),
        "//conditions:default": [],
    })
