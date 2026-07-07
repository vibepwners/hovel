"""Shared C compiler flags for first-party code (used by //src and //examples).

The strict surface applies to *our* code only; platform headers arrive through
the toolchain's builtin (system) include dirs and are exempt. See
docs/C_STYLE_GUIDE.md for the rationale behind each warning.
"""

SQ_COPTS = [
    "-std=c11",
    "-D_WIN32_WINNT=0x0501",  # Windows XP SP3 API floor
    "-DUNICODE",  # this is a wide (UTF-16) application: generic
    "-D_UNICODE",  # Win32 macros resolve to their ...W variants
    "-DDECLSPEC_IMPORT=",  # calls bind to local stubs unless a binary opts into import libs
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wshadow",
    "-Wcast-qual",
    "-Wstrict-prototypes",
    "-Wmissing-prototypes",
    "-Wmissing-declarations",
    "-Wredundant-decls",
    "-Wpointer-arith",
    "-Wwrite-strings",
    "-Wundef",
    "-Wvla",
    "-Wstrict-overflow=5",
    "-Werror",
]
