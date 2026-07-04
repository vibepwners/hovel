#!/usr/bin/env python3
"""Check generated VHS GIFs stay short enough for the documentation site."""

from __future__ import annotations

import argparse
import pathlib
import sys


MAX_SECONDS = 30.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gif", nargs="+", type=pathlib.Path)
    parser.add_argument("--max-seconds", type=float, default=MAX_SECONDS)
    args = parser.parse_args()

    for path in args.gif:
        if path.suffix.lower() != ".gif":
            continue
        duration = gif_duration_seconds(path)
        print(f"{path}: {duration:.2f}s")
        if duration > args.max_seconds:
            print(
                f"warning: {path} runs {duration:.2f}s, over the {args.max_seconds:.0f}s "
                "GIF duration guideline",
                file=sys.stderr,
            )
    return 0


def gif_duration_seconds(path: pathlib.Path) -> float:
    data = path.read_bytes()
    if len(data) < 13 or data[:3] != b"GIF":
        raise ValueError(f"{path} is not a GIF")

    duration_cs = 0
    index = 13

    if data[10] & 0x80:
        index += 3 * (2 ** ((data[10] & 0x07) + 1))

    def skip_sub_blocks(offset: int) -> int:
        while offset < len(data):
            block_size = data[offset]
            offset += 1
            if block_size == 0:
                return offset
            offset += block_size
        raise ValueError(f"{path} has unterminated GIF sub-blocks")

    while index < len(data):
        block_type = data[index]
        index += 1
        if block_type == 0x3B:
            break
        if block_type == 0x21:
            if index >= len(data):
                raise ValueError(f"{path} has truncated extension block")
            label = data[index]
            index += 1
            if label == 0xF9:
                if index >= len(data):
                    raise ValueError(f"{path} has truncated graphics control block")
                block_size = data[index]
                index += 1
                if block_size != 4 or index + block_size > len(data):
                    raise ValueError(f"{path} has invalid graphics control block")
                duration_cs += int.from_bytes(data[index + 1 : index + 3], "little")
                index += block_size
                if index >= len(data) or data[index] != 0:
                    raise ValueError(f"{path} has unterminated graphics control block")
                index += 1
            else:
                index = skip_sub_blocks(index)
            continue
        if block_type == 0x2C:
            if index + 9 >= len(data):
                raise ValueError(f"{path} has truncated image descriptor")
            packed = data[index + 8]
            index += 9
            if packed & 0x80:
                index += 3 * (2 ** ((packed & 0x07) + 1))
            if index >= len(data):
                raise ValueError(f"{path} has truncated image data")
            index += 1
            index = skip_sub_blocks(index)
            continue
        raise ValueError(f"{path} has unknown GIF block type 0x{block_type:02x}")

    return duration_cs / 100.0


if __name__ == "__main__":
    raise SystemExit(main())
