"""The single pinned Wine runtime shared by tests and demos."""
from __future__ import annotations

import os
from pathlib import Path
import re


def image_ref() -> str:
    value = Path(__file__).with_name("image.txt").read_text().strip()
    if not re.fullmatch(r"ghcr\.io/vibepwners/hovel-ci-wine@sha256:[a-f0-9]{64}", value):
        raise ValueError("Wine runtime must be pinned by digest")
    return os.environ.get("HOVEL_WINE_IMAGE", value)
