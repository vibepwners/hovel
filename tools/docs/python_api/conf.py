from __future__ import annotations

import os
import sys
from pathlib import Path


repo_root = Path(os.environ.get("HOVEL_DOCS_REPO_ROOT", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(repo_root / "sdk/python"))

project = "Hovel Python SDK"
author = "Hovel"
copyright = "2026, Hovel"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
    "undoc-members": True,
}
autodoc_member_order = "bysource"
autodoc_typehints = "signature"
html_theme = "alabaster"
html_title = "Hovel Python SDK API"
html_static_path: list[str] = []
templates_path: list[str] = []
