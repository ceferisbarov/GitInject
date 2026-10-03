"""Make repository CLI declarations importable in documentation-only builds."""

import sys
from pathlib import Path


def on_config(config):
    root = str(Path(config.config_file_path).resolve().parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    return config
