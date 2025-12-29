from __future__ import annotations

import os


def expand_path(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))
