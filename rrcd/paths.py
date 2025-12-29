from __future__ import annotations

import os
from pathlib import Path


def default_rrcd_dir() -> Path:
    override = os.environ.get("RRCD_HOME")
    if override:
        return Path(override)
    return Path.home() / ".rrcd"


def default_config_path() -> Path:
    return default_rrcd_dir() / "rrcd.toml"


def default_identity_path() -> Path:
    return default_rrcd_dir() / "hub_identity"


def default_room_registry_path() -> Path:
    return default_rrcd_dir() / "rooms.toml"


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        # Best-effort tightening; may fail on some filesystems.
        os.chmod(path, 0o700)
    except Exception:
        pass
