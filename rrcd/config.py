from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import HubService


@dataclass(frozen=True)
class HubRuntimeConfig:
    config_path: str | None = None
    room_registry_path: str | None = None
    configdir: str | None = None
    identity_path: str | None = None
    dest_name: str = "rrc.hub"
    announce_on_start: bool = True
    announce_period_s: float = 0.0
    hub_name: str = "rrc"
    greeting: str | None = None
    trusted_identities: tuple[str, ...] = ()
    banned_identities: tuple[str, ...] = ()
    room_registry_prune_after_s: float = 30 * 24 * 3600
    room_registry_prune_interval_s: float = 3600.0
    room_invite_timeout_s: float = 900.0
    include_joined_member_list: bool = False
    nick_max_chars: int = 32
    max_rooms_per_session: int = 32
    max_room_name_len: int = 64
    rate_limit_msgs_per_minute: int = 240
    ping_interval_s: float = 0.0
    ping_timeout_s: float = 0.0
    max_resource_bytes: int = 256 * 1024
    max_pending_resource_expectations: int = 8
    resource_expectation_ttl_s: float = 30.0
    enable_resource_transfer: bool = True
    log_level: str = "INFO"
    log_rns_level: str = "WARNING"
    log_console: bool = True
    log_file: str | None = None
    log_format: str = "%(asctime)s %(levelname)s %(name)s[%(threadName)s]: %(message)s"
    log_datefmt: str | None = None


class ConfigManager:
    """
    Manages hub configuration loading, reloading, and persistence.

    Handles:
    - Loading TOML configuration files
    - Applying configuration updates
    - Reloading configuration at runtime
    - Config diffing and comparison
    - Config file path resolution
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = hub.log
        self._write_lock = threading.Lock()

    def load_toml(self, path: str) -> dict:
        """Load a TOML file and return its contents as a dictionary."""
        import tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data if isinstance(data, dict) else {}

    def apply_config_data(self, base: HubRuntimeConfig, data: dict) -> HubRuntimeConfig:
        """Apply configuration data from TOML to a runtime config instance."""
        hub = data.get("hub") if isinstance(data, dict) else None
        if isinstance(hub, dict):
            data = {**data, **hub}

        log_table = data.get("logging") if isinstance(data, dict) else None
        if isinstance(log_table, dict):
            mapped: dict[str, object] = {}
            if "level" in log_table:
                mapped["log_level"] = log_table.get("level")
            if "rns_level" in log_table:
                mapped["log_rns_level"] = log_table.get("rns_level")
            if "console" in log_table:
                mapped["log_console"] = log_table.get("console")
            if "file" in log_table:
                mapped["log_file"] = log_table.get("file")
            if "format" in log_table:
                mapped["log_format"] = log_table.get("format")
            if "datefmt" in log_table:
                mapped["log_datefmt"] = log_table.get("datefmt")
            data = {**data, **mapped}

        allowed = set(asdict(base).keys())
        allowed.discard("config_path")

        updates = {k: v for k, v in data.items() if k in allowed}

        for list_key in ("trusted_identities", "banned_identities"):
            if list_key in updates and isinstance(updates[list_key], list):
                updates[list_key] = tuple(str(x) for x in updates[list_key])

        if "announce" in data and "announce_on_start" not in updates:
            try:
                updates["announce_on_start"] = bool(data["announce"])
            except Exception:
                pass
        if "configdir" in updates and updates["configdir"] == "":
            updates["configdir"] = None
        if "greeting" in updates and updates["greeting"] == "":
            updates["greeting"] = None
        if "log_file" in updates and updates["log_file"] == "":
            updates["log_file"] = None
        if "log_datefmt" in updates and updates["log_datefmt"] == "":
            updates["log_datefmt"] = None

        return replace(base, **updates) if updates else base

    def format_reload_value(self, v: Any) -> str:
        """Format a config value for display in reload summaries."""
        if v is None:
            return "(none)"
        if isinstance(v, (bool, int, float)):
            return str(v)
        if isinstance(v, (tuple, list, set)):
            return f"len={len(v)}"
        s = str(v)
        s = " ".join(s.split())
        if len(s) > 80:
            s = s[:77] + "..."
        return s

    def diff_config_summary(
        self, old: HubRuntimeConfig, new: HubRuntimeConfig
    ) -> list[str]:
        """Generate a summary of differences between two config instances."""
        old_d = asdict(old)
        new_d = asdict(new)
        old_d.pop("config_path", None)
        new_d.pop("config_path", None)

        changed: list[str] = []
        for k in sorted(new_d.keys()):
            if old_d.get(k) == new_d.get(k):
                continue
            changed.append(
                f"{k}: {self.format_reload_value(old_d.get(k))} -> {self.format_reload_value(new_d.get(k))}"
            )
        return changed

    def get_config_path_for_writes(self) -> str | None:
        """Get the resolved config file path for write operations."""
        from .util import expand_path

        p = self.hub.config.config_path
        if not p:
            return None
        return expand_path(str(p))

    def get_write_lock(self) -> threading.Lock:
        """Get the lock used for config file write operations."""
        return self._write_lock
