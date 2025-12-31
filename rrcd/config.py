from __future__ import annotations

from dataclasses import dataclass


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
    max_resource_bytes: int = 256 * 1024  # 256 KiB default
    max_pending_resource_expectations: int = 8
    resource_expectation_ttl_s: float = 30.0
    enable_resource_transfer: bool = True
    log_level: str = "INFO"
    log_rns_level: str = "WARNING"
    log_console: bool = True
    log_file: str | None = None
    log_format: str = "%(asctime)s %(levelname)s %(name)s[%(threadName)s]: %(message)s"
    log_datefmt: str | None = None
