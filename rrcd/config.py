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
    # Hex-encoded Reticulum identity hashes trusted as operators.
    trusted_identities: tuple[str, ...] = ()
    # Hex-encoded Reticulum identity hashes banned from connecting.
    banned_identities: tuple[str, ...] = ()

    # Room registry maintenance (registered rooms are stored in room_registry_path).
    # Pruning only applies to registered rooms with no connected members.
    room_registry_prune_after_s: float = 30 * 24 * 3600
    room_registry_prune_interval_s: float = 3600.0
    # Invite timeout for keyed rooms (+k). Invites are removed on join or expiry.
    room_invite_timeout_s: float = 900.0
    include_joined_member_list: bool = False
    max_rooms_per_session: int = 32
    max_room_name_len: int = 64
    rate_limit_msgs_per_minute: int = 240
    ping_interval_s: float = 0.0
    ping_timeout_s: float = 0.0
