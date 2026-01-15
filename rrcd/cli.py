from __future__ import annotations

import argparse
import os
import sys
from dataclasses import asdict, replace
from pathlib import Path

import RNS

from .config import HubRuntimeConfig
from .logging_config import configure_logging
from .paths import (
    default_config_path,
    default_identity_path,
    default_room_registry_path,
    ensure_private_dir,
)
from .service import HubService


def _load_toml(path: str) -> dict:
    import tomllib

    with open(path, "rb") as f:
        return tomllib.load(f)


def _apply_config_file(cfg: HubRuntimeConfig, path: str) -> HubRuntimeConfig:
    data = _load_toml(path)

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

    allowed = set(asdict(cfg).keys())
    # This identifies where to reload/persist from; do not let the file override it.
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
    return replace(cfg, **updates) if updates else cfg


def _write_default_config(config_path: str, identity_path: str) -> None:
    cfg_dir = os.path.dirname(config_path)
    if cfg_dir:
        ensure_private_dir(Path(cfg_dir))

    storage_dir = os.path.dirname(identity_path)
    if storage_dir:
        ensure_private_dir(Path(storage_dir))

    room_registry_path = str(default_room_registry_path())

    content = f"""# rrcd configuration (TOML)
#
# This file was created on first run.
# Edit it, then start rrcd again.

[hub]

# Optional: Reticulum configuration directory.
# If left unset, Reticulum will choose its default (usually ~/.reticulum).
configdir = ""

# Where rrcd stores its persistent identity (Reticulum Identity file).
identity_path = {identity_path!r}

# Separate room registry file (registered rooms, topics, modes, bans, etc).
# This file is maintained by rrcd. You can edit it manually, but keep it valid TOML.
# A running hub can reload both rrcd.toml and rooms.toml with the /reload command.
room_registry_path = {room_registry_path!r}

# Destination name to host the hub on.
dest_name = "rrc.hub"

# Announcing (Reticulum destination announces)
#
# announce_on_start: send a single announce right after startup.
# announce_period_s: if >0, periodically re-announce.
# To disable announcing entirely, set:
#   announce_on_start = false
#   announce_period_s = 0.0
announce_on_start = true
announce_period_s = 0.0

# Hub identity fields.
hub_name = "rrc"
greeting = ""

# Note: The hub 'greeting' is the MOTD (message of the day) delivered after WELCOME.
# If it exceeds the link MTU, it will be sent via RNS.Resource for reliable transfer.

# Operator / moderation
#
# trusted_identities: list of Reticulum Identity hashes (hex) allowed to run
# operator commands.
# banned_identities: list of Identity hashes (hex) that will be disconnected.
trusted_identities = []
banned_identities = []

# Registered-room pruning.
# Only applies to registered rooms with no connected members.
room_registry_prune_after_s = {30 * 24 * 3600}
room_registry_prune_interval_s = 3600.0

# Keyed-room invites.
# Room operators can use /invite to let a user join a +k room without the key.
# Invites are removed on join or after this timeout.
room_invite_timeout_s = 900.0

# Optional behaviors.
include_joined_member_list = false

# Nickname policy.
# Maximum accepted nickname length (Unicode characters). 0 disables length limiting.
nick_max_chars = 32

# Limits.
# These limits help mitigate abuse and resource exhaustion, but can be adjusted
# based on your use case.
#
# N.B. max_msg_body_bytes should not allow messages so large that they cannot
# fit within the link MTU after UTF-8 encoding and envelope overhead. The
# default of 350 bytes is a safe choice for the default Reticulum MTU of 500.
max_rooms_per_session = 32
max_room_name_len = 64
max_msg_body_bytes = 350
rate_limit_msgs_per_minute = 240

# Hub-initiated liveness checks (0 disables).
ping_interval_s = 0.0
ping_timeout_s = 0.0

# Large payload transfer via RNS.Resource
#
# When a message exceeds the link MTU, rrcd can use RNS.Resource for reliable
# transfer instead of manual chunking. A small RESOURCE_ENVELOPE is sent first,
# followed by the payload as an RNS.Resource.
#
# enable_resource_transfer: enable/disable feature (default: true)
# max_resource_bytes: maximum size for a single resource (default: 256 KiB)
# max_pending_resource_expectations: max pending expectations per link (default: 8)
# resource_expectation_ttl_s: how long to wait for announced resource (default: 30s)
enable_resource_transfer = true
max_resource_bytes = 262144
max_pending_resource_expectations = 8
resource_expectation_ttl_s = 30.0

[logging]

# Log level for rrcd itself.
level = "INFO"

# Log level for Reticulum/RNS Python logging (if used by your install).
rns_level = "WARNING"

# Log to stderr (systemd/journald friendly).
console = true

# Optional file path for logs (leave empty to disable).
file = ""

# Log format and optional date format.
format = "%(asctime)s %(levelname)s %(name)s[%(threadName)s]: %(message)s"
datefmt = ""
"""

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(content)


def _ensure_first_run_files(
    config_path: str, identity_path: str, room_registry_path: str
) -> bool:
    created_any = False

    if not os.path.exists(config_path):
        _write_default_config(config_path, identity_path)
        created_any = True

    if not os.path.exists(identity_path):
        storage_dir = os.path.dirname(identity_path)
        if storage_dir:
            ensure_private_dir(Path(storage_dir))
        ident = RNS.Identity()
        ident.to_file(identity_path)
        try:
            os.chmod(identity_path, 0o600)
        except Exception:
            pass
        created_any = True

    if room_registry_path and not os.path.exists(room_registry_path):
        storage_dir = os.path.dirname(room_registry_path)
        if storage_dir:
            ensure_private_dir(Path(storage_dir))
        content = """# rrcd room registry (TOML)
#
# This file stores registered rooms and their moderation state.
# It is maintained by rrcd and may be updated while rrcd is running.
#
# Schema
# ------
#
# Each registered room is a table under [rooms]. Room names are TOML keys.
# If your room name contains spaces or punctuation, quote it:
#
#   [rooms."my room"]
#
# Supported keys per room:
#
# - founder:      string, hex Reticulum Identity hash
# - topic:        string (optional)
# - moderated:    bool (defaults false)
# - operators:    list of string identity hashes (hex)
# - voiced:       list of string identity hashes (hex)
# - bans:         list of string identity hashes (hex)
# - invited:      table mapping identity hash (hex) -> expiry unix timestamp seconds
# - last_used_ts: float unix timestamp seconds (used for pruning; optional)
#
# Example
# -------
#
# [rooms."lobby"]
# founder = "0123abcd..."
# topic = "Welcome"
# moderated = false
# operators = ["0123abcd..."]
# voiced = []
# bans = []
# invited = { "89abcdef..." = 1730003600.0 }
# last_used_ts = 1730000000.0

[rooms]
"""
        with open(room_registry_path, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.chmod(room_registry_path, 0o600)
        except Exception:
            pass
        created_any = True

    return created_any


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rrcd", description="Run an RRC hub daemon")

    p.add_argument(
        "--config",
        default=str(default_config_path()),
        help="Path to a TOML config file (created on first run)",
    )
    p.add_argument("--configdir", default=None, help="Reticulum config directory")

    p.add_argument(
        "--identity",
        default=str(default_identity_path()),
        help="Path to hub identity file (created on first run)",
    )

    p.add_argument(
        "--room-registry",
        default=str(default_room_registry_path()),
        help="Path to separate room registry TOML (created on first run)",
    )
    p.add_argument(
        "--dest-name", default=None, help="Destination app name (default: rrc.hub)"
    )

    p.add_argument(
        "--no-announce",
        action="store_true",
        help="Disable announce on start (does not affect periodic announce)",
    )
    p.add_argument(
        "--announce-period",
        type=float,
        default=None,
        help="Periodic announce interval seconds (0 disables)",
    )

    p.add_argument("--hub-name", default=None, help="Hub name in WELCOME")
    p.add_argument(
        "--greeting",
        default=None,
        help="Greeting delivered via NOTICE after WELCOME",
    )
    p.add_argument(
        "--include-joined-member-list",
        action="store_true",
        help="Include member list in JOINED (best-effort)",
    )

    p.add_argument("--max-rooms", type=int, default=None, help="Max rooms per session")
    p.add_argument(
        "--max-room-name-len", type=int, default=None, help="Max room name length"
    )

    p.add_argument(
        "--rate-limit-msgs-per-minute",
        type=int,
        default=None,
        help="Per-link message rate limit",
    )
    p.add_argument(
        "--max-msg-body-bytes",
        type=int,
        default=None,
        help="Maximum message body size in UTF-8 bytes",
    )

    p.add_argument(
        "--ping-interval",
        type=float,
        default=None,
        help="Hub-initiated PING interval seconds (0 disables)",
    )
    p.add_argument(
        "--ping-timeout",
        type=float,
        default=None,
        help="Close link if PONG not received within this many seconds (0 disables)",
    )

    p.add_argument(
        "--log-level",
        default=None,
        help="Logging level override (DEBUG, INFO, WARNING, ERROR). Default comes from config.",
    )

    p.add_argument(
        "--log-file",
        default=None,
        help="Log file path override (empty disables file logging). Default comes from config.",
    )

    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_arg_parser().parse_args(sys.argv[1:] if argv is None else argv)

    config_path = str(args.config)
    identity_path = str(args.identity)
    room_registry_path = str(args.room_registry)

    if _ensure_first_run_files(config_path, identity_path, room_registry_path):
        print(
            "Created default rrcd files. Edit the configuration before starting:\n"
            f"- Config:   {config_path}\n"
            f"- Identity: {identity_path}\n"
            f"- Rooms:    {room_registry_path}\n"
            "\nThen re-run rrcd.",
            file=sys.stderr,
        )
        raise SystemExit(0)

    cfg = HubRuntimeConfig(configdir=args.configdir, identity_path=identity_path)
    cfg = replace(cfg, config_path=config_path)
    cfg = replace(cfg, room_registry_path=room_registry_path)

    # Use ConfigManager to load config file
    if config_path:
        from .config import ConfigManager

        # Create temporary manager for loading
        temp_hub = type(
            "obj", (object,), {"config": cfg, "log": None, "_state_lock": None}
        )()
        temp_mgr = ConfigManager(temp_hub)  # type: ignore
        data = temp_mgr.load_toml(config_path)
        cfg = temp_mgr.apply_config_data(cfg, data)

    if args.dest_name is not None:
        cfg = replace(cfg, dest_name=args.dest_name)

    if args.no_announce:
        cfg = replace(cfg, announce_on_start=False)
    if args.announce_period is not None:
        cfg = replace(cfg, announce_period_s=float(args.announce_period))

    if args.hub_name is not None:
        cfg = replace(cfg, hub_name=args.hub_name)
    if args.greeting is not None:
        cfg = replace(cfg, greeting=args.greeting)

    if args.include_joined_member_list:
        cfg = replace(cfg, include_joined_member_list=True)

    if args.max_rooms is not None:
        cfg = replace(cfg, max_rooms_per_session=int(args.max_rooms))
    if args.max_room_name_len is not None:
        cfg = replace(cfg, max_room_name_len=int(args.max_room_name_len))

    if args.rate_limit_msgs_per_minute is not None:
        cfg = replace(
            cfg, rate_limit_msgs_per_minute=int(args.rate_limit_msgs_per_minute)
        )
    if args.max_msg_body_bytes is not None:
        cfg = replace(cfg, max_msg_body_bytes=int(args.max_msg_body_bytes))

    if args.ping_interval is not None:
        cfg = replace(cfg, ping_interval_s=float(args.ping_interval))
    if args.ping_timeout is not None:
        cfg = replace(cfg, ping_timeout_s=float(args.ping_timeout))

    if args.log_level is not None:
        cfg = replace(cfg, log_level=str(args.log_level))
    if args.log_file is not None:
        cfg = replace(cfg, log_file=str(args.log_file) if str(args.log_file) else None)

    configure_logging(cfg, override_level=args.log_level, override_file=args.log_file)

    svc = HubService(cfg)
    svc.start()
    svc.run_forever()


if __name__ == "__main__":
    main()
