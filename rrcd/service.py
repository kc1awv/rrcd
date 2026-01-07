from __future__ import annotations

import logging
import os
import signal
import threading
import time
from dataclasses import asdict, replace
from typing import Any

import RNS

from . import __version__
from .codec import encode
from .commands import CommandHandler
from .config import HubRuntimeConfig
from .constants import (
    B_WELCOME_HUB,
    B_WELCOME_VER,
    RES_KIND_MOTD,
    RES_KIND_NOTICE,
    T_ERROR,
    T_NOTICE,
    T_PING,
    T_WELCOME,
)
from .envelope import make_envelope
from .logging_config import configure_logging
from .resources import ResourceManager
from .rooms import RoomManager
from .router import MessageRouter, OutgoingList
from .session import SessionManager
from .stats import StatsManager
from .util import expand_path


class HubService:
    def __init__(self, config: HubRuntimeConfig) -> None:
        self.config = config
        self.log = logging.getLogger("rrcd.hub")

        # Shared mutable state (sessions/rooms/room registry/etc) is accessed from
        # Reticulum callbacks and background worker threads. Guard it with a
        # single re-entrant lock.
        self._state_lock = threading.RLock()

        self._shutdown = threading.Event()

        # Message router for handling protocol messages
        self.router = MessageRouter(self)
        
        # Session manager for connection lifecycle
        self.session_manager = SessionManager(self)
        
        # Command handler for operator commands
        self.command_handler = CommandHandler(self)
        
        # Resource manager for file/data transfers
        self.resource_manager = ResourceManager(self)
        
        # Room manager for room memberships and permissions
        self.room_manager = RoomManager(self)
        
        # Stats manager for metrics and reporting
        self.stats_manager = StatsManager(self)

        self.identity: RNS.Identity | None = None
        self.destination: RNS.Destination | None = None


        self._trusted: set[bytes] = set()
        self._banned: set[bytes] = set()

        self._prune_thread: threading.Thread | None = None

        self._ping_thread: threading.Thread | None = None
        self._announce_thread: threading.Thread | None = None
        self._resource_cleanup_thread: threading.Thread | None = None

        self._config_write_lock = threading.Lock()



    def _fmt_hash(self, h: Any, *, prefix: int = 12) -> str:
        if isinstance(h, (bytes, bytearray)):
            s = bytes(h).hex()
            return s if prefix <= 0 else s[: min(prefix, len(s))]
        return "-"

    def _fmt_link_id(self, link: RNS.Link) -> str:
        lid = getattr(link, "link_id", None)
        if isinstance(lid, (bytes, bytearray)):
            return bytes(lid).hex()
        h = getattr(link, "hash", None)
        if isinstance(h, (bytes, bytearray)):
            return bytes(h).hex()
        return "-"

    def _packet_would_fit(self, link: RNS.Link, payload: bytes) -> bool:
        """Check if payload fits within link MDU without creating/packing packets."""
        try:
            # Query link MDU directly if available (more efficient than packing)
            if hasattr(link, 'MDU') and link.MDU is not None:
                return len(payload) <= link.MDU
            # Fall back to packet creation if MDU not available
            pkt = RNS.Packet(link, payload)
            pkt.pack()
            return True
        except Exception:
            return False

    def _queue_notice_chunks(
        self,
        outgoing: list[tuple[RNS.Link, bytes]],
        link: RNS.Link,
        *,
        room: str | None,
        text: str,
    ) -> None:
        if self.identity is None:
            return
        if not text:
            return

        # Prefer splitting on lines for readability. If a single line is too
        # large, further split it by characters using a pack preflight.
        lines = text.splitlines() or [text]
        for line in lines:
            remaining = line
            if not remaining:
                continue

            # Start with a generous chunk size; shrink on demand.
            max_chars = min(len(remaining), 512)
            while remaining:
                take = min(len(remaining), max_chars)
                chunk = remaining[:take]
                env = make_envelope(
                    T_NOTICE,
                    src=self.identity.hash,
                    room=room,
                    body=chunk,
                )
                payload = encode(env)
                if self._packet_would_fit(link, payload):
                    self._queue_payload(outgoing, link, payload)
                    remaining = remaining[take:]
                    max_chars = min(max_chars, 512)
                    continue

                if max_chars <= 1:
                    # Nothing we can do; avoid an infinite loop.
                    self.log.warning(
                        "NOTICE chunk would not fit MTU; dropping remainder (%s chars)",
                        len(remaining),
                    )
                    break

                max_chars = max(1, max_chars // 2)

    def _queue_welcome(
        self,
        outgoing: list[tuple[RNS.Link, bytes]],
        link: RNS.Link,
        *,
        peer_hash: Any,
        motd: str | None,
    ) -> None:
        if self.identity is None:
            return

        g = str(motd) if motd else ""
        body_w: dict[int, Any] = {
            B_WELCOME_HUB: self.config.hub_name,
            B_WELCOME_VER: str(__version__),
        }
        # Capabilities are optional; keep WELCOME minimal unless needed.

        welcome = make_envelope(T_WELCOME, src=self.identity.hash, body=body_w)
        welcome_payload = encode(welcome)

        if not self._packet_would_fit(link, welcome_payload):
            self.log.warning(
                "WELCOME would not fit MTU; cannot welcome peer=%s link_id=%s",
                self._fmt_hash(peer_hash),
                self._fmt_link_id(link),
            )
            return

        self._queue_payload(outgoing, link, welcome_payload)
        self.log.debug(
            "Queued WELCOME peer=%s link_id=%s",
            self._fmt_hash(peer_hash),
            self._fmt_link_id(link),
        )

    def _update_nick_index(self, link: RNS.Link, old_nick: str | None, new_nick: str | None) -> None:
        """Update nick index when a nick changes. Delegates to SessionManager."""
        self.session_manager.update_nick_index(link, old_nick, new_nick)

    # Resource transfer methods

    def _send_text_smart(
        self,
        link: RNS.Link,
        *,
        msg_type: int,
        text: str,
        room: str | None = None,
        encoding: str = "utf-8",
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
        kind: str | None = None,
    ) -> None:
        """
        Send text message using best method (packet or resource).
        Falls back to chunking if resource transfer fails or is disabled.
        
        Args:
            kind: Resource kind if sent via resource (default: RES_KIND_NOTICE)
        """
        if self.identity is None:
            return
        
        # Try encoding as a single packet first
        env = make_envelope(msg_type, src=self.identity.hash, room=room, body=text)
        payload = encode(env)
        
        # If it fits, send normally
        if self._packet_would_fit(link, payload):
            self.log.debug(
                "Text fits in packet link_id=%s bytes=%s",
                self._fmt_link_id(link),
                len(payload),
            )
            if outgoing is None:
                self._send(link, env)
            else:
                self._queue_env(outgoing, link, env)
            return
        
        self.log.debug(
            "Text too large for packet link_id=%s bytes=%s mtu_check_failed=True",
            self._fmt_link_id(link),
            len(payload),
        )
        
        # Too large for packet - try resource if enabled and type is NOTICE
        # Only use resources when NOT batching (outgoing=None), since resource
        # creation happens immediately and would race with queued packets.
        text_bytes = text.encode(encoding)
        can_use_resource = (
            self.config.enable_resource_transfer
            and msg_type == T_NOTICE
            and outgoing is None
            and len(text_bytes) <= self.config.max_resource_bytes
        )
        
        self.log.debug(
            "Resource check: enabled=%s type_is_notice=%s not_batching=%s size_ok=%s/%s",
            self.config.enable_resource_transfer,
            msg_type == T_NOTICE,
            outgoing is None,
            len(text_bytes),
            self.config.max_resource_bytes,
        )
        
        if can_use_resource:
            self.log.debug(
                "Attempting to send via resource link_id=%s kind=%s",
                self._fmt_link_id(link),
                kind if kind is not None else RES_KIND_NOTICE,
            )
            resource_kind = kind if kind is not None else RES_KIND_NOTICE
            if self.resource_manager.send_via_resource(
                link,
                kind=resource_kind,
                payload=text_bytes,
                room=room,
                encoding=encoding,
            ):
                self.log.debug(
                    "Sent large text via resource link_id=%s kind=%s chars=%s",
                    self._fmt_link_id(link),
                    resource_kind,
                    len(text),
                )
                return
            else:
                self.log.warning(
                    "Resource send failed, falling back to chunks link_id=%s",
                    self._fmt_link_id(link),
                )
        
        # Fall back to chunking for NOTICE
        if msg_type == T_NOTICE:
            self.log.debug(
                "Falling back to chunking link_id=%s outgoing_is_none=%s",
                self._fmt_link_id(link),
                outgoing is None,
            )
            if outgoing is None:
                outgoing = []
                self._queue_notice_chunks(outgoing, link, room=room, text=text)
                for out_link, chunk_payload in outgoing:
                    self.stats_manager.inc("bytes_out", len(chunk_payload))
                    try:
                        RNS.Packet(out_link, chunk_payload).send()
                    except Exception as e:
                        self.log.warning(
                            "Failed to send chunk link_id=%s: %s",
                            self._fmt_link_id(out_link),
                            e,
                        )
            else:
                self._queue_notice_chunks(outgoing, link, room=room, text=text)
        else:
            # For other message types, just drop or log error
            self.log.error(
                "Message too large and not NOTICE link_id=%s type=%s",
                self._fmt_link_id(link),
                msg_type,
            )

    def start(self) -> None:
        self.log.info("Starting Reticulum")
        if self.stats_manager.started_wall_time is None:
            self.stats_manager.set_start_time()
        RNS.Reticulum(configdir=self.config.configdir, require_shared_instance=False)

        if not self.config.identity_path:
            raise RuntimeError("identity_path is not set")
        self.identity = self._load_identity(self.config.identity_path)

        self._trusted = {
            self._parse_identity_hash(h)
            for h in (self.config.trusted_identities or ())
            if str(h).strip()
        }
        self._banned = {
            self._parse_identity_hash(h)
            for h in (self.config.banned_identities or ())
            if str(h).strip()
        }

        self._load_registered_rooms_from_registry()

        parts = [p for p in str(self.config.dest_name).split(".") if p]
        if not parts:
            raise ValueError("dest_name must not be empty")
        app_name, aspects = parts[0], parts[1:]

        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            app_name,
            *aspects,
        )
        self.destination.set_link_established_callback(self._on_link)

        if self.config.announce_on_start:
            self._announce_once()

        if self.config.announce_period_s and self.config.announce_period_s > 0:
            self._announce_thread = threading.Thread(
                target=self._announce_loop,
                name="rrcd-announce",
                daemon=True,
            )
            self._announce_thread.start()

        self.log.info(
            "Hub running dest_name=%s dest_hash=%s",
            self.config.dest_name,
            self.destination.hash.hex() if self.destination else "-",
        )
        self.log.info(
            "Policy nick_max_chars=%s max_rooms=%s max_room_name_len=%s rate_limit_msgs_per_minute=%s",
            self.config.nick_max_chars,
            self.config.max_rooms_per_session,
            self.config.max_room_name_len,
            self.config.rate_limit_msgs_per_minute,
        )

        if self.config.ping_interval_s and self.config.ping_interval_s > 0:
            self._ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
            self._ping_thread.start()

        if (
            self.config.room_registry_prune_interval_s
            and self.config.room_registry_prune_interval_s > 0
            and self.config.room_registry_prune_after_s
            and self.config.room_registry_prune_after_s > 0
        ):
            self._prune_thread = threading.Thread(
                target=self._prune_loop, name="rrcd-room-prune", daemon=True
            )
            self._prune_thread.start()

        # Start resource cleanup thread if resource transfer is enabled
        if self.config.enable_resource_transfer:
            self._resource_cleanup_thread = threading.Thread(
                target=self._resource_cleanup_loop, name="rrcd-resource-cleanup", daemon=True
            )
            self._resource_cleanup_thread.start()

    def _announce_once(self) -> None:
        if self.destination is None:
            return
        try:
            self.destination.announce(
                app_data=encode({"proto": "rrc", "v": 1, "hub": self.config.hub_name})
            )
            self.stats_manager.inc("announces")
        except Exception:
            self.log.exception("Announce failed")

    def _announce_loop(self) -> None:
        while not self._shutdown.is_set():
            period = float(self.config.announce_period_s)
            if period <= 0:
                time.sleep(1.0)
                continue

            time.sleep(period)
            if self._shutdown.is_set():
                break
            self._announce_once()

    def run_forever(self) -> None:
        if self.destination is None:
            self.start()

        signal.signal(signal.SIGINT, lambda *_: self.stop())
        signal.signal(signal.SIGTERM, lambda *_: self.stop())

        while not self._shutdown.is_set():
            time.sleep(0.25)

    def stop(self) -> None:
        self._shutdown.set()

        with self._state_lock:
            links = self.session_manager.clear_all()
            self.room_manager.clear_all()
            self.resource_manager.clear_all()

        for link in links:
            try:
                link.teardown()
            except Exception:
                pass

    def _load_identity(self, path: str) -> RNS.Identity:
        p = expand_path(path)
        if not os.path.exists(p):
            raise RuntimeError(f"Identity not found at {p}")
        ident = RNS.Identity.from_file(p)
        if ident is None:
            raise RuntimeError(f"Failed to load identity from {p}")
        return ident

    def _parse_identity_hash(self, text: str) -> bytes:
        s = str(text).strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        s = "".join(ch for ch in s if not ch.isspace())
        try:
            b = bytes.fromhex(s)
        except Exception as e:
            raise ValueError(f"invalid identity hash {text!r}: {e}") from e
        if len(b) < 4:
            raise ValueError(f"identity hash too short: {text!r}")
        return b

    def _load_toml(self, path: str) -> dict:
        import tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data if isinstance(data, dict) else {}

    def _apply_config_data(
        self, base: HubRuntimeConfig, data: dict
    ) -> HubRuntimeConfig:
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
        # This identifies where to reload from; do not let the file override it.
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

    def _format_reload_value(self, v: Any) -> str:
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

    def _diff_config_summary(
        self, old: HubRuntimeConfig, new: HubRuntimeConfig
    ) -> list[str]:
        old_d = asdict(old)
        new_d = asdict(new)
        old_d.pop("config_path", None)
        new_d.pop("config_path", None)

        changed: list[str] = []
        for k in sorted(new_d.keys()):
            if old_d.get(k) == new_d.get(k):
                continue
            changed.append(
                f"{k}: {self._format_reload_value(old_d.get(k))} -> {self._format_reload_value(new_d.get(k))}"
            )
        return changed

    def _ensure_worker_threads(self) -> None:
        # Announce loop
        if self._announce_thread is None or not self._announce_thread.is_alive():
            if (
                self.config.announce_period_s
                and float(self.config.announce_period_s) > 0
            ):
                self._announce_thread = threading.Thread(
                    target=self._announce_loop,
                    name="rrcd-announce",
                    daemon=True,
                )
                self._announce_thread.start()

        # Ping loop
        if self._ping_thread is None or not self._ping_thread.is_alive():
            if self.config.ping_interval_s and float(self.config.ping_interval_s) > 0:
                self._ping_thread = threading.Thread(
                    target=self._ping_loop, daemon=True
                )
                self._ping_thread.start()

        # Prune loop
        if self._prune_thread is None or not self._prune_thread.is_alive():
            if (
                self.config.room_registry_prune_interval_s
                and float(self.config.room_registry_prune_interval_s) > 0
                and self.config.room_registry_prune_after_s
                and float(self.config.room_registry_prune_after_s) > 0
            ):
                self._prune_thread = threading.Thread(
                    target=self._prune_loop,
                    name="rrcd-room-prune",
                    daemon=True,
                )
                self._prune_thread.start()

    def _reload_config_and_rooms(
        self,
        link: RNS.Link,
        room: str | None,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
    ) -> None:
        cfg_path = self._config_path_for_writes()
        if not cfg_path or not os.path.exists(cfg_path):
            self._emit_notice(
                outgoing, link, room, "reload failed: config_path not set or missing"
            )
            return

        with self._state_lock:
            old_cfg = self.config
            old_trusted = set(self._trusted)
            old_banned = set(self._banned)
            old_registry = dict(self.room_manager._room_registry)

        # Stage config parse
        try:
            data = self._load_toml(cfg_path)
            new_cfg = self._apply_config_data(old_cfg, data)
        except Exception as e:
            self._emit_notice(
                outgoing, link, room, f"reload failed: config parse error: {e}"
            )
            return

        # Stage identity lists
        try:
            new_trusted = {
                self._parse_identity_hash(h)
                for h in (new_cfg.trusted_identities or ())
                if str(h).strip()
            }
            new_banned = {
                self._parse_identity_hash(h)
                for h in (new_cfg.banned_identities or ())
                if str(h).strip()
            }
        except Exception as e:
            self._emit_notice(
                outgoing, link, room, f"reload failed: identity list parse error: {e}"
            )
            return

        # Stage room registry parse (strict)
        reg_path = (
            expand_path(str(new_cfg.room_registry_path))
            if new_cfg.room_registry_path
            else ""
        )
        new_registry, reg_err = self.room_manager.load_registry_from_path(
            reg_path,
            invite_timeout_s=new_cfg.room_invite_timeout_s,
        )
        if reg_err is not None:
            self._emit_notice(outgoing, link, room, f"reload failed: {reg_err}")
            return

        with self._state_lock:
            # Apply (all-or-nothing)
            self.config = new_cfg
            self._trusted = new_trusted
            self._banned = new_banned
            self.room_manager._room_registry = new_registry

            # Merge registry into live per-room state (for active rooms).
            # This makes /reload take effect immediately for existing members.
            self.room_manager.merge_registry_into_state(new_registry)

        self._ensure_worker_threads()

        # Apply logging changes immediately.
        try:
            configure_logging(self.config)
        except Exception:
            self.log.exception("Failed to reconfigure logging")

        cfg_changes = self._diff_config_summary(old_cfg, new_cfg)
        room_changes = self.room_manager.diff_registry_summary(old_registry, new_registry)

        lines: list[str] = []
        lines.append(
            f"reloaded: trusted={len(old_trusted)}->{len(new_trusted)} "
            f"banned={len(old_banned)}->{len(new_banned)} "
            f"registered_rooms={len(old_registry)}->{len(new_registry)}"
        )
        lines.append(f"policy: nick_max_chars={new_cfg.nick_max_chars}")

        if cfg_changes:
            lines.append("config_changes:")
            preview = cfg_changes[:12]
            lines.extend(f"- {x}" for x in preview)
            if len(cfg_changes) > 12:
                lines.append(f"- (+{len(cfg_changes) - 12} more)")
        else:
            lines.append("config_changes: (none)")

        lines.append("rooms_changes:")
        lines.extend(f"- {x}" for x in room_changes)

        self._emit_notice(outgoing, link, room, "\n".join(lines))

    def _load_registered_rooms_from_registry(self) -> None:
        reg_path = self.room_manager.get_registry_path_for_writes()
        if not reg_path:
            return
        registry, err = self.room_manager.load_registry_from_path(
            reg_path, invite_timeout_s=self.config.room_invite_timeout_s
        )
        if err is not None:
            return
        self.room_manager._room_registry = registry

    def _is_server_op(self, peer_hash: bytes | None) -> bool:
        return self._is_trusted(peer_hash)

    def _resolve_identity_hash(
        self, token: str, *, room: str | None = None
    ) -> bytes | None:
        """Resolve token to identity hash. Returns hash if successful, None otherwise.
        For ambiguous matches, use _resolve_identity_hash_with_matches instead.
        """
        target_link = self._find_target_link(token, room=room)
        if target_link is not None:
            s = self.session_manager.sessions.get(target_link)
            ph = s.get("peer") if s else None
            if isinstance(ph, (bytes, bytearray)):
                return bytes(ph)
        try:
            return self._parse_identity_hash(token)
        except Exception:
            return None

    def _resolve_identity_hash_with_matches(
        self, token: str, *, room: str | None = None
    ) -> tuple[bytes | None, list[RNS.Link]]:
        """Resolve token to identity hash, also returning all matching links.
        Returns (hash, matches) tuple. Hash is None if ambiguous or not found.
        Use matches list to provide helpful error messages.
        """
        matches = self._find_target_links(token, room=room)
        
        if len(matches) == 1:
            # Exactly one match - get hash from session
            s = self.session_manager.sessions.get(matches[0])
            ph = s.get("peer") if s else None
            if isinstance(ph, (bytes, bytearray)):
                return (bytes(ph), matches)
        elif len(matches) > 1:
            # Ambiguous - return None hash but provide matches for error message
            return (None, matches)
        
        # No matches from nick/hash-prefix lookup - try raw hash parse
        try:
            h = self._parse_identity_hash(token)
            return (h, [])
        except Exception:
            return (None, [])

    def _resource_cleanup_loop(self) -> None:
        """Periodically cleanup expired resource expectations."""
        while not self._shutdown.is_set():
            # Run cleanup every 30 seconds
            time.sleep(30.0)
            if self._shutdown.is_set():
                break
            try:
                self.resource_manager.cleanup_all_expired_expectations()
            except Exception:
                self.log.exception("Resource cleanup failed")

    def _prune_loop(self) -> None:
        """Periodically prune unused registered rooms."""
        while not self._shutdown.is_set():
            interval = float(self.config.room_registry_prune_interval_s)
            prune_after = float(self.config.room_registry_prune_after_s)
            if interval <= 0 or prune_after <= 0:
                time.sleep(1.0)
                continue

            time.sleep(interval)
            if self._shutdown.is_set():
                break

            rooms_to_prune: list[str] = []
            dummy_link: RNS.Link | None = None

            with self._state_lock:
                dummy_link = next(iter(self.session_manager.sessions.keys()), None)
                rooms_to_prune = self.room_manager.prune_unused_registered_rooms(
                    prune_after, self.stats_manager.started_wall_time or time.time()
                )

            if dummy_link is not None:
                for room in rooms_to_prune:
                    self.room_manager.delete_room_from_registry(dummy_link, room)

            for room in rooms_to_prune:
                self.log.info("Pruned unused registered room %s", room)

    def _config_path_for_writes(self) -> str | None:
        p = self.config.config_path
        if not p:
            return None
        return expand_path(str(p))

    def _persist_banned_identities_to_config(
        self,
        link: RNS.Link,
        room: str | None,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
    ) -> None:
        cfg_path = self._config_path_for_writes()
        if not cfg_path:
            self._emit_notice(
                outgoing, link, room, "ban updated (not persisted; no config_path)"
            )
            return

        try:
            from tomlkit import dumps, parse, table  # type: ignore
        except Exception:
            self._emit_notice(
                outgoing,
                link,
                room,
                "ban updated (not persisted; missing dependency tomlkit)",
            )
            return

        try:
            with self._config_write_lock:
                st = None
                try:
                    st = os.stat(cfg_path)
                except Exception:
                    st = None

                with open(cfg_path, encoding="utf-8") as f:
                    doc = parse(f.read())

                hub = doc.get("hub")
                if hub is None:
                    hub = table()
                    doc["hub"] = hub

                existing = hub.get("banned_identities")
                existing_list: list[str] = []
                if isinstance(existing, list):
                    for x in existing:
                        if x is None:
                            continue
                        sx = str(x).strip().lower()
                        if sx.startswith("0x"):
                            sx = sx[2:]
                        if sx:
                            existing_list.append(sx)

                merged = set(existing_list)
                merged.update(h.hex() for h in sorted(self._banned))
                hub["banned_identities"] = sorted(merged)

                new_text = dumps(doc)
                with open(cfg_path, "w", encoding="utf-8") as f:
                    f.write(new_text)

                if st is not None:
                    try:
                        os.chmod(cfg_path, st.st_mode)
                    except Exception:
                        pass
        except Exception as e:
            self._emit_notice(
                outgoing, link, room, f"ban updated (persist failed: {e})"
            )

    def _is_trusted(self, peer_hash: bytes | None) -> bool:
        if not peer_hash:
            return False
        with self._state_lock:
            return peer_hash in self._trusted

    def _notice_to(self, link: RNS.Link, room: str | None, text: str) -> None:
        if self.identity is None:
            return
        env = make_envelope(T_NOTICE, src=self.identity.hash, room=room, body=text)
        self._send(link, env)

    def _queue_payload(
        self, outgoing: list[tuple[RNS.Link, bytes]], link: RNS.Link, payload: bytes
    ) -> None:
        self.stats_manager.inc("bytes_out", len(payload))
        outgoing.append((link, payload))

    def _queue_env(
        self, outgoing: list[tuple[RNS.Link, bytes]], link: RNS.Link, env: dict
    ) -> None:
        payload = encode(env)
        self._queue_payload(outgoing, link, payload)

    def _emit_notice(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        room: str | None,
        text: str,
    ) -> None:
        if self.identity is None:
            return
        env = make_envelope(T_NOTICE, src=self.identity.hash, room=room, body=text)
        if outgoing is None:
            self._send(link, env)
        else:
            self._queue_env(outgoing, link, env)

    def _emit_error(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        *,
        src: bytes,
        text: str,
        room: str | None = None,
    ) -> None:
        self.stats_manager.inc("errors_sent")
        env = make_envelope(T_ERROR, src=src, room=room, body=text)
        if outgoing is None:
            self._send(link, env)
        else:
            self._queue_env(outgoing, link, env)

    def _on_link(self, link: RNS.Link) -> None:
        with self._state_lock:
            self.session_manager.on_link_established(link)
            self.resource_manager.on_link_established(link)

        link.set_packet_callback(lambda data, pkt: self._on_packet(link, data))
        link.set_link_closed_callback(lambda closed_link: self._on_close(closed_link))
        link.set_remote_identified_callback(
            lambda identified_link, ident: self._on_remote_identified(
                identified_link, ident
            )
        )
        
        # Set up resource callbacks
        self.resource_manager.configure_link_callbacks(link)

        self.log.info("Link established link_id=%s", self._fmt_link_id(link))

    def _on_remote_identified(
        self, link: RNS.Link, identity: RNS.Identity | None
    ) -> None:
        banned = False
        peer_hash = None
        with self._state_lock:
            banned, peer_hash = self.session_manager.on_remote_identified(link, identity)

        if banned:
            self.log.warning(
                "Disconnecting banned peer peer=%s link_id=%s",
                self._fmt_hash(peer_hash),
                self._fmt_link_id(link),
            )
            if self.identity is not None:
                try:
                    self._error(link, src=self.identity.hash, text="banned")
                except Exception:
                    pass
            try:
                link.teardown()
            except Exception:
                pass

    def _welcome(self, link: RNS.Link, sess: dict[str, Any]) -> None:
        if self.identity is None:
            return

        sess["welcomed"] = True
        # Use the queued path so we can preflight MTU sizing and optionally
        # follow up with MOTD via resource or chunks.
        outgoing: list[tuple[RNS.Link, bytes]] = []
        self._queue_welcome(
            outgoing,
            link,
            peer_hash=sess.get("peer"),
            motd=self.config.greeting,
        )
        
        # Send queued WELCOME first
        for out_link, payload in outgoing:
            self.stats_manager.inc("bytes_out", len(payload))
            try:
                RNS.Packet(out_link, payload).send()
            except OSError as e:
                self.log.warning(
                    "Send failed link_id=%s bytes=%s err=%s",
                    self._fmt_link_id(out_link),
                    len(payload),
                    e,
                )
            except Exception:
                self.log.debug(
                    "Send failed link_id=%s bytes=%s",
                    self._fmt_link_id(out_link),
                    len(payload),
                    exc_info=True,
                )
        
        # Now send MOTD via resource or chunks (after WELCOME is sent)
        if self.config.greeting:
            self.log.debug(
                "Sending MOTD link_id=%s len=%s",
                self._fmt_link_id(link),
                len(self.config.greeting),
            )
            self._send_text_smart(
                link,
                msg_type=T_NOTICE,
                text=self.config.greeting,
                room=None,
                kind=RES_KIND_MOTD,
            )

    def _on_close(self, link: RNS.Link) -> None:
        peer = None
        nick = None
        rooms_count = 0

        with self._state_lock:
            # Clean up resource and session state
            self.resource_manager.on_link_closed(link)
            peer, nick, rooms_count = self.session_manager.on_link_closed(link)

        self.log.info(
            "Link closed peer=%s nick=%r rooms=%s link_id=%s",
            self._fmt_hash(peer),
            nick,
            rooms_count,
            self._fmt_link_id(link),
        )

    def _send(self, link: RNS.Link, env: dict) -> None:
        payload = encode(env)
        self.stats_manager.inc("bytes_out", len(payload))
        try:
            RNS.Packet(link, payload).send()
        except OSError as e:
            # Common failure mode on low-MTU links: packet too large.
            self.log.warning(
                "Send failed link_id=%s bytes=%s err=%s",
                self._fmt_link_id(link),
                len(payload),
                e,
            )
        except Exception:
            self.log.debug(
                "Send failed link_id=%s bytes=%s",
                self._fmt_link_id(link),
                len(payload),
                exc_info=True,
            )

    def _error(
        self, link: RNS.Link, src: bytes, text: str, room: str | None = None
    ) -> None:
        self._emit_error(None, link, src=src, text=text, room=room)

    def _norm_room(self, room: str) -> str:
        r = room.strip().lower()
        if not r:
            raise ValueError("room name must not be empty")
        if len(r) > int(self.config.max_room_name_len):
            raise ValueError("room name too long")
        return r

    def _refill_and_take(self, link: RNS.Link, cost: float = 1.0) -> bool:
        """Token bucket rate limiting. Delegates to SessionManager."""
        return self.session_manager.refill_and_take(link, cost)

    def _on_packet(self, link: RNS.Link, data: bytes) -> None:
        # Packet callbacks can occur concurrently with other link callbacks and
        # background worker threads. Keep state mutations under the shared lock,
        # but avoid holding the lock while sending packets via RNS.
        outgoing: list[tuple[RNS.Link, bytes]] = OutgoingList()
        with self._state_lock:
            self._on_packet_locked(link, data, outgoing)

        if self.log.isEnabledFor(logging.DEBUG) and outgoing:
            self.log.debug(
                "Sending %d response(s) link_id=%s",
                len(outgoing),
                self._fmt_link_id(link),
            )

        for out_link, payload in outgoing:
            self.stats_manager.inc("bytes_out", len(payload))
            try:
                RNS.Packet(out_link, payload).send()
            except OSError as e:
                self.log.warning(
                    "Send failed link_id=%s bytes=%s err=%s",
                    self._fmt_link_id(out_link),
                    len(payload),
                    e,
                )
            except Exception:
                self.log.debug(
                    "Send failed link_id=%s bytes=%s",
                    self._fmt_link_id(out_link),
                    len(payload),
                    exc_info=True,
                )
        
        # Execute any post-send callbacks (e.g., for MOTD after WELCOME)
        if hasattr(outgoing, '_post_send_callbacks'):
            for callback in outgoing._post_send_callbacks:  # type: ignore
                try:
                    callback()
                except Exception:
                    self.log.exception("Post-send callback failed")

    def _on_packet_locked(
        self,
        link: RNS.Link,
        data: bytes,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """
        Handle incoming packet with state lock held.
        
        Delegates to MessageRouter for message routing and dispatching.
        """
        self.router.route_packet(link, data, outgoing)

    def _ping_loop(self) -> None:
        while not self._shutdown.is_set():
            interval = float(self.config.ping_interval_s)
            timeout = float(self.config.ping_timeout_s)
            if interval <= 0:
                time.sleep(1.0)
                continue

            time.sleep(interval)
            if self.identity is None:
                continue

            now = time.monotonic()
            to_teardown: list[RNS.Link] = []
            to_ping: list[RNS.Link] = []

            with self._state_lock:
                for link, sess in list(self.session_manager.sessions.items()):
                    if not sess.get("welcomed"):
                        continue

                    awaiting = sess.get("awaiting_pong")
                    if (
                        timeout > 0
                        and awaiting is not None
                        and (now - float(awaiting)) > timeout
                    ):
                        to_teardown.append(link)
                        continue

                    if awaiting is None:
                        sess["awaiting_pong"] = now
                        to_ping.append(link)

            for link in to_teardown:
                try:
                    link.teardown()
                except Exception:
                    pass

            for link in to_ping:
                ping = make_envelope(T_PING, src=self.identity.hash, body=now)
                try:
                    self.stats_manager.inc("pings_out")
                    self._send(link, ping)
                except Exception:
                    pass
