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
from .config import ConfigManager, HubRuntimeConfig
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
from .messages import MessageHelper
from .resources import ResourceManager
from .rooms import RoomManager
from .router import MessageRouter, OutgoingList
from .session import SessionManager
from .stats import StatsManager
from .trust import TrustManager
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
        
        # Trust manager for trusted/banned identities
        self.trust_manager = TrustManager(self)
        
        # Config manager for configuration loading and reloading
        self.config_manager = ConfigManager(self)
        
        # Message helper for sending and queueing messages
        self.message_helper = MessageHelper(self)

        self.identity: RNS.Identity | None = None
        self.destination: RNS.Destination | None = None

        self._prune_thread: threading.Thread | None = None

        self._ping_thread: threading.Thread | None = None
        self._announce_thread: threading.Thread | None = None
        self._resource_cleanup_thread: threading.Thread | None = None



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

    def _update_nick_index(self, link: RNS.Link, old_nick: str | None, new_nick: str | None) -> None:
        """Update nick index when a nick changes. Delegates to SessionManager."""
        self.session_manager.update_nick_index(link, old_nick, new_nick)

    # Resource transfer methods - delegates to message_helper for smart sending

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
        """Delegate to message_helper for smart text sending."""
        self.message_helper.send_text_smart(
            link,
            msg_type=msg_type,
            text=text,
            room=room,
            kind=kind,
            outgoing=outgoing,
            encoding=encoding,
        )

    def start(self) -> None:
        self.log.info("Starting Reticulum")
        if self.stats_manager.started_wall_time is None:
            self.stats_manager.set_start_time()
        RNS.Reticulum(configdir=self.config.configdir, require_shared_instance=False)

        if not self.config.identity_path:
            raise RuntimeError("identity_path is not set")
        self.identity = self._load_identity(self.config.identity_path)

        self.trust_manager.load_from_config(
            self.config.trusted_identities,
            self.config.banned_identities,
        )

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
        cfg_path = self.config_manager.get_config_path_for_writes()
        if not cfg_path or not os.path.exists(cfg_path):
            self._emit_notice(
                outgoing, link, room, "reload failed: config_path not set or missing"
            )
            return

        with self._state_lock:
            old_cfg = self.config
            old_trusted = set(self.trust_manager._trusted)
            old_banned = set(self.trust_manager._banned)
            old_registry = dict(self.room_manager._room_registry)

        # Stage config parse
        try:
            data = self.config_manager.load_toml(cfg_path)
            new_cfg = self.config_manager.apply_config_data(old_cfg, data)
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
            self.trust_manager._trusted = new_trusted
            self.trust_manager._banned = new_banned
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

        cfg_changes = self.config_manager.diff_config_summary(old_cfg, new_cfg)
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
        """Delegate to message_helper for sending."""
        self.message_helper.send(link, env)

    def _error(
        self, link: RNS.Link, src: bytes, text: str, room: str | None = None
    ) -> None:
        """Delegate to message_helper for error sending."""
        self.message_helper.error(link, src, text, room)

    def _emit_error(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        *,
        src: bytes,
        text: str,
        room: str | None = None,
    ) -> None:
        """Delegate to message_helper for error emission."""
        self.message_helper.emit_error(outgoing, link, src=src, text=text, room=room)

    def _emit_notice(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        room: str | None,
        text: str,
    ) -> None:
        """Delegate to message_helper for notice emission."""
        self.message_helper.emit_notice(outgoing, link, room, text)

    def _queue_welcome(
        self,
        outgoing: list[tuple[RNS.Link, bytes]],
        link: RNS.Link,
        *,
        peer_hash: Any,
        motd: str | None,
    ) -> None:
        """Delegate to message_helper for queuing welcome."""
        self.message_helper.queue_welcome(outgoing, link, peer_hash=peer_hash, motd=motd)

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
