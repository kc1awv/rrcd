from __future__ import annotations

import hashlib
import logging
import os
import signal
import threading
import time
from dataclasses import asdict, dataclass, replace
from typing import Any

import RNS

from . import __version__
from .codec import encode
from .config import HubRuntimeConfig
from .constants import (
    B_RES_ENCODING,
    B_RES_ID,
    B_RES_KIND,
    B_RES_SHA256,
    B_RES_SIZE,
    B_WELCOME_HUB,
    B_WELCOME_VER,
    RES_KIND_BLOB,
    RES_KIND_MOTD,
    RES_KIND_NOTICE,
    T_ERROR,
    T_NOTICE,
    T_PING,
    T_RESOURCE_ENVELOPE,
    T_WELCOME,
)
from .envelope import make_envelope
from .logging_config import configure_logging
from .router import MessageRouter
from .session import SessionManager
from .util import expand_path


@dataclass
class _ResourceExpectation:
    """Tracks an expected incoming Resource transfer."""
    id: bytes
    kind: str
    size: int
    sha256: bytes | None
    encoding: str | None
    created_at: float
    expires_at: float
    room: str | None = None


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

        self.identity: RNS.Identity | None = None
        self.destination: RNS.Destination | None = None

        self.rooms: dict[str, set[RNS.Link]] = {}

        # Resource transfer state
        self._resource_expectations: dict[RNS.Link, dict[bytes, _ResourceExpectation]] = {}
        self._active_resources: dict[RNS.Link, set[RNS.Resource]] = {}
        # Tracks which expectation RID was matched to an advertised Resource.
        self._resource_bindings: dict[RNS.Resource, bytes] = {}

        self._trusted: set[bytes] = set()
        self._banned: set[bytes] = set()

        # Room state (hub-local conventions; no new on-wire message types).
        # _room_state holds active in-memory state (and registered state for empty rooms).
        # _room_registry holds registered rooms loaded from config.
        self._room_state: dict[str, dict[str, Any]] = {}
        self._room_registry: dict[str, dict[str, Any]] = {}

        self._room_registry_write_lock = threading.Lock()
        self._prune_thread: threading.Thread | None = None

        self._ping_thread: threading.Thread | None = None
        self._announce_thread: threading.Thread | None = None
        self._resource_cleanup_thread: threading.Thread | None = None

        self._config_write_lock = threading.Lock()

        self._started_wall_time: float | None = None
        self._started_monotonic: float | None = None
        # Lifetime counters for uptime statistics (monotonically increasing after startup).
        # Python int has arbitrary precision, so overflow is not a concern.
        self._counters: dict[str, int] = {
            "bytes_in": 0,
            "bytes_out": 0,
            "pkts_in": 0,
            "pkts_bad": 0,
            "rate_limited": 0,
            "errors_sent": 0,
            "joins": 0,
            "parts": 0,
            "msgs_forwarded": 0,
            "notices_forwarded": 0,
            "pings_in": 0,
            "pongs_in": 0,
            "pings_out": 0,
            "pongs_out": 0,
            "announces": 0,
            "resources_sent": 0,
            "resources_received": 0,
            "resources_rejected": 0,
            "resource_bytes_sent": 0,
            "resource_bytes_received": 0,
        }



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

        # The hub MOTD (message of the day) is delivered after WELCOME.
        if g:
            self._send_text_smart(
                link, msg_type=T_NOTICE, text=g, room=None, outgoing=outgoing, kind=RES_KIND_MOTD
            )

    def _inc(self, key: str, delta: int = 1) -> None:
        try:
            with self._state_lock:
                self._counters[key] = int(self._counters.get(key, 0)) + int(delta)
        except Exception:
            pass

    def _update_nick_index(self, link: RNS.Link, old_nick: str | None, new_nick: str | None) -> None:
        """Update nick index when a nick changes. Delegates to SessionManager."""
        self.session_manager.update_nick_index(link, old_nick, new_nick)

    # Resource transfer methods

    def _cleanup_expired_expectations(self, link: RNS.Link) -> None:
        """Remove expired resource expectations for a link."""
        now = time.time()
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return
        
        expired = [rid for rid, exp in exp_dict.items() if exp.expires_at <= now]
        for rid in expired:
            exp_dict.pop(rid, None)
            self.log.debug(
                "Expired resource expectation link_id=%s rid=%s",
                self._fmt_link_id(link),
                rid.hex() if isinstance(rid, bytes) else rid,
            )

    def _cleanup_all_expired_expectations(self) -> None:
        """Cleanup expired resource expectations across all links."""
        now = time.time()
        with self._state_lock:
            for link, exp_dict in list(self._resource_expectations.items()):
                if not exp_dict:
                    continue
                
                expired = [rid for rid, exp in exp_dict.items() if exp.expires_at <= now]
                for rid in expired:
                    exp_dict.pop(rid, None)
                    self.log.debug(
                        "Expired resource expectation link_id=%s rid=%s",
                        self._fmt_link_id(link),
                        rid.hex() if isinstance(rid, bytes) else rid,
                    )

    def _add_resource_expectation(
        self,
        link: RNS.Link,
        *,
        rid: bytes,
        kind: str,
        size: int,
        sha256: bytes | None = None,
        encoding: str | None = None,
        room: str | None = None,
    ) -> bool:
        """Add a resource expectation. Returns False if limit exceeded."""
        self._cleanup_expired_expectations(link)
        
        exp_dict = self._resource_expectations.setdefault(link, {})
        
        if len(exp_dict) >= self.config.max_pending_resource_expectations:
            self.log.warning(
                "Max pending expectations exceeded link_id=%s",
                self._fmt_link_id(link),
            )
            return False
        
        now = time.time()
        exp = _ResourceExpectation(
            id=rid,
            kind=kind,
            size=size,
            sha256=sha256,
            encoding=encoding,
            created_at=now,
            expires_at=now + self.config.resource_expectation_ttl_s,
            room=room,
        )
        exp_dict[rid] = exp
        
        self.log.debug(
            "Added resource expectation link_id=%s rid=%s kind=%s size=%s",
            self._fmt_link_id(link),
            rid.hex(),
            kind,
            size,
        )
        return True

    def _find_resource_expectation(
        self, link: RNS.Link, size: int
    ) -> _ResourceExpectation | None:
        """Find a matching resource expectation by size (fallback matching)."""
        self._cleanup_expired_expectations(link)
        
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        
        # Match by size (first match wins)
        for exp in exp_dict.values():
            if exp.size == size:
                return exp
        
        return None

    def _get_resource_expectation_by_rid(
        self, link: RNS.Link, rid: bytes
    ) -> _ResourceExpectation | None:
        """Lookup an expectation by RID without removing it."""
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        return exp_dict.get(rid)

    def _match_resource_expectation(
        self, link: RNS.Link, *, rid: bytes | None, size: int, sha256: bytes | None
    ) -> _ResourceExpectation | None:
        """Find the expectation that should satisfy a completed resource.

        Preference order:
        1) Bound RID (from advertisement) when available.
        2) Exact RID lookup.
        3) Fallback: first size match whose sha256 (if present) matches.
        """
        self._cleanup_expired_expectations(link)

        if rid is not None:
            exp = self._get_resource_expectation_by_rid(link, rid)
            if exp is not None:
                return exp

        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None

        # Avoid linear scan if nothing matches by size.
        for exp in exp_dict.values():
            if exp.size != size:
                continue
            if exp.sha256 and sha256 and exp.sha256 != sha256:
                continue
            return exp
        return None

    def _pop_resource_expectation(
        self, link: RNS.Link, rid: bytes
    ) -> _ResourceExpectation | None:
        """Remove and return a resource expectation."""
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        return exp_dict.pop(rid, None)

    def _resource_advertised(self, resource: RNS.Resource) -> bool:
        """
        Callback when a Resource is advertised by remote peer.
        Returns True to accept, False to reject.
        
        Minimize lock scope to prevent potential deadlocks with RNS internal locks.
        """
        link = resource.link
        
        # Check config outside lock (immutable during runtime)
        if not self.config.enable_resource_transfer:
            self.log.debug(
                "Rejecting resource (disabled) link_id=%s",
                self._fmt_link_id(link),
            )
            self._inc("resources_rejected")
            return False
        
        # Check size limit (immutable config)
        size = resource.total_size if hasattr(resource, "total_size") else resource.size
        if size > self.config.max_resource_bytes:
            self.log.warning(
                "Rejecting resource (too large: %s > %s) link_id=%s",
                size,
                self.config.max_resource_bytes,
                self._fmt_link_id(link),
            )
            self._inc("resources_rejected")
            return False
        
        # Check session exists and find expectation with minimal lock scope
        with self._state_lock:
            sess = self.session_manager.sessions.get(link)
            if not sess:
                self.log.debug(
                    "Rejecting resource (no session) link_id=%s",
                    self._fmt_link_id(link),
                )
                self._inc("resources_rejected")
                return False
            
            # Find matching expectation
            exp = self._find_resource_expectation(link, size)
        
        # Check expectation outside lock
        if not exp:
            self.log.warning(
                "Rejecting resource (no matching expectation) link_id=%s size=%s",
                self._fmt_link_id(link),
                size,
            )
            self._inc("resources_rejected")
            return False
        
        # Accept and register with minimal lock scope
        self.log.info(
            "Accepting resource link_id=%s size=%s kind=%s",
            self._fmt_link_id(link),
            size,
            exp.kind,
        )
        
        with self._state_lock:
            self._active_resources.setdefault(link, set()).add(resource)
            # Remember which expectation RID this resource was matched to so the
            # conclusion handler can verify and pop the correct entry.
            self._resource_bindings[resource] = exp.id
        
        return True

    def _resource_concluded(self, resource: RNS.Resource) -> None:
        """Callback when a Resource transfer completes."""
        link = resource.link
        
        with self._state_lock:
            # Remove from active set and retrieve any bound expectation RID.
            active_set = self._active_resources.get(link)
            if active_set:
                active_set.discard(resource)
            bound_rid = self._resource_bindings.pop(resource, None)

        if resource.status != RNS.Resource.COMPLETE:
            self.log.warning(
                "Resource transfer failed link_id=%s status=%s",
                self._fmt_link_id(link),
                resource.status,
            )
            return

        # Get payload outside the lock.
        try:
            payload = resource.data.read() if hasattr(resource.data, "read") else resource.data
            if isinstance(payload, bytearray):
                payload = bytes(payload)
        except Exception as e:
            self.log.error(
                "Failed to read resource data link_id=%s: %s",
                self._fmt_link_id(link),
                e,
            )
            return

        size = len(payload)
        actual_hash = hashlib.sha256(payload).digest()

        # Find expectation using bound RID first, then RID lookup, then size/sha fallback.
        exp = self._match_resource_expectation(link, rid=bound_rid, size=size, sha256=actual_hash)
        if not exp:
            self.log.warning(
                "Received resource without expectation link_id=%s size=%s",
                self._fmt_link_id(link),
                size,
            )
            return

        # Verify SHA256 if provided; keep expectation if mismatch so sender can retry.
        if exp.sha256 and actual_hash != exp.sha256:
            self.log.error(
                "Resource SHA256 mismatch link_id=%s expected=%s actual=%s",
                self._fmt_link_id(link),
                exp.sha256.hex(),
                actual_hash.hex(),
            )
            return

        # Pop expectation only after validation succeeds.
        self._pop_resource_expectation(link, exp.id)

        self._inc("resources_received")
        self._inc("resource_bytes_received", size)
        
        self.log.info(
            "Resource received link_id=%s size=%s kind=%s",
            self._fmt_link_id(link),
            size,
            exp.kind,
        )
        
        # Dispatch by kind
        try:
            self._dispatch_received_resource(link, exp, payload)
        except Exception as e:
            self.log.exception(
                "Failed to dispatch resource link_id=%s kind=%s: %s",
                self._fmt_link_id(link),
                exp.kind,
                e,
            )

    def _dispatch_received_resource(
        self, link: RNS.Link, exp: _ResourceExpectation, payload: bytes
    ) -> None:
        """Dispatch a received resource payload to appropriate handler."""
        if exp.kind == RES_KIND_NOTICE:
            # Decode as text and deliver as notice
            encoding = exp.encoding or "utf-8"
            try:
                text = payload.decode(encoding)
            except Exception as e:
                self.log.error(
                    "Failed to decode notice resource link_id=%s encoding=%s: %s",
                    self._fmt_link_id(link),
                    encoding,
                    e,
                )
                return
            
            self.log.info(
                "Received large NOTICE via resource link_id=%s room=%r chars=%s",
                self._fmt_link_id(link),
                exp.room,
                len(text),
            )
            
            # Forward NOTICE to room members if room is specified
            if exp.room and self.identity is not None:
                with self._state_lock:
                    sess = self.session_manager.sessions.get(link)
                    peer_hash = sess.get("peer") if sess else None
                    room_members = self.rooms.get(exp.room, set())
                
                if peer_hash and room_members:
                    notice_env = make_envelope(
                        T_NOTICE,
                        src=peer_hash,
                        room=exp.room,
                        body=text,
                    )
                    notice_payload = encode(notice_env)
                    
                    # Forward to all room members except sender
                    forwarded = 0
                    for other in room_members:
                        if other != link:
                            try:
                                other.packet(notice_payload)
                                forwarded += 1
                            except Exception as e:
                                self.log.warning(
                                    "Failed to forward NOTICE resource link_id=%s: %s",
                                    self._fmt_link_id(other),
                                    e,
                                )
                    
                    if forwarded > 0:
                        self._inc("notices_forwarded")
                        self.log.debug(
                            "Forwarded NOTICE resource to %d members room=%s",
                            forwarded,
                            exp.room,
                        )
            
        elif exp.kind == RES_KIND_MOTD:
            # Similar to NOTICE
            encoding = exp.encoding or "utf-8"
            try:
                text = payload.decode(encoding)
            except Exception as e:
                self.log.error(
                    "Failed to decode MOTD resource link_id=%s: %s",
                    self._fmt_link_id(link),
                    e,
                )
                return
            
            self.log.info(
                "Received MOTD via resource link_id=%s chars=%s",
                self._fmt_link_id(link),
                len(text),
            )
            
        elif exp.kind == RES_KIND_BLOB:
            # Generic binary data
            self.log.info(
                "Received BLOB via resource link_id=%s bytes=%s",
                self._fmt_link_id(link),
                len(payload),
            )
        else:
            self.log.warning(
                "Unknown resource kind link_id=%s kind=%s",
                self._fmt_link_id(link),
                exp.kind,
            )

    def _send_via_resource(
        self,
        link: RNS.Link,
        *,
        kind: str,
        payload: bytes,
        room: str | None = None,
        encoding: str | None = None,
    ) -> bool:
        """
        Send large payload via Resource.
        Returns True if successfully initiated, False otherwise.
        """
        if not self.config.enable_resource_transfer:
            return False
        
        size = len(payload)
        if size > self.config.max_resource_bytes:
            self.log.error(
                "Payload too large for resource transfer: %s > %s",
                size,
                self.config.max_resource_bytes,
            )
            return False
        
        # Generate resource ID
        rid = os.urandom(8)
        
        # Compute SHA256
        sha256 = hashlib.sha256(payload).digest()
        
        # Send envelope first
        if self.identity is None:
            return False
        
        envelope_body = {
            B_RES_ID: rid,
            B_RES_KIND: kind,
            B_RES_SIZE: size,
            B_RES_SHA256: sha256,
        }
        if encoding:
            envelope_body[B_RES_ENCODING] = encoding
        
        envelope = make_envelope(
            T_RESOURCE_ENVELOPE,
            src=self.identity.hash,
            room=room,
            body=envelope_body,
        )
        
        try:
            envelope_payload = encode(envelope)
            RNS.Packet(link, envelope_payload).send()
            self._inc("bytes_out", len(envelope_payload))
            
            self.log.debug(
                "Sent resource envelope link_id=%s rid=%s kind=%s size=%s",
                self._fmt_link_id(link),
                rid.hex(),
                kind,
                size,
            )
        except Exception as e:
            self.log.error(
                "Failed to send resource envelope link_id=%s: %s",
                self._fmt_link_id(link),
                e,
            )
            return False
        
        # Create and advertise resource
        try:
            resource = RNS.Resource(payload, link, advertise=True, auto_compress=False)
            
            with self._state_lock:
                self._active_resources.setdefault(link, set()).add(resource)
            
            self._inc("resources_sent")
            self._inc("resource_bytes_sent", size)
            
            self.log.info(
                "Sent resource link_id=%s rid=%s kind=%s size=%s",
                self._fmt_link_id(link),
                rid.hex(),
                kind,
                size,
            )
            return True
            
        except Exception as e:
            self.log.error(
                "Failed to create resource link_id=%s: %s",
                self._fmt_link_id(link),
                e,
            )
            return False

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
            if outgoing is None:
                self._send(link, env)
            else:
                self._queue_env(outgoing, link, env)
            return
        
        # Too large for packet - try resource if enabled and type is NOTICE
        if (
            self.config.enable_resource_transfer
            and msg_type == T_NOTICE
            and len(text.encode(encoding)) <= self.config.max_resource_bytes
        ):
            text_bytes = text.encode(encoding)
            resource_kind = kind if kind is not None else RES_KIND_NOTICE
            if self._send_via_resource(
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
        
        # Fall back to chunking for NOTICE
        if msg_type == T_NOTICE:
            if outgoing is None:
                outgoing = []
                self._queue_notice_chunks(outgoing, link, room=room, text=text)
                for out_link, chunk_payload in outgoing:
                    self._inc("bytes_out", len(chunk_payload))
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
        if self._started_wall_time is None:
            self._started_wall_time = time.time()
        if self._started_monotonic is None:
            self._started_monotonic = time.monotonic()
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
            self._inc("announces")
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
            self.rooms.clear()
            self._resource_expectations.clear()
            self._active_resources.clear()

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

    def _load_room_registry_from_path(
        self,
        reg_path: str,
        *,
        invite_timeout_s: float | None = None,
    ) -> tuple[dict[str, dict[str, Any]], str | None]:
        if not reg_path:
            return {}, "room_registry_path is empty"
        if not os.path.exists(reg_path):
            return {}, f"room registry file not found: {reg_path}"
        try:
            from tomlkit import parse  # type: ignore
        except Exception:
            return {}, "missing dependency tomlkit"

        try:
            with open(reg_path, encoding="utf-8") as f:
                doc = parse(f.read())
        except Exception as e:
            return {}, f"failed to parse rooms registry: {e}"

        rooms = doc.get("rooms")
        if rooms is None:
            return {}, None
        if not isinstance(rooms, dict):
            return {}, "rooms registry: [rooms] must be a table"

        def _parse_list(cfg: dict[str, Any], name: str) -> set[bytes]:
            out: set[bytes] = set()
            lst = cfg.get(name)
            if isinstance(lst, list):
                for item in lst:
                    if not isinstance(item, str) or not item.strip():
                        continue
                    try:
                        out.add(self._parse_identity_hash(item))
                    except Exception:
                        continue
            return out

        registry: dict[str, dict[str, Any]] = {}
        for raw_room, raw_cfg in rooms.items():
            if not isinstance(raw_room, str):
                continue
            try:
                room = self._norm_room(raw_room)
            except Exception:
                continue
            if not isinstance(raw_cfg, dict):
                continue

            founder_hex = raw_cfg.get("founder")
            founder = None
            if isinstance(founder_hex, str) and founder_hex.strip():
                try:
                    founder = self._parse_identity_hash(founder_hex)
                except Exception:
                    founder = None

            topic = raw_cfg.get("topic")
            if not isinstance(topic, str) or not topic.strip():
                topic = None

            moderated = bool(raw_cfg.get("moderated", False))

            invite_only = bool(raw_cfg.get("invite_only", False))
            topic_ops_only = bool(raw_cfg.get("topic_ops_only", False))
            no_outside_msgs = bool(raw_cfg.get("no_outside_msgs", False))

            key = raw_cfg.get("key")
            if not isinstance(key, str) or not key:
                key = None

            last_used_ts = raw_cfg.get("last_used_ts")
            try:
                last_used_ts = float(last_used_ts) if last_used_ts is not None else None
            except Exception:
                last_used_ts = None

            ops = _parse_list(raw_cfg, "operators")
            voiced = _parse_list(raw_cfg, "voiced")
            bans = _parse_list(raw_cfg, "bans")

            invited: dict[bytes, float] = {}
            raw_inv = raw_cfg.get("invited")
            now = float(time.time())
            ttl_src = invite_timeout_s
            if ttl_src is None:
                ttl_src = self.config.room_invite_timeout_s
            ttl = float(ttl_src) if ttl_src else 0.0
            if ttl <= 0:
                ttl = 900.0

            # New format: invited is a table mapping hex->expiry_ts
            if isinstance(raw_inv, dict):
                for k, v in raw_inv.items():
                    if not isinstance(k, str) or not k.strip():
                        continue
                    try:
                        h = self._parse_identity_hash(k)
                    except Exception:
                        continue
                    try:
                        exp = float(v)
                    except Exception:
                        continue
                    if exp > now:
                        invited[h] = exp

            # Back-compat: invited as a list of identity hashes => grant ttl from now
            elif isinstance(raw_inv, list):
                for item in raw_inv:
                    if not isinstance(item, str) or not item.strip():
                        continue
                    try:
                        h = self._parse_identity_hash(item)
                    except Exception:
                        continue
                    invited[h] = now + ttl

            if founder is not None:
                ops.add(founder)

            registry[room] = {
                "founder": founder,
                "registered": True,
                "topic": topic,
                "moderated": moderated,
                "invite_only": invite_only,
                "topic_ops_only": topic_ops_only,
                "no_outside_msgs": no_outside_msgs,
                "key": key,
                "ops": ops,
                "voiced": voiced,
                "bans": bans,
                "invited": invited,
                "last_used_ts": last_used_ts,
            }

        return registry, None

    def _diff_room_registry_summary(
        self, old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]
    ) -> list[str]:
        old_rooms = set(old.keys())
        new_rooms = set(new.keys())
        added = sorted(new_rooms - old_rooms)
        removed = sorted(old_rooms - new_rooms)

        lines: list[str] = []
        if added:
            preview = ", ".join(added[:10])
            suffix = "" if len(added) <= 10 else f" (+{len(added) - 10} more)"
            lines.append(f"rooms_added={len(added)}: {preview}{suffix}")
        if removed:
            preview = ", ".join(removed[:10])
            suffix = "" if len(removed) <= 10 else f" (+{len(removed) - 10} more)"
            lines.append(f"rooms_removed={len(removed)}: {preview}{suffix}")
        if not lines:
            lines.append(f"rooms_changed=0 (registered_rooms={len(new_rooms)})")
        return lines

    def _room_modes(self, room: str) -> dict[str, Any]:
        st = self._room_state_ensure(room)
        registered = bool(st.get("registered", False))
        moderated = bool(st.get("moderated", False))
        invite_only = bool(st.get("invite_only", False))
        topic_ops_only = bool(st.get("topic_ops_only", False))
        no_outside_msgs = bool(st.get("no_outside_msgs", False))
        private = bool(st.get("private", False))
        key = st.get("key")
        has_key = isinstance(key, str) and bool(key)
        return {
            "registered": registered,
            "moderated": moderated,
            "invite_only": invite_only,
            "topic_ops_only": topic_ops_only,
            "no_outside_msgs": no_outside_msgs,
            "private": private,
            "has_key": has_key,
        }

    def _room_mode_string(self, room: str) -> str:
        m = self._room_modes(room)
        flags: list[str] = []
        # Keep roughly IRC-ish order.
        if m.get("invite_only"):
            flags.append("i")
        if m.get("has_key"):
            flags.append("k")
        if m.get("moderated"):
            flags.append("m")
        if m.get("no_outside_msgs"):
            flags.append("n")
        if m.get("private"):
            flags.append("p")
        if m.get("registered"):
            flags.append("r")
        if m.get("topic_ops_only"):
            flags.append("t")
        return "+" + "".join(flags) if flags else "(none)"

    def _broadcast_room_mode(
        self, room: str, outgoing: list[tuple[RNS.Link, bytes]] | None = None
    ) -> None:
        mode_txt = self._room_mode_string(room)
        with self._state_lock:
            recipients = list(self.rooms.get(room, set()))
        for other in recipients:
            self._emit_notice(
                outgoing, other, room, f"mode for {room} is now: {mode_txt}"
            )

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
            old_registry = dict(self._room_registry)

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
        new_registry, reg_err = self._load_room_registry_from_path(
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
            self._room_registry = new_registry

            # Merge registry into live per-room state (for active rooms).
            # This makes /reload take effect immediately for existing members.
            for r, st in list(self._room_state.items()):
                if not isinstance(st, dict):
                    continue

                reg = self._room_registry.get(r)
                if reg is None:
                    # If a room was unregistered on disk, reflect that.
                    if st.get("registered"):
                        st["registered"] = False
                    continue

                st["registered"] = True

                founder = reg.get("founder")
                if isinstance(founder, (bytes, bytearray)):
                    st["founder"] = bytes(founder)

                # Simple scalar fields
                for key in (
                    "topic",
                    "moderated",
                    "invite_only",
                    "topic_ops_only",
                    "no_outside_msgs",
                    "key",
                    "last_used_ts",
                ):
                    if key in reg:
                        st[key] = reg.get(key)

                # Set fields
                for key in ("ops", "voiced", "bans"):
                    v = reg.get(key)
                    if isinstance(v, set):
                        st[key] = set(v)

                # Invites (dict[bytes, float])
                inv = reg.get("invited")
                if isinstance(inv, dict):
                    st["invited"] = dict(inv)

                # Ensure founder stays op.
                founder_st = st.get("founder")
                if isinstance(founder_st, (bytes, bytearray)):
                    ops = st.setdefault("ops", set())
                    if isinstance(ops, set):
                        ops.add(bytes(founder_st))

        self._ensure_worker_threads()

        # Apply logging changes immediately.
        try:
            configure_logging(self.config)
        except Exception:
            self.log.exception("Failed to reconfigure logging")

        cfg_changes = self._diff_config_summary(old_cfg, new_cfg)
        room_changes = self._diff_room_registry_summary(old_registry, new_registry)

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

    def _room_registry_path_for_writes(self) -> str | None:
        p = self.config.room_registry_path
        if not p:
            return
        return expand_path(str(p))

    def _load_registered_rooms_from_registry(self) -> None:
        reg_path = self._room_registry_path_for_writes()
        if not reg_path:
            return
        registry, err = self._load_room_registry_from_path(reg_path)
        if err is not None:
            return
        self._room_registry = registry

    def _room_state_get(self, room: str) -> dict[str, Any] | None:
        return self._room_state.get(room)

    def _room_state_ensure(
        self, room: str, *, founder: bytes | None = None
    ) -> dict[str, Any]:
        st = self._room_state.get(room)
        if st is not None:
            if st.get("founder") is None and founder is not None:
                st["founder"] = founder
                st.setdefault("ops", set()).add(founder)
            return st

        if room in self._room_registry:
            base = self._room_registry[room]
            invited = base.get("invited")
            invited_dict: dict[bytes, float] = {}
            if isinstance(invited, dict):
                for k, v in invited.items():
                    if isinstance(k, (bytes, bytearray)):
                        try:
                            invited_dict[bytes(k)] = float(v)
                        except Exception:
                            continue
            st = {
                "founder": base.get("founder"),
                "registered": True,
                "topic": base.get("topic"),
                "moderated": bool(base.get("moderated", False)),
                "invite_only": bool(base.get("invite_only", False)),
                "topic_ops_only": bool(base.get("topic_ops_only", False)),
                "no_outside_msgs": bool(base.get("no_outside_msgs", False)),
                "private": bool(base.get("private", False)),
                "key": base.get("key"),
                "ops": set(base.get("ops", set())),
                "voiced": set(base.get("voiced", set())),
                "bans": set(base.get("bans", set())),
                "invited": invited_dict,
                "last_used_ts": base.get("last_used_ts"),
            }
            self._room_state[room] = st
            return st

        st = {
            "founder": founder,
            "registered": False,
            "topic": None,
            "moderated": False,
            "invite_only": False,
            "topic_ops_only": False,
            "no_outside_msgs": False,
            "private": False,
            "key": None,
            "ops": set([founder]) if founder is not None else set(),
            "voiced": set(),
            "bans": set(),
            "invited": {},
            "last_used_ts": None,
        }
        self._room_state[room] = st
        return st

    def _prune_expired_invites(self, st: dict[str, Any]) -> bool:
        inv = st.get("invited")
        if not isinstance(inv, dict) or not inv:
            return False
        now = float(time.time())
        removed_any = False
        for h, exp in list(inv.items()):
            try:
                exp_f = float(exp)
            except Exception:
                exp_f = 0.0
            if exp_f <= now:
                inv.pop(h, None)
                removed_any = True
        return removed_any

    def _is_invited(self, st: dict[str, Any], peer_hash: bytes) -> bool:
        inv = st.get("invited")
        if not isinstance(inv, dict) or not inv:
            return False
        now = float(time.time())
        exp = inv.get(peer_hash)
        try:
            exp_f = float(exp) if exp is not None else 0.0
        except Exception:
            exp_f = 0.0
        if exp_f <= now:
            inv.pop(peer_hash, None)
            return False
        return True

    def _touch_room(self, room: str) -> None:
        try:
            st = self._room_state_ensure(room)
            ts = float(time.time())
            st["last_used_ts"] = ts
            reg = self._room_registry.get(room)
            if isinstance(reg, dict):
                reg["last_used_ts"] = ts
        except Exception:
            pass

    def _is_server_op(self, peer_hash: bytes | None) -> bool:
        return self._is_trusted(peer_hash)

    def _is_room_op(self, room: str, peer_hash: bytes | None) -> bool:
        if peer_hash is None:
            return False
        if self._is_server_op(peer_hash):
            return True
        st = self._room_state_ensure(room)
        founder = st.get("founder")
        if isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash:
            return True
        ops = st.get("ops")
        return isinstance(ops, set) and peer_hash in ops

    def _is_room_voiced(self, room: str, peer_hash: bytes | None) -> bool:
        if peer_hash is None:
            return False
        if self._is_room_op(room, peer_hash):
            return True
        st = self._room_state_ensure(room)
        voiced = st.get("voiced")
        return isinstance(voiced, set) and peer_hash in voiced

    def _is_room_banned(self, room: str, peer_hash: bytes | None) -> bool:
        if peer_hash is None:
            return False
        st = self._room_state_ensure(room)
        bans = st.get("bans")
        return isinstance(bans, set) and peer_hash in bans

    def _room_moderated(self, room: str) -> bool:
        st = self._room_state_ensure(room)
        return bool(st.get("moderated", False))

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

    def _persist_room_state_to_registry(self, link: RNS.Link, room: str | None) -> None:
        if room is None:
            return
        reg_path = self._room_registry_path_for_writes()
        if not reg_path:
            return
        st = self._room_state_get(room)
        if not st or not st.get("registered"):
            return

        try:
            from tomlkit import dumps, parse, table  # type: ignore
        except Exception:
            return

        try:
            with self._room_registry_write_lock:
                file_stat = None
                try:
                    file_stat = os.stat(reg_path)
                except Exception:
                    file_stat = None

                with open(reg_path, encoding="utf-8") as f:
                    doc = parse(f.read())

                rooms = doc.get("rooms")
                if rooms is None:
                    rooms = table()
                    doc["rooms"] = rooms

                room_tbl = rooms.get(room)
                if room_tbl is None:
                    room_tbl = table()
                    rooms[room] = room_tbl

                founder = st.get("founder")
                if isinstance(founder, (bytes, bytearray)):
                    room_tbl["founder"] = bytes(founder).hex()

                topic = st.get("topic")
                if isinstance(topic, str) and topic.strip():
                    room_tbl["topic"] = topic
                else:
                    if "topic" in room_tbl:
                        del room_tbl["topic"]

                room_tbl["moderated"] = bool(st.get("moderated", False))

                room_tbl["invite_only"] = bool(st.get("invite_only", False))
                room_tbl["topic_ops_only"] = bool(st.get("topic_ops_only", False))
                room_tbl["no_outside_msgs"] = bool(st.get("no_outside_msgs", False))

                key = st.get("key")
                if isinstance(key, str) and key:
                    room_tbl["key"] = key
                else:
                    if "key" in room_tbl:
                        del room_tbl["key"]

                last_used_ts = st.get("last_used_ts")
                if last_used_ts is None:
                    last_used_ts = float(time.time())
                try:
                    room_tbl["last_used_ts"] = float(last_used_ts)
                except Exception:
                    room_tbl["last_used_ts"] = float(time.time())

                ops = st.get("ops")
                if isinstance(ops, set):
                    room_tbl["operators"] = sorted(
                        bytes(x).hex() for x in ops if isinstance(x, (bytes, bytearray))
                    )

                voiced = st.get("voiced")
                if isinstance(voiced, set):
                    room_tbl["voiced"] = sorted(
                        bytes(x).hex()
                        for x in voiced
                        if isinstance(x, (bytes, bytearray))
                    )

                bans = st.get("bans")
                if isinstance(bans, set):
                    room_tbl["bans"] = sorted(
                        bytes(x).hex()
                        for x in bans
                        if isinstance(x, (bytes, bytearray))
                    )

                invited = st.get("invited")
                if isinstance(invited, dict):
                    inv_tbl = {}
                    now = float(time.time())
                    for h, exp in invited.items():
                        if not isinstance(h, (bytes, bytearray)):
                            continue
                        try:
                            exp_f = float(exp)
                        except Exception:
                            continue
                        if exp_f > now:
                            inv_tbl[bytes(h).hex()] = exp_f
                    room_tbl["invited"] = inv_tbl

                new_text = dumps(doc)
                with open(reg_path, "w", encoding="utf-8") as f:
                    f.write(new_text)

                if file_stat is not None:
                    try:
                        os.chmod(reg_path, file_stat.st_mode)
                    except Exception:
                        pass
        except Exception as e:
            self._notice_to(link, room, f"room config persist failed: {e}")

    def _delete_room_from_registry(self, link: RNS.Link, room: str) -> None:
        reg_path = self._room_registry_path_for_writes()
        if not reg_path:
            return
        try:
            from tomlkit import dumps, parse  # type: ignore
        except Exception:
            return

        try:
            with self._room_registry_write_lock:
                file_stat = None
                try:
                    file_stat = os.stat(reg_path)
                except Exception:
                    file_stat = None

                with open(reg_path, encoding="utf-8") as f:
                    doc = parse(f.read())

                rooms = doc.get("rooms")
                if isinstance(rooms, dict) and room in rooms:
                    try:
                        del rooms[room]
                    except Exception:
                        rooms.pop(room, None)

                new_text = dumps(doc)
                with open(reg_path, "w", encoding="utf-8") as f:
                    f.write(new_text)

                if file_stat is not None:
                    try:
                        os.chmod(reg_path, file_stat.st_mode)
                    except Exception:
                        pass
        except Exception as e:
            self._notice_to(link, room, f"room unregister persist failed: {e}")

    def _prune_loop(self) -> None:
        while not self._shutdown.is_set():
            interval = float(self.config.room_registry_prune_interval_s)
            prune_after = float(self.config.room_registry_prune_after_s)
            if interval <= 0 or prune_after <= 0:
                time.sleep(1.0)
                continue

            time.sleep(interval)
            if self._shutdown.is_set():
                break

            now = float(time.time())

            rooms_to_prune: list[str] = []
            dummy_link: RNS.Link | None = None

            with self._state_lock:
                dummy_link = next(iter(self.session_manager.sessions.keys()), None)

                for room, reg in list(self._room_registry.items()):
                    # Skip active rooms.
                    if room in self.rooms and self.rooms.get(room):
                        continue

                    last_used = reg.get("last_used_ts")
                    try:
                        last_used = float(last_used) if last_used is not None else None
                    except Exception:
                        last_used = None
                    if last_used is None:
                        # Never-used rooms are eligible after prune_after from process start.
                        last_used = self._started_wall_time or now

                    if (now - float(last_used)) < prune_after:
                        continue

                    # Prune in-memory under lock.
                    self._room_registry.pop(room, None)
                    self._room_state.pop(room, None)
                    rooms_to_prune.append(room)

            if dummy_link is not None:
                for room in rooms_to_prune:
                    self._delete_room_from_registry(dummy_link, room)

            for room in rooms_to_prune:
                self.log.info("Pruned unused registered room %s", room)

    def _resource_cleanup_loop(self) -> None:
        """Periodically cleanup expired resource expectations."""
        while not self._shutdown.is_set():
            # Run cleanup every 30 seconds
            time.sleep(30.0)
            if self._shutdown.is_set():
                break
            try:
                self._cleanup_all_expired_expectations()
            except Exception:
                self.log.exception("Resource cleanup failed")

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
        self._inc("bytes_out", len(payload))
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
        self._inc("errors_sent")
        env = make_envelope(T_ERROR, src=src, room=room, body=text)
        if outgoing is None:
            self._send(link, env)
        else:
            self._queue_env(outgoing, link, env)

    def _format_stats(self) -> str:
        now_mono = time.monotonic()
        started_mono = self._started_monotonic
        uptime_s = (now_mono - started_mono) if started_mono is not None else 0.0

        with self._state_lock:
            session_stats = self.session_manager.get_stats()
            sessions_total = session_stats["total"]
            sessions_welcomed = session_stats["welcomed"]
            sessions_identified = session_stats["identified"]

            rooms_total = len(self.rooms)
            memberships = sum(len(v) for v in self.rooms.values())

            top_rooms = sorted(
                ((room, len(links)) for room, links in self.rooms.items()),
                key=lambda x: (-x[1], x[0]),
            )[:5]

            trusted_count = len(self._trusted)
            banned_count = len(self._banned)
            c = dict(self._counters)

        lines: list[str] = []
        lines.append(f"rrcd {__version__} stats")
        lines.append(f"uptime_s={uptime_s:.1f}")
        lines.append(
            f"clients_total={sessions_total} "
            f"clients_identified={sessions_identified} "
            f"clients_welcomed={sessions_welcomed}"
        )
        lines.append(f"rooms={rooms_total} memberships={memberships}")

        if top_rooms:
            lines.append("top_rooms=" + ", ".join(f"{r}:{n}" for r, n in top_rooms))

        lines.append(f"trust: trusted={trusted_count} banned={banned_count}")
        lines.append(
            f"limits: rate_limit_msgs_per_minute={self.config.rate_limit_msgs_per_minute} "
            f"max_rooms_per_session={self.config.max_rooms_per_session} "
            f"max_room_name_len={self.config.max_room_name_len} "
            f"nick_max_chars={self.config.nick_max_chars}"
        )
        lines.append(
            f"features: ping_interval_s={self.config.ping_interval_s} "
            f"ping_timeout_s={self.config.ping_timeout_s} "
            f"announce_on_start={self.config.announce_on_start} "
            f"announce_period_s={self.config.announce_period_s}"
        )

        lines.append(
            "io: pkts_in={} pkts_bad={} bytes_in={} bytes_out={}".format(
                c.get("pkts_in", 0),
                c.get("pkts_bad", 0),
                c.get("bytes_in", 0),
                c.get("bytes_out", 0),
            )
        )
        lines.append(
            "events: joins={} parts={} msgs_fwd={} notices_fwd={} errors_sent={} rate_limited={}".format(
                c.get("joins", 0),
                c.get("parts", 0),
                c.get("msgs_forwarded", 0),
                c.get("notices_forwarded", 0),
                c.get("errors_sent", 0),
                c.get("rate_limited", 0),
            )
        )
        lines.append(
            "pings: in={} out={} pongs: in={} out={}".format(
                c.get("pings_in", 0),
                c.get("pings_out", 0),
                c.get("pongs_in", 0),
                c.get("pongs_out", 0),
            )
        )
        lines.append(
            "resources: sent={} received={} rejected={} bytes_sent={} bytes_received={}".format(
                c.get("resources_sent", 0),
                c.get("resources_received", 0),
                c.get("resources_rejected", 0),
                c.get("resource_bytes_sent", 0),
                c.get("resource_bytes_received", 0),
            )
        )

        return "".join(lines)

    def _find_target_link(self, token: str, room: str | None = None) -> RNS.Link | None:
        """Find a link by nick or identity hash prefix. Uses indexes for O(1) lookups.
        Returns the link if exactly one match, None otherwise.
        """
        result = self._find_target_links(token, room)
        if len(result) == 1:
            return result[0]
        return None

    def _find_target_links(self, token: str, room: str | None = None) -> list[RNS.Link]:
        """Find all links matching a nick or identity hash prefix.
        Returns list of matching links (empty if none, multiple if ambiguous).
        """
        t = token.strip().lower()
        if not t:
            return []

        # If it's hex-like, treat as an identity hash prefix.
        hex_candidate = t[2:] if t.startswith("0x") else t
        if (
            all(c in "0123456789abcdef" for c in hex_candidate)
            and len(hex_candidate) >= 6
        ):
            try:
                prefix = bytes.fromhex(hex_candidate)
            except Exception:
                prefix = None
            
            if prefix is not None:
                with self._state_lock:
                    # Search hash index for matching prefixes
                    matches: list[RNS.Link] = []
                    for peer_hash, candidate_link in self.session_manager._index_by_hash.items():
                        if peer_hash.startswith(prefix):
                            # Check room membership if specified
                            if room is not None:
                                sess = self.session_manager.sessions.get(candidate_link)
                                if sess and room not in sess.get("rooms", set()):
                                    continue
                            matches.append(candidate_link)
                
                return matches

        # Otherwise treat as nickname - use nick index for O(1) lookup
        with self._state_lock:
            candidate_links = self.session_manager._index_by_nick.get(t, set())
            if not candidate_links:
                return []
            
            # Filter by room membership if specified
            if room is not None:
                matches = []
                for candidate_link in candidate_links:
                    sess = self.session_manager.sessions.get(candidate_link)
                    if sess and room in sess.get("rooms", set()):
                        matches.append(candidate_link)
            else:
                matches = list(candidate_links)
        
        return matches

    def _format_ambiguous_targets(
        self, token: str, matches: list[RNS.Link]
    ) -> str:
        """Format a helpful message when target lookup is ambiguous."""
        if not matches:
            return f"target '{token}' not found"
        
        with self._state_lock:
            items = []
            for match_link in matches:
                sess = self.session_manager.sessions.get(match_link)
                if not sess:
                    continue
                peer = sess.get("peer")
                nick = sess.get("nick")
                hash_str = self._fmt_hash(peer, prefix=16) if peer else "?"
                nick_str = f"nick={nick!r}" if nick else "(no nick)"
                items.append(f"{hash_str} {nick_str}")
        
        if len(items) == 0:
            return f"target '{token}' not found"
        
        return (
            f"ambiguous: '{token}' matches {len(items)} identities:\n"
            + "\n".join(f"  - {item}" for item in items)
            + "\nUse full or longer identity hash to disambiguate."
        )

    def _handle_operator_command(
        self,
        link: RNS.Link,
        peer_hash: bytes,
        room: str | None,
        text: str,
        *,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
    ) -> bool:
        # Returns True if it was a recognized command (handled). Unknown commands
        # return False so the message can be forwarded as normal chat.
        cmdline = text.strip()
        if not cmdline.startswith("/"):
            return False

        parts = [p for p in cmdline[1:].split() if p]
        if not parts:
            return False

        cmd = parts[0].lower()

        if cmd == "reload":
            if not self._is_server_op(peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True
            # Hub-level command - send responses without room field
            self._reload_config_and_rooms(link, None, outgoing)
            return True

        # Global/server-operator commands
        if cmd == "stats":
            if not self._is_server_op(peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True
            # Send response without room field for hub-level command
            self._emit_notice(outgoing, link, None, self._format_stats())
            return True

        if cmd == "list":
            # List all registered, non-private rooms with their topics
            with self._state_lock:
                registered_rooms = []
                for room_name, st in self._room_state.items():
                    if st.get("registered") and not st.get("private"):
                        topic = st.get("topic")
                        registered_rooms.append((room_name, topic))
                
                # Also check room registry for rooms not currently in room_state
                for room_name, reg in self._room_registry.items():
                    if room_name not in self._room_state:
                        if not reg.get("private"):
                            topic = reg.get("topic")
                            registered_rooms.append((room_name, topic))

            if not registered_rooms:
                self._emit_notice(outgoing, link, None, "No public rooms registered")
                return True

            # Sort rooms alphabetically
            registered_rooms.sort(key=lambda x: x[0])
            
            # Format room list with topics
            lines = ["Registered public rooms:"]
            for room_name, topic in registered_rooms:
                if topic:
                    lines.append(f"  {room_name} - {topic}")
                else:
                    lines.append(f"  {room_name}")
            
            self._emit_notice(outgoing, link, None, "\n".join(lines))
            return True

        if cmd in ("who", "names"):
            target_room = room
            if len(parts) >= 2:
                target_room = parts[1]
            if not isinstance(target_room, str) or not target_room:
                self._emit_notice(outgoing, link, None, "usage: /who [room]")
                return True
            try:
                r = self._norm_room(target_room)
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            # Check if room is private - only server operators can see private rooms
            st = self._room_state_get(r)
            if st and st.get("private"):
                if not self._is_server_op(peer_hash):
                    self._emit_notice(outgoing, link, None, f"room {r} is private")
                    return True

            members = []
            for other in sorted(self.rooms.get(r, set()), key=lambda x: id(x)):
                s = self.session_manager.sessions.get(other)
                if not s:
                    continue
                nick = s.get("nick")
                ph = s.get("peer")
                ident = bytes(ph).hex() if isinstance(ph, (bytes, bytearray)) else "?"
                if isinstance(nick, str) and nick:
                    members.append(f"{nick} ({ident[:12]})")
                else:
                    members.append(ident)
            # Send response without room field for hub-level query
            self._emit_notice(
                outgoing,
                link,
                None,
                f"members in {r}: " + (", ".join(members) if members else "(none)"),
            )
            return True

        if cmd == "kick":
            if len(parts) < 3:
                self._emit_notice(
                    outgoing, link, None, "usage: /kick <room> <nick|hashprefix>"
                )
                return True
            target_room = parts[1]
            target = parts[2]
            try:
                r = self._norm_room(target_room)
            except Exception as e:
                self._emit_notice(outgoing, link, room, f"bad room: {e}")
                return True

            if not self._is_room_op(r, peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            target_link = self._find_target_link(target, room=r)
            if target_link is None:
                # Check if ambiguous or just not found
                all_matches = self._find_target_links(target, room=r)
                self._emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(target, all_matches)
                )
                return True

            tsess = self.session_manager.sessions.get(target_link)
            if not tsess or r not in tsess.get("rooms", set()):
                self._emit_notice(outgoing, link, room, "target not in room")
                return True

            tsess["rooms"].discard(r)
            if r in self.rooms:
                self.rooms[r].discard(target_link)
                if not self.rooms[r]:
                    self.rooms.pop(r, None)

            if self.identity is not None:
                self._emit_error(
                    outgoing,
                    target_link,
                    src=self.identity.hash,
                    text=f"kicked from {r}",
                    room=r,
                )
            self._emit_notice(outgoing, link, room, f"kicked {target} from {r}")
            return True

        if cmd == "kline":
            if not self._is_server_op(peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True

            # Hub-level command - all responses without room field
            if len(parts) < 2:
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /kline add|del|list [nick|hashprefix|hash]",
                )
                return True

            op = parts[1].strip().lower()
            if op == "list":
                items = sorted(h.hex() for h in self._banned)
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "klines: " + (", ".join(items) if items else "(none)"),
                )
                return True

            if op not in ("add", "del"):
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /kline add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 3:
                self._emit_notice(
                    outgoing, link, None, f"usage: /kline {op} <nick|hashprefix|hash>"
                )
                return True

            target = parts[2]
            if op == "add":
                target_link = self._find_target_link(target)
                if target_link is not None:
                    tsess = self.session_manager.sessions.get(target_link)
                    ph = tsess.get("peer") if tsess else None
                    if isinstance(ph, (bytes, bytearray)):
                        self._banned.add(bytes(ph))
                        self._persist_banned_identities_to_config(link, None, outgoing)
                    try:
                        target_link.teardown()
                    except Exception:
                        pass
                    self._emit_notice(outgoing, link, None, f"kline added for {target}")
                    return True

                # Not found as active link - check if ambiguous or try as raw hash
                all_matches = self._find_target_links(target, room=None)
                if all_matches:
                    # Ambiguous
                    self._emit_notice(
                        outgoing, link, None, self._format_ambiguous_targets(target, all_matches)
                    )
                    return True

                # Try as raw hash
                try:
                    h = self._parse_identity_hash(target)
                except Exception as e:
                    self._emit_notice(outgoing, link, None, f"bad identity hash: {e}")
                    return True
                self._banned.add(h)
                self._persist_banned_identities_to_config(link, None, outgoing)
                self._emit_notice(outgoing, link, None, f"kline added for {h.hex()}")
                return True

            # op == "del"
            try:
                h = self._parse_identity_hash(target)
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad identity hash: {e}")
                return True

            if h in self._banned:
                self._banned.discard(h)
                self._persist_banned_identities_to_config(link, None, outgoing)
                self._emit_notice(outgoing, link, None, f"kline removed for {h.hex()}")
            else:
                self._emit_notice(outgoing, link, None, f"not klined: {h.hex()}")
            return True

        # Room-scoped moderation and maintenance
        if cmd == "register":
            if len(parts) < 2:
                self._emit_notice(outgoing, link, None, "usage: /register <room>")
                return True
            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            # Registration rules: requester must be in the room and must be the founder.
            # (No server-op override by design.)
            if (
                not room
                or self._norm_room(room) != r
                or r not in self.session_manager.sessions.get(link, {}).get("rooms", set())
            ):
                self._emit_notice(
                    outgoing, link, room, "must be present in the room to register it"
                )
                return True

            st = self._room_state_ensure(r)

            # Clean up expired invites (best-effort).
            if self._prune_expired_invites(st) and bool(st.get("registered")):
                self._persist_room_state_to_registry(link, r)
            founder = st.get("founder")
            if not (
                isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash
            ):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="only the room founder can register",
                        room=r,
                    )
                return True

            if not self._room_registry_path_for_writes():
                self._emit_notice(
                    outgoing, link, room, "cannot register room: no room_registry_path"
                )
                return True
            st["registered"] = True
            # Default modes for registered rooms: +nrt
            st["no_outside_msgs"] = True
            st["topic_ops_only"] = True
            if isinstance(founder, (bytes, bytearray)):
                st.setdefault("ops", set()).add(bytes(founder))
            self._touch_room(r)

            # Ensure registry mirrors registered rooms.
            self._room_registry[r] = {
                "founder": bytes(founder)
                if isinstance(founder, (bytes, bytearray))
                else None,
                "registered": True,
                "topic": st.get("topic"),
                "moderated": bool(st.get("moderated", False)),
                "ops": set(st.get("ops", set()))
                if isinstance(st.get("ops"), set)
                else set(),
                "voiced": set(st.get("voiced", set()))
                if isinstance(st.get("voiced"), set)
                else set(),
                "bans": set(st.get("bans", set()))
                if isinstance(st.get("bans"), set)
                else set(),
                "last_used_ts": st.get("last_used_ts"),
            }

            self._persist_room_state_to_registry(link, r)
            self._emit_notice(outgoing, link, room, f"registered room {r}")
            return True

        if cmd == "unregister":
            if len(parts) < 2:
                self._emit_notice(outgoing, link, None, "usage: /unregister <room>")
                return True
            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            if (
                not room
                or self._norm_room(room) != r
                or r not in self.session_manager.sessions.get(link, {}).get("rooms", set())
            ):
                self._emit_notice(
                    outgoing, link, room, "must be present in the room to unregister it"
                )
                return True

            st = self._room_state_ensure(r)
            founder = st.get("founder")
            if not (
                isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash
            ):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="only the room founder can unregister",
                        room=r,
                    )
                return True

            if not st.get("registered"):
                self._emit_notice(outgoing, link, room, f"room {r} is not registered")
                return True

            st["registered"] = False
            self._room_registry.pop(r, None)
            self._delete_room_from_registry(link, r)
            # Drop state if empty.
            if r not in self.rooms or not self.rooms.get(r):
                self._room_state.pop(r, None)
            self._emit_notice(outgoing, link, room, f"unregistered room {r}")
            return True

        if cmd == "topic":
            if len(parts) < 2:
                self._emit_notice(outgoing, link, None, "usage: /topic <room> [topic]")
                return True
            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            st = self._room_state_ensure(r)
            if len(parts) == 2:
                topic = st.get("topic")
                self._emit_notice(
                    outgoing,
                    link,
                    room,
                    f"topic for {r}: {topic if topic else '(none)'}",
                )
                return True

            if not self._is_room_op(r, peer_hash):
                st = self._room_state_ensure(r)
                if bool(st.get("topic_ops_only", False)):
                    if self.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.identity.hash,
                            text="not authorized (+t)",
                            room=r,
                        )
                    return True

            topic = " ".join(parts[2:]).strip()
            st["topic"] = topic if topic else None
            self._touch_room(r)
            self._persist_room_state_to_registry(link, r)
            # Broadcast topic change to current members.
            for other in list(self.rooms.get(r, set())):
                self._emit_notice(
                    outgoing,
                    other,
                    r,
                    f"topic for {r} is now: {topic if topic else '(cleared)'}",
                )
            return True

        if cmd in ("op", "deop", "voice", "devoice"):
            if len(parts) < 3:
                self._emit_notice(
                    outgoing, link, None, f"usage: /{cmd} <room> <nick|hashprefix|hash>"
                )
                return True
            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            if not self._is_room_op(r, peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True
            
            target_hash, all_matches = self._resolve_identity_hash_with_matches(parts[2], room=r)
            if target_hash is None:
                self._emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[2], all_matches)
                )
                return True
            
            st = self._room_state_ensure(r)
            founder = st.get("founder")
            founder_b = (
                bytes(founder) if isinstance(founder, (bytes, bytearray)) else None
            )

            if cmd in ("op", "deop"):
                ops = st.setdefault("ops", set())
                if not isinstance(ops, set):
                    ops = set()
                    st["ops"] = ops
                if cmd == "op":
                    ops.add(target_hash)
                    self._touch_room(r)
                    self._persist_room_state_to_registry(link, r)
                    self._emit_notice(outgoing, link, room, f"op granted in {r}")
                    return True
                else:
                    if founder_b is not None and target_hash == founder_b:
                        self._emit_notice(outgoing, link, room, "cannot deop founder")
                        return True
                    ops.discard(target_hash)
                    self._touch_room(r)
                    self._persist_room_state_to_registry(link, r)
                    self._emit_notice(outgoing, link, room, f"op removed in {r}")
                    return True

            voiced = st.setdefault("voiced", set())
            if not isinstance(voiced, set):
                voiced = set()
                st["voiced"] = voiced
            if cmd == "voice":
                voiced.add(target_hash)
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._emit_notice(outgoing, link, room, f"voice granted in {r}")
                return True
            else:
                voiced.discard(target_hash)
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._emit_notice(outgoing, link, room, f"voice removed in {r}")
                return True

        if cmd == "mode":
            if len(parts) < 3:
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /mode <room> (+m|-m|+i|-i|+t|-t|+n|-n|+p|-p|+k|-k|+r|-r) [key] | /mode <room> (+o|-o|+v|-v) <nick|hashprefix|hash>",
                )
                return True
            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            if not self._is_room_op(r, peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True
            flag = parts[2].strip().lower()
            st = self._room_state_ensure(r)

            if flag in ("+m", "-m"):
                st["moderated"] = flag == "+m"
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+i", "-i"):
                st["invite_only"] = flag == "+i"
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+t", "-t"):
                st["topic_ops_only"] = flag == "+t"
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+n", "-n"):
                st["no_outside_msgs"] = flag == "+n"
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+p", "-p"):
                st["private"] = flag == "+p"
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+k", "-k"):
                if flag == "+k":
                    if len(parts) < 4:
                        self._emit_notice(
                            outgoing, link, room, "usage: /mode <room> +k <key>"
                        )
                        return True
                    key = " ".join(parts[3:]).strip()
                    if not key:
                        self._emit_notice(outgoing, link, room, "key must not be empty")
                        return True
                    st["key"] = key
                else:
                    st["key"] = None
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                self._broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+r", "-r"):
                self._emit_notice(
                    outgoing, link, room, "use /register or /unregister to change +r"
                )
                return True

            if flag in ("+o", "-o", "+v", "-v"):
                if len(parts) < 4:
                    self._emit_notice(
                        outgoing,
                        link,
                        room,
                        "usage: /mode <room> (+o|-o|+v|-v) <nick|hashprefix|hash>",
                    )
                    return True

                target_hash, all_matches = self._resolve_identity_hash_with_matches(parts[3], room=r)
                if target_hash is None:
                    self._emit_notice(
                        outgoing, link, room, self._format_ambiguous_targets(parts[3], all_matches)
                    )
                    return True

                founder = st.get("founder")
                founder_b = (
                    bytes(founder) if isinstance(founder, (bytes, bytearray)) else None
                )

                if flag in ("+o", "-o"):
                    ops = st.setdefault("ops", set())
                    if not isinstance(ops, set):
                        ops = set()
                        st["ops"] = ops

                    if flag == "+o":
                        ops.add(target_hash)
                    else:
                        if founder_b is not None and target_hash == founder_b:
                            self._emit_notice(
                                outgoing, link, room, "cannot deop founder"
                            )
                            return True
                        ops.discard(target_hash)

                    self._touch_room(r)
                    self._persist_room_state_to_registry(link, r)
                    for other in list(self.rooms.get(r, set())):
                        self._emit_notice(
                            outgoing,
                            other,
                            r,
                            f"mode for {r} is now: {flag} {target_hash.hex()[:12]}",
                        )
                    return True

                voiced = st.setdefault("voiced", set())
                if not isinstance(voiced, set):
                    voiced = set()
                    st["voiced"] = voiced
                if flag == "+v":
                    voiced.add(target_hash)
                else:
                    voiced.discard(target_hash)

                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)
                for other in list(self.rooms.get(r, set())):
                    self._emit_notice(
                        outgoing,
                        other,
                        r,
                        f"mode for {r} is now: {flag} {target_hash.hex()[:12]}",
                    )
                return True

            self._emit_notice(
                outgoing,
                link,
                room,
                "supported modes: +m -m +i -i +k -k +t -t +n -n +p -p +r -r +o -o +v -v",
            )
            return True

        if cmd == "ban":
            if len(parts) < 3:
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /ban <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            op = parts[2].strip().lower()
            if op == "list":
                st = self._room_state_ensure(r)
                bans = st.get("bans")
                if not isinstance(bans, set) or not bans:
                    self._emit_notice(outgoing, link, room, f"no bans in {r}")
                    return True
                items = sorted(
                    bytes(x).hex() for x in bans if isinstance(x, (bytes, bytearray))
                )
                self._emit_notice(
                    outgoing, link, room, f"bans in {r}: " + ", ".join(items)
                )
                return True

            if op not in ("add", "del"):
                self._emit_notice(
                    outgoing,
                    link,
                    room,
                    "usage: /ban <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 4:
                self._emit_notice(
                    outgoing, link, room, f"usage: /ban {r} {op} <nick|hashprefix|hash>"
                )
                return True

            if not self._is_room_op(r, peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            target_hash, all_matches = self._resolve_identity_hash_with_matches(parts[3], room=r)
            if target_hash is None:
                self._emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[3], all_matches)
                )
                return True

            st = self._room_state_ensure(r)
            bans = st.setdefault("bans", set())
            if not isinstance(bans, set):
                bans = set()
                st["bans"] = bans

            if op == "add":
                bans.add(target_hash)
                self._touch_room(r)
                self._persist_room_state_to_registry(link, r)

                # If currently present in room, remove them.
                for other in list(self.rooms.get(r, set())):
                    s = self.session_manager.sessions.get(other)
                    ph = s.get("peer") if s else None
                    if isinstance(ph, (bytes, bytearray)) and bytes(ph) == target_hash:
                        s.get("rooms", set()).discard(r)
                        self.rooms.get(r, set()).discard(other)
                        if self.identity is not None:
                            self._emit_error(
                                outgoing,
                                other,
                                src=self.identity.hash,
                                text=f"banned from {r}",
                                room=r,
                            )
                if r in self.rooms and not self.rooms[r]:
                    self.rooms.pop(r, None)
                self._emit_notice(outgoing, link, room, f"ban added in {r}")
                return True

            bans.discard(target_hash)
            self._touch_room(r)
            self._persist_room_state_to_registry(link, r)
            self._emit_notice(outgoing, link, room, f"ban removed in {r}")
            return True

        if cmd == "invite":
            if len(parts) < 3:
                self._emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /invite <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            try:
                r = self._norm_room(parts[1])
            except Exception as e:
                self._emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            if not self._is_room_op(r, peer_hash):
                if self.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            op = parts[2].strip().lower()
            st = self._room_state_ensure(r)

            invited = st.setdefault("invited", {})
            if not isinstance(invited, dict):
                invited = {}
                st["invited"] = invited

            # Drop expired entries before operating.
            pruned = self._prune_expired_invites(st)

            if op == "list":
                now = float(time.time())
                items = []
                for h, exp in invited.items():
                    if not isinstance(h, (bytes, bytearray)):
                        continue
                    try:
                        exp_f = float(exp)
                    except Exception:
                        continue
                    if exp_f <= now:
                        continue
                    items.append(f"{bytes(h).hex()} expires_in={int(exp_f - now)}s")
                items.sort()
                if pruned:
                    self._touch_room(r)
                    self._persist_room_state_to_registry(link, r)
                self._emit_notice(
                    outgoing,
                    link,
                    room,
                    f"invites in {r}: " + (", ".join(items) if items else "(none)"),
                )
                return True

            if op not in ("add", "del"):
                self._emit_notice(
                    outgoing,
                    link,
                    room,
                    "usage: /invite <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 4:
                self._emit_notice(
                    outgoing,
                    link,
                    room,
                    f"usage: /invite {r} {op} <nick|hashprefix|hash>",
                )
                return True

            if op == "add":
                token = parts[3]
                target_link = self._find_target_link(token, room=None)
                if target_link is None:
                    # Check if ambiguous or just not found
                    all_matches = self._find_target_links(token, room=None)
                    if self.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.identity.hash,
                            text=f"invite failed: {self._format_ambiguous_targets(token, all_matches)}",
                            room=r,
                        )
                    return True

                tsess = self.session_manager.sessions.get(target_link)
                ph = tsess.get("peer") if tsess else None
                if not isinstance(ph, (bytes, bytearray)):
                    if self.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.identity.hash,
                            text="invite failed: target not identified",
                            room=r,
                        )
                    return True
                target_hash = bytes(ph)

                # Always send the invite as a NOTICE so the user can choose to join.
                key = st.get("key")
                is_keyed = isinstance(key, str) and bool(key)
                is_invite_only = bool(st.get("invite_only", False))

                if is_keyed:
                    self._emit_notice(
                        outgoing,
                        target_link,
                        r,
                        f"You have been invited to join {r}. This invite allows joining without the key (+k).",
                    )
                else:
                    self._emit_notice(
                        outgoing, target_link, r, f"You have been invited to join {r}."
                    )

                # Persist an expiring invite only when it has semantics: +k bypass and/or +i allow.
                if is_keyed or is_invite_only:
                    ttl = (
                        float(self.config.room_invite_timeout_s)
                        if self.config.room_invite_timeout_s
                        else 0.0
                    )
                    if ttl <= 0:
                        ttl = 900.0
                    exp = float(time.time()) + ttl
                    invited[target_hash] = exp
                    self._touch_room(r)
                    self._persist_room_state_to_registry(link, r)
                    self._emit_notice(
                        outgoing,
                        link,
                        room,
                        f"invite added in {r} (expires in {int(ttl)}s)",
                    )
                else:
                    self._emit_notice(
                        outgoing, link, room, f"invite sent to {token} for {r}"
                    )
                return True

            target_hash, all_matches = self._resolve_identity_hash_with_matches(parts[3], room=None)
            if target_hash is None:
                self._emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[3], all_matches)
                )
                return True

            if target_hash in invited:
                invited.pop(target_hash, None)
            self._touch_room(r)
            self._persist_room_state_to_registry(link, r)
            self._emit_notice(outgoing, link, room, f"invite removed in {r}")
            return True

        return False

    def _on_link(self, link: RNS.Link) -> None:
        with self._state_lock:
            self.session_manager.on_link_established(link)
            
            # Initialize resource tracking for this link
            self._resource_expectations[link] = {}
            self._active_resources[link] = set()

        link.set_packet_callback(lambda data, pkt: self._on_packet(link, data))
        link.set_link_closed_callback(lambda closed_link: self._on_close(closed_link))
        link.set_remote_identified_callback(
            lambda identified_link, ident: self._on_remote_identified(
                identified_link, ident
            )
        )
        
        # Set up resource callbacks
        if self.config.enable_resource_transfer:
            try:
                link.set_resource_strategy(RNS.Link.ACCEPT_APP)
                link.set_resource_callback(self._resource_advertised)
                link.set_resource_concluded_callback(self._resource_concluded)
                self.log.debug(
                    "Resource callbacks configured link_id=%s",
                    self._fmt_link_id(link),
                )
            except Exception as e:
                self.log.warning(
                    "Failed to set resource callbacks link_id=%s: %s",
                    self._fmt_link_id(link),
                    e,
                )

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
        for out_link, payload in outgoing:
            self._inc("bytes_out", len(payload))
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

    def _on_close(self, link: RNS.Link) -> None:
        peer = None
        nick = None
        rooms_count = 0

        with self._state_lock:
            # Clean up resource state
            self._resource_expectations.pop(link, None)
            self._active_resources.pop(link, None)
            
            # Clean up session (also handles room cleanup)
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
        self._inc("bytes_out", len(payload))
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
        outgoing: list[tuple[RNS.Link, bytes]] = []
        with self._state_lock:
            self._on_packet_locked(link, data, outgoing)

        if self.log.isEnabledFor(logging.DEBUG) and outgoing:
            self.log.debug(
                "Sending %d response(s) link_id=%s",
                len(outgoing),
                self._fmt_link_id(link),
            )

        for out_link, payload in outgoing:
            self._inc("bytes_out", len(payload))
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
                    self._inc("pings_out")
                    self._send(link, ping)
                except Exception:
                    pass
