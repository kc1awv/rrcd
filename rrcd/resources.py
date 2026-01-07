"""Resource transfer management for RRCD."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import RNS

from rrcd.codec import encode
from rrcd.constants import (
    B_RES_ENCODING,
    B_RES_ID,
    B_RES_KIND,
    B_RES_SHA256,
    B_RES_SIZE,
    RES_KIND_BLOB,
    RES_KIND_MOTD,
    RES_KIND_NOTICE,
    T_NOTICE,
    T_RESOURCE_ENVELOPE,
)
from rrcd.envelope import make_envelope

if TYPE_CHECKING:
    from rrcd.service import HubService


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


class ResourceManager:
    """Manages RNS Resource transfers for the hub."""

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = hub.log
        
        # Resource state
        self._resource_expectations: dict[RNS.Link, dict[bytes, _ResourceExpectation]] = {}
        self._active_resources: dict[RNS.Link, set[RNS.Resource]] = {}
        # Tracks which expectation RID was matched to an advertised Resource.
        self._resource_bindings: dict[RNS.Resource, bytes] = {}

    def on_link_established(self, link: RNS.Link) -> None:
        """Initialize resource tracking for a new link."""
        self._resource_expectations[link] = {}
        self._active_resources[link] = set()

    def on_link_closed(self, link: RNS.Link) -> None:
        """Clean up resource state when a link closes."""
        self._resource_expectations.pop(link, None)
        self._active_resources.pop(link, None)

    def clear_all(self) -> None:
        """Clear all resource state (called during shutdown)."""
        self._resource_expectations.clear()
        self._active_resources.clear()

    def configure_link_callbacks(self, link: RNS.Link) -> None:
        """Set up resource callbacks for a link if resource transfer is enabled."""
        if not self.hub.config.enable_resource_transfer:
            return
        
        try:
            link.set_resource_strategy(RNS.Link.ACCEPT_APP)
            link.set_resource_callback(self._resource_advertised)
            link.set_resource_concluded_callback(self._resource_concluded)
            self.log.debug(
                "Resource callbacks configured link_id=%s",
                self.hub._fmt_link_id(link),
            )
        except Exception as e:
            self.log.warning(
                "Failed to set resource callbacks link_id=%s: %s",
                self.hub._fmt_link_id(link),
                e,
            )

    # Resource expectation management

    def cleanup_expired_expectations(self, link: RNS.Link) -> None:
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
                self.hub._fmt_link_id(link),
                rid.hex() if isinstance(rid, bytes) else rid,
            )

    def cleanup_all_expired_expectations(self) -> None:
        """Cleanup expired resource expectations across all links."""
        now = time.time()
        with self.hub._state_lock:
            for link, exp_dict in list(self._resource_expectations.items()):
                if not exp_dict:
                    continue
                
                expired = [rid for rid, exp in exp_dict.items() if exp.expires_at <= now]
                for rid in expired:
                    exp_dict.pop(rid, None)
                    self.log.debug(
                        "Expired resource expectation link_id=%s rid=%s",
                        self.hub._fmt_link_id(link),
                        rid.hex() if isinstance(rid, bytes) else rid,
                    )

    def add_resource_expectation(
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
        self.cleanup_expired_expectations(link)
        
        exp_dict = self._resource_expectations.setdefault(link, {})
        
        if len(exp_dict) >= self.hub.config.max_pending_resource_expectations:
            self.log.warning(
                "Max pending expectations exceeded link_id=%s",
                self.hub._fmt_link_id(link),
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
            expires_at=now + self.hub.config.resource_expectation_ttl_s,
            room=room,
        )
        exp_dict[rid] = exp
        
        self.log.debug(
            "Added resource expectation link_id=%s rid=%s kind=%s size=%s",
            self.hub._fmt_link_id(link),
            rid.hex(),
            kind,
            size,
        )
        return True

    def find_resource_expectation(
        self, link: RNS.Link, size: int
    ) -> _ResourceExpectation | None:
        """Find a matching resource expectation by size (fallback matching)."""
        self.cleanup_expired_expectations(link)
        
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        
        # Match by size (first match wins)
        for exp in exp_dict.values():
            if exp.size == size:
                return exp
        
        return None

    def get_resource_expectation_by_rid(
        self, link: RNS.Link, rid: bytes
    ) -> _ResourceExpectation | None:
        """Lookup an expectation by RID without removing it."""
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        return exp_dict.get(rid)

    def match_resource_expectation(
        self, link: RNS.Link, *, rid: bytes | None, size: int, sha256: bytes | None
    ) -> _ResourceExpectation | None:
        """Find the expectation that should satisfy a completed resource.

        Preference order:
        1) Bound RID (from advertisement) when available.
        2) Exact RID lookup.
        3) Fallback: first size match whose sha256 (if present) matches.
        """
        self.cleanup_expired_expectations(link)

        if rid is not None:
            exp = self.get_resource_expectation_by_rid(link, rid)
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

    def pop_resource_expectation(
        self, link: RNS.Link, rid: bytes
    ) -> _ResourceExpectation | None:
        """Remove and return a resource expectation."""
        exp_dict = self._resource_expectations.get(link)
        if not exp_dict:
            return None
        return exp_dict.pop(rid, None)

    # Resource transfer callbacks

    def _resource_advertised(self, resource: RNS.Resource) -> bool:
        """
        Callback when a Resource is advertised by remote peer.
        Returns True to accept, False to reject.
        
        Minimize lock scope to prevent potential deadlocks with RNS internal locks.
        """
        link = resource.link
        
        # Check config outside lock (immutable during runtime)
        if not self.hub.config.enable_resource_transfer:
            self.log.debug(
                "Rejecting resource (disabled) link_id=%s",
                self.hub._fmt_link_id(link),
            )
            self.hub._inc("resources_rejected")
            return False
        
        # Check size limit (immutable config)
        size = resource.total_size if hasattr(resource, "total_size") else resource.size
        if size > self.hub.config.max_resource_bytes:
            self.log.warning(
                "Rejecting resource (too large: %s > %s) link_id=%s",
                size,
                self.hub.config.max_resource_bytes,
                self.hub._fmt_link_id(link),
            )
            self.hub._inc("resources_rejected")
            return False
        
        # Check session exists and find expectation with minimal lock scope
        with self.hub._state_lock:
            sess = self.hub.session_manager.sessions.get(link)
            if not sess:
                self.log.debug(
                    "Rejecting resource (no session) link_id=%s",
                    self.hub._fmt_link_id(link),
                )
                self.hub._inc("resources_rejected")
                return False
            
            # Find matching expectation
            exp = self.find_resource_expectation(link, size)
        
        # Check expectation outside lock
        if not exp:
            self.log.warning(
                "Rejecting resource (no matching expectation) link_id=%s size=%s",
                self.hub._fmt_link_id(link),
                size,
            )
            self.hub._inc("resources_rejected")
            return False
        
        # Accept and register with minimal lock scope
        self.log.info(
            "Accepting resource link_id=%s size=%s kind=%s",
            self.hub._fmt_link_id(link),
            size,
            exp.kind,
        )
        
        with self.hub._state_lock:
            self._active_resources.setdefault(link, set()).add(resource)
            # Remember which expectation RID this resource was matched to so the
            # conclusion handler can verify and pop the correct entry.
            self._resource_bindings[resource] = exp.id
        
        return True

    def _resource_concluded(self, resource: RNS.Resource) -> None:
        """Callback when a Resource transfer completes."""
        link = resource.link
        
        with self.hub._state_lock:
            # Remove from active set and retrieve any bound expectation RID.
            active_set = self._active_resources.get(link)
            if active_set:
                active_set.discard(resource)
            bound_rid = self._resource_bindings.pop(resource, None)

        if resource.status != RNS.Resource.COMPLETE:
            self.log.warning(
                "Resource transfer failed link_id=%s status=%s",
                self.hub._fmt_link_id(link),
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
                self.hub._fmt_link_id(link),
                e,
            )
            return

        size = len(payload)
        actual_hash = hashlib.sha256(payload).digest()

        # Find expectation using bound RID first, then RID lookup, then size/sha fallback.
        exp = self.match_resource_expectation(link, rid=bound_rid, size=size, sha256=actual_hash)
        if not exp:
            self.log.warning(
                "Received resource without expectation link_id=%s size=%s",
                self.hub._fmt_link_id(link),
                size,
            )
            return

        # Verify SHA256 if provided; keep expectation if mismatch so sender can retry.
        if exp.sha256 and actual_hash != exp.sha256:
            self.log.error(
                "Resource SHA256 mismatch link_id=%s expected=%s actual=%s",
                self.hub._fmt_link_id(link),
                exp.sha256.hex(),
                actual_hash.hex(),
            )
            return

        # Pop expectation only after validation succeeds.
        self.pop_resource_expectation(link, exp.id)

        self.hub._inc("resources_received")
        self.hub._inc("resource_bytes_received", size)
        
        self.log.info(
            "Resource received link_id=%s size=%s kind=%s",
            self.hub._fmt_link_id(link),
            size,
            exp.kind,
        )
        
        # Dispatch by kind
        try:
            self._dispatch_received_resource(link, exp, payload)
        except Exception as e:
            self.log.exception(
                "Failed to dispatch resource link_id=%s kind=%s: %s",
                self.hub._fmt_link_id(link),
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
                    self.hub._fmt_link_id(link),
                    encoding,
                    e,
                )
                return
            
            self.log.info(
                "Received large NOTICE via resource link_id=%s room=%r chars=%s",
                self.hub._fmt_link_id(link),
                exp.room,
                len(text),
            )
            
            # Forward NOTICE to room members if room is specified
            if exp.room and self.hub.identity is not None:
                with self.hub._state_lock:
                    sess = self.hub.session_manager.sessions.get(link)
                    peer_hash = sess.get("peer") if sess else None
                    room_members = self.hub.rooms.get(exp.room, set())
                
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
                                    self.hub._fmt_link_id(other),
                                    e,
                                )
                    
                    if forwarded > 0:
                        self.hub._inc("notices_forwarded")
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
                    self.hub._fmt_link_id(link),
                    e,
                )
                return
            
            self.log.info(
                "Received MOTD via resource link_id=%s chars=%s",
                self.hub._fmt_link_id(link),
                len(text),
            )
            
        elif exp.kind == RES_KIND_BLOB:
            # Generic binary data
            self.log.info(
                "Received BLOB via resource link_id=%s bytes=%s",
                self.hub._fmt_link_id(link),
                len(payload),
            )
        else:
            self.log.warning(
                "Unknown resource kind link_id=%s kind=%s",
                self.hub._fmt_link_id(link),
                exp.kind,
            )

    def send_via_resource(
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
        if not self.hub.config.enable_resource_transfer:
            return False
        
        size = len(payload)
        if size > self.hub.config.max_resource_bytes:
            self.log.error(
                "Payload too large for resource transfer: %s > %s",
                size,
                self.hub.config.max_resource_bytes,
            )
            return False
        
        # Generate resource ID
        rid = os.urandom(8)
        
        # Compute SHA256
        sha256 = hashlib.sha256(payload).digest()
        
        # Send envelope first
        if self.hub.identity is None:
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
            src=self.hub.identity.hash,
            room=room,
            body=envelope_body,
        )
        
        try:
            envelope_payload = encode(envelope)
            RNS.Packet(link, envelope_payload).send()
            self.hub._inc("bytes_out", len(envelope_payload))
            
            self.log.debug(
                "Sent resource envelope link_id=%s rid=%s kind=%s size=%s",
                self.hub._fmt_link_id(link),
                rid.hex(),
                kind,
                size,
            )
        except Exception as e:
            self.log.error(
                "Failed to send resource envelope link_id=%s: %s",
                self.hub._fmt_link_id(link),
                e,
            )
            return False
        
        # Create and advertise resource
        try:
            resource = RNS.Resource(payload, link, advertise=True, auto_compress=False)
            
            with self.hub._state_lock:
                self._active_resources.setdefault(link, set()).add(resource)
            
            self.hub._inc("resources_sent")
            self.hub._inc("resource_bytes_sent", size)
            
            self.log.info(
                "Sent resource link_id=%s rid=%s kind=%s size=%s",
                self.hub._fmt_link_id(link),
                rid.hex(),
                kind,
                size,
            )
            return True
            
        except Exception as e:
            self.log.error(
                "Failed to create resource link_id=%s: %s",
                self.hub._fmt_link_id(link),
                e,
            )
            return False
