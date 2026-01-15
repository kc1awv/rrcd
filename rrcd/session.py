from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import RNS

if TYPE_CHECKING:
    from .service import HubService


@dataclass
class _RateState:
    """Token bucket state for rate limiting."""

    tokens: float
    last_refill: float


class SessionManager:
    """
    Manages session lifecycle for RRC hub connections.

    This class is responsible for:
    - Session creation and initialization
    - Session state management (nicknames, rooms, capabilities)
    - Nickname indexing for efficient lookups
    - Rate limiting with token bucket algorithm
    - Session cleanup and teardown
    - Remote identity tracking
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = logging.getLogger("rrcd.session")
        self.sessions: dict[RNS.Link, dict[str, Any]] = {}
        self._rate: dict[RNS.Link, _RateState] = {}
        self._index_by_hash: dict[bytes, RNS.Link] = {}  # identity hash -> link
        self._index_by_nick: dict[str, set[RNS.Link]] = {}  # normalized nick -> links

    def on_link_established(self, link: RNS.Link) -> None:
        """
        Handle new link establishment.

        Creates session state and sets up callbacks.
        Must be called with state lock held.
        """
        self.sessions[link] = {
            "welcomed": False,
            "rooms": set(),
            "peer": None,
            "nick": None,
            "peer_caps": {},
            "awaiting_pong": None,
        }

        self._rate[link] = _RateState(
            tokens=float(self.hub.config.rate_limit_msgs_per_minute),
            last_refill=time.monotonic(),
        )

        self.log.info("Session created link_id=%s", self.hub._fmt_link_id(link))

    def on_remote_identified(
        self, link: RNS.Link, identity: RNS.Identity | None
    ) -> tuple[bool, bytes | None]:
        """
        Handle remote identity being established.

        Returns:
            (is_banned, peer_hash) tuple
        Must be called with state lock held.
        """
        sess = self.sessions.get(link)
        if sess is None:
            return False, None

        if identity is not None:
            peer_hash = identity.hash
            sess["peer"] = peer_hash

            self._index_by_hash[bytes(peer_hash)] = link

            banned = self.hub.trust_manager.is_banned(bytes(peer_hash))

            if not banned:
                self.log.info(
                    "Remote identified peer=%s link_id=%s",
                    self.hub._fmt_hash(peer_hash),
                    self.hub._fmt_link_id(link),
                )

            return banned, peer_hash

        return False, None

    def on_link_closed(self, link: RNS.Link) -> tuple[bytes | None, str | None, int]:
        """
        Handle link closure and cleanup.

        Returns:
            (peer_hash, nick, rooms_count) for logging
        Must be called with state lock held.
        """
        from .codec import encode
        from .constants import T_PARTED
        from .envelope import make_envelope

        sess = self.sessions.pop(link, None)
        self._rate.pop(link, None)

        if not sess:
            return None, None, 0

        peer = sess.get("peer")
        nick = sess.get("nick")
        rooms_count = len(sess.get("rooms") or ())

        if isinstance(peer, (bytes, bytearray)):
            self._index_by_hash.pop(bytes(peer), None)

        if nick:
            self.update_nick_index(link, nick, None)

        peer_hash = bytes(peer) if isinstance(peer, (bytes, bytearray)) else None
        for room in list(sess["rooms"]):
            remaining_members = [
                member_link
                for member_link in self.hub.room_manager.get_room_members(room)
                if member_link != link
            ]

            self.hub.room_manager.remove_member(room, link)

            if remaining_members and peer_hash and self.hub.identity:
                notification_body = (
                    [peer_hash] if self.hub.config.include_joined_member_list else None
                )
                member_notification = make_envelope(
                    T_PARTED,
                    src=self.hub.identity.hash,
                    room=room,
                    body=notification_body,
                )
                member_notification_payload = encode(member_notification)
                for member_link in remaining_members:
                    try:
                        import RNS

                        RNS.Packet(member_link, member_notification_payload).send()
                        self.hub.stats_manager.inc(
                            "bytes_out", len(member_notification_payload)
                        )
                    except Exception:
                        pass

        return peer, nick, rooms_count

    def update_nick_index(
        self, link: RNS.Link, old_nick: str | None, new_nick: str | None
    ) -> None:
        """
        Update nickname index when a nick changes.

        Must be called with state lock held.
        """
        if old_nick:
            old_key = old_nick.strip().lower()
            if old_key in self._index_by_nick:
                self._index_by_nick[old_key].discard(link)
                if not self._index_by_nick[old_key]:
                    self._index_by_nick.pop(old_key, None)

        if new_nick:
            new_key = new_nick.strip().lower()
            self._index_by_nick.setdefault(new_key, set()).add(link)

    def refill_and_take(self, link: RNS.Link, cost: float = 1.0) -> bool:
        """
        Token bucket rate limiting.

        Refills tokens based on elapsed time and attempts to take `cost` tokens.
        Returns True if tokens were available and taken, False if rate limited.

        Must be called with state lock held.
        """
        state = self._rate.get(link)
        if state is None:
            return True

        now = time.monotonic()
        per_min = float(max(1, int(self.hub.config.rate_limit_msgs_per_minute)))
        rate_per_s = per_min / 60.0
        elapsed = max(0.0, now - state.last_refill)
        state.tokens = min(per_min, state.tokens + elapsed * rate_per_s)
        state.last_refill = now

        if state.tokens < cost:
            return False

        state.tokens -= cost
        return True

    def get_session(self, link: RNS.Link) -> dict[str, Any] | None:
        """Get session state for a link."""
        return self.sessions.get(link)

    def get_link_by_hash(self, peer_hash: bytes) -> RNS.Link | None:
        """Look up link by peer identity hash (O(1))."""
        return self._index_by_hash.get(bytes(peer_hash))

    def get_links_by_nick(self, nick: str) -> set[RNS.Link]:
        """Look up links by normalized nickname (O(1))."""
        key = nick.strip().lower()
        return self._index_by_nick.get(key, set()).copy()

    def clear_all(self) -> list[RNS.Link]:
        """
        Clear all sessions and return list of links for teardown.

        Must be called with state lock held.
        """
        links = list(self.sessions.keys())
        self.sessions.clear()
        self._rate.clear()
        self._index_by_hash.clear()
        self._index_by_nick.clear()
        return links

    def get_stats(self) -> dict[str, Any]:
        """Get session statistics for monitoring."""
        total = len(self.sessions)
        welcomed = sum(1 for s in self.sessions.values() if s.get("welcomed"))
        identified = sum(1 for s in self.sessions.values() if s.get("peer") is not None)

        return {
            "total": total,
            "welcomed": welcomed,
            "identified": identified,
            "indexed_by_hash": len(self._index_by_hash),
            "indexed_by_nick": len(self._index_by_nick),
        }

    def send_welcome(
        self,
        link: RNS.Link,
        outgoing: list[tuple[RNS.Link, bytes]],
        *,
        peer_hash: bytes,
        old_nick: str | None = None,
        new_nick: str | None = None,
    ) -> None:
        """
        Send WELCOME message to a client and optionally MOTD.

        This handles:
        - Setting session as welcomed
        - Updating nick index if needed
        - Queueing WELCOME message
        - Setting up MOTD callback for post-send delivery

        Must be called with state lock held.
        """
        from .constants import RES_KIND_MOTD, T_NOTICE

        sess = self.sessions.get(link)
        if sess is None:
            return

        if old_nick != new_nick:
            self.update_nick_index(link, old_nick, new_nick)

        sess["welcomed"] = True

        self.hub.message_helper.queue_welcome(
            outgoing,
            link,
            peer_hash=peer_hash,
            motd=self.hub.config.greeting,
        )

        if self.hub.config.greeting:

            def send_motd():
                self.hub.message_helper.send_text_smart(
                    link,
                    msg_type=T_NOTICE,
                    text=self.hub.config.greeting,
                    room=None,
                    kind=RES_KIND_MOTD,
                )

            if not hasattr(outgoing, "_post_send_callbacks"):
                outgoing._post_send_callbacks = []  # type: ignore
            outgoing._post_send_callbacks.append(send_motd)  # type: ignore
