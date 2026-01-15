from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import RNS

from .codec import decode, encode
from .constants import (
    B_HELLO_CAPS,
    B_HELLO_NICK_LEGACY,
    B_RES_ENCODING,
    B_RES_ID,
    B_RES_KIND,
    B_RES_SHA256,
    B_RES_SIZE,
    K_BODY,
    K_NICK,
    K_ROOM,
    K_SRC,
    K_T,
    T_HELLO,
    T_JOIN,
    T_JOINED,
    T_MSG,
    T_NOTICE,
    T_PART,
    T_PARTED,
    T_PING,
    T_PONG,
    T_RESOURCE_ENVELOPE,
)
from .envelope import make_envelope, validate_envelope
from .util import normalize_nick


class OutgoingList(list):
    """Custom list that allows attaching callback attributes."""

    pass


if TYPE_CHECKING:
    from .service import HubService


class MessageRouter:
    """
    Handles message routing and dispatching for the RRC hub.

    This class is responsible for:
    - Decoding and validating incoming packets
    - Dispatching messages by type (HELLO, JOIN, PART, MSG, NOTICE, PING, etc.)
    - Forwarding messages to appropriate rooms/recipients
    - Rate limiting
    - Protocol validation
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = logging.getLogger("rrcd.router")

    def route_packet(
        self,
        link: RNS.Link,
        data: bytes,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """
        Main entry point for routing an incoming packet.

        This method should be called with the state lock held.
        """
        sess = self.hub.session_manager.sessions.get(link)
        if sess is None:
            return

        self.hub.stats_manager.inc("pkts_in")
        self.hub.stats_manager.inc("bytes_in", len(data))

        peer_hash = sess.get("peer")
        if peer_hash is None:
            ri = link.get_remote_identity()
            if ri is None:
                return
            peer_hash = ri.hash
            sess["peer"] = peer_hash

        if not self.hub.session_manager.refill_and_take(link, 1.0):
            self.hub.stats_manager.inc("rate_limited")
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(
                    "Rate limited peer=%s link_id=%s",
                    self.hub._fmt_hash(peer_hash),
                    self.hub._fmt_link_id(link),
                )
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text="rate limited"
                )
            return

        try:
            env = decode(data)
            validate_envelope(env)
        except Exception as e:
            self.hub.stats_manager.inc("pkts_bad")
            self.log.debug(
                "Bad packet peer=%s link_id=%s bytes=%s err=%s",
                self.hub._fmt_hash(peer_hash),
                self.hub._fmt_link_id(link),
                len(data),
                e,
            )
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text=f"bad message: {e}"
                )
            return

        t = env.get(K_T)
        room = env.get(K_ROOM)
        body = env.get(K_BODY)

        if self.log.isEnabledFor(logging.DEBUG):
            body_len = None
            if isinstance(body, (bytes, bytearray)):
                body_len = len(body)
            elif isinstance(body, str):
                body_len = len(body)
            self.log.debug(
                "RX peer=%s link_id=%s t=%s room=%r bytes=%s body_type=%s body_len=%s",
                self.hub._fmt_hash(peer_hash),
                self.hub._fmt_link_id(link),
                t,
                room,
                len(data),
                type(body).__name__,
                body_len,
            )

        if t == T_PONG:
            self._handle_pong(link, sess)
        elif t == T_RESOURCE_ENVELOPE:
            self._handle_resource_envelope(link, sess, env, outgoing)
        elif not sess["welcomed"]:
            self._handle_pre_welcome(link, sess, peer_hash, env, outgoing)
        elif t == T_HELLO:
            self._handle_re_hello(link, sess, peer_hash, env, outgoing)
        elif t == T_JOIN:
            self._handle_join(link, sess, peer_hash, env, outgoing)
        elif t == T_PART:
            self._handle_part(link, sess, peer_hash, env, outgoing)
        elif t in (T_MSG, T_NOTICE):
            self._handle_message(link, sess, peer_hash, env, outgoing)
        elif t == T_PING:
            self._handle_ping(link, env, outgoing)

    def _handle_pong(self, link: RNS.Link, sess: dict[str, Any]) -> None:
        """Handle PONG message."""
        self.hub.stats_manager.inc("pongs_in")
        sess["awaiting_pong"] = None

    def _handle_resource_envelope(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle RESOURCE_ENVELOPE message."""
        room = env.get(K_ROOM)
        body = env.get(K_BODY)

        if not self.hub.config.enable_resource_transfer:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="resource transfer disabled",
                    room=room,
                )
            return

        if not isinstance(body, dict):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="invalid resource envelope body",
                    room=room,
                )
            return

        rid = body.get(B_RES_ID)
        kind = body.get(B_RES_KIND)
        size = body.get(B_RES_SIZE)
        sha256 = body.get(B_RES_SHA256)
        encoding = body.get(B_RES_ENCODING)

        if not isinstance(rid, (bytes, bytearray)):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="resource envelope missing id",
                    room=room,
                )
            return

        if not isinstance(kind, str) or not kind:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="resource envelope missing kind",
                    room=room,
                )
            return

        if not isinstance(size, int) or size < 0:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="resource envelope invalid size",
                    room=room,
                )
            return

        if size > self.hub.config.max_resource_bytes:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text=f"resource too large: {size} > {self.hub.config.max_resource_bytes}",
                    room=room,
                )
            return

        if sha256 is not None and not isinstance(sha256, (bytes, bytearray)):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="resource envelope invalid sha256",
                    room=room,
                )
            return

        if encoding is not None and not isinstance(encoding, str):
            encoding = None

        if not self.hub.resource_manager.add_resource_expectation(
            link,
            rid=bytes(rid),
            kind=kind,
            size=size,
            sha256=bytes(sha256) if sha256 else None,
            encoding=encoding,
            room=room,
        ):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="too many pending resource expectations",
                    room=room,
                )

    def _handle_pre_welcome(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        peer_hash: bytes,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle messages before WELCOME (only HELLO is allowed)."""
        t = env.get(K_T)
        nick = env.get(K_NICK)
        body = env.get(K_BODY)

        if t != T_HELLO:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text="send HELLO first"
                )
            return

        old_nick = sess.get("nick")
        new_nick = None

        if isinstance(nick, str):
            n = normalize_nick(nick, max_bytes=self.hub.config.max_nick_bytes)
            if n is not None:
                new_nick = n
                sess["nick"] = n

        if isinstance(body, dict):
            sess["peer_caps"] = self._extract_caps(body)

            if new_nick is None:
                legacy_nick = body.get(B_HELLO_NICK_LEGACY)
                n2 = normalize_nick(
                    legacy_nick, max_bytes=self.hub.config.max_nick_bytes
                )
                if n2 is not None:
                    new_nick = n2
                    sess["nick"] = n2

        self.log.info(
            "HELLO peer=%s nick=%r link_id=%s",
            self.hub._fmt_hash(peer_hash),
            sess.get("nick"),
            self.hub._fmt_link_id(link),
        )

        self.hub.session_manager.send_welcome(
            link,
            outgoing,
            peer_hash=peer_hash,
            old_nick=old_nick,
            new_nick=new_nick,
        )

    def _handle_re_hello(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        peer_hash: bytes,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle re-authentication (HELLO after already welcomed)."""
        nick = env.get(K_NICK)
        body = env.get(K_BODY)

        if self.hub.identity is None:
            return

        old_nick = sess.get("nick")
        old_rooms = set(sess.get("rooms", set()))
        sess["welcomed"] = False
        sess["rooms"] = set()
        sess["nick"] = None
        sess["peer_caps"] = {}

        for r in old_rooms:
            self.hub.room_manager.remove_member(r, link)

        new_nick = None

        if isinstance(nick, str):
            n = normalize_nick(nick, max_bytes=self.hub.config.max_nick_bytes)
            if n is not None:
                new_nick = n
                sess["nick"] = n

        if isinstance(body, dict):
            sess["peer_caps"] = self._extract_caps(body)
            if new_nick is None:
                legacy_nick = body.get(B_HELLO_NICK_LEGACY)
                n2 = normalize_nick(
                    legacy_nick, max_bytes=self.hub.config.max_nick_bytes
                )
                if n2 is not None:
                    new_nick = n2
                    sess["nick"] = n2

        self.log.info(
            "Re-HELLO peer=%s nick=%r link_id=%s",
            self.hub._fmt_hash(peer_hash),
            sess.get("nick"),
            self.hub._fmt_link_id(link),
        )

        self.hub.session_manager.send_welcome(
            link,
            outgoing,
            peer_hash=peer_hash,
            old_nick=old_nick,
            new_nick=new_nick,
        )

    def _handle_join(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        peer_hash: bytes,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle JOIN message."""
        room = env.get(K_ROOM)
        body = env.get(K_BODY)

        self.hub.stats_manager.inc("joins")
        if not isinstance(room, str) or not room:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="JOIN requires room name",
                )
            return

        if len(sess["rooms"]) >= int(self.hub.config.max_rooms_per_session):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text="too many rooms"
                )
            return

        try:
            r = self.hub._norm_room(room)
        except Exception as e:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text=str(e)
                )
            return

        if r in self.hub.room_manager._room_registry:
            self.hub.room_manager._room_state_ensure(r)

        st = self.hub.room_manager._room_state_ensure(r)

        if bool(st.get("invite_only", False)):
            is_invited = self.hub.room_manager.is_invited(r, peer_hash)
            if not self.hub.room_manager.is_room_op(r, peer_hash) and not is_invited:
                if self.hub.identity is not None:
                    self.hub.message_helper.emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="invite-only (+i)",
                        room=r,
                    )
                return

        key = st.get("key")
        if isinstance(key, str) and key:
            is_invited = self.hub.room_manager.is_invited(r, peer_hash)
            if not self.hub.room_manager.is_room_op(r, peer_hash) and not is_invited:
                provided = body if isinstance(body, str) else None
                if provided != key:
                    if self.hub.identity is not None:
                        self.hub.message_helper.emit_error(
                            outgoing,
                            link,
                            src=self.hub.identity.hash,
                            text="bad key (+k)",
                            room=r,
                        )
                    return

        if self.hub.room_manager.is_room_banned(r, peer_hash):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="banned from room",
                    room=r,
                )
            return

        if not self.hub.room_manager.get_room_members(r):
            pass
            self.hub.room_manager._room_state_ensure(r, founder=peer_hash)

        sess["rooms"].add(r)
        self.hub.room_manager.add_member(r, link)

        self.log.info(
            "JOIN peer=%s nick=%r room=%s link_id=%s",
            self.hub._fmt_hash(peer_hash),
            sess.get("nick"),
            r,
            self.hub._fmt_link_id(link),
        )

        self.hub.room_manager.touch_room(r)

        existing_members = [
            member_link
            for member_link in self.hub.room_manager.get_room_members(r)
            if member_link != link
        ]
        if existing_members and self.hub.identity is not None:
            notification_body = (
                [peer_hash] if self.hub.config.include_joined_member_list else None
            )
            member_notification = make_envelope(
                T_JOINED, src=self.hub.identity.hash, room=r, body=notification_body
            )
            member_notification_payload = encode(member_notification)
            for member_link in existing_members:
                self.hub.message_helper.queue_payload(
                    outgoing, member_link, member_notification_payload
                )

        joined_body = None
        if self.hub.config.include_joined_member_list:
            members: list[bytes] = []
            for member_link in self.hub.room_manager.get_room_members(r):
                s = self.hub.session_manager.sessions.get(member_link)
                ph = s.get("peer") if s else None
                if isinstance(ph, (bytes, bytearray)):
                    members.append(bytes(ph))
            joined_body = members

        if self.hub.identity is not None:
            joined = make_envelope(
                T_JOINED, src=self.hub.identity.hash, room=r, body=joined_body
            )
            self.hub.message_helper.queue_env(outgoing, link, joined)

        try:
            inv = st.get("invited")
            if isinstance(inv, dict) and peer_hash in inv:
                inv.pop(peer_hash, None)
                if bool(st.get("registered")):
                    self.hub.room_manager.persist_room_state(link, r)
        except Exception:
            pass

        try:
            registered = bool(st.get("registered", False))
            topic = st.get("topic") if isinstance(st.get("topic"), str) else None
            mode_txt = self.hub.room_manager.get_room_mode_string(r)
            topic_txt = topic if topic else "(none)"
            reg_txt = "registered" if registered else "unregistered"
            self.hub.message_helper.emit_notice(
                outgoing,
                link,
                r,
                f"room {r}: {reg_txt}; mode={mode_txt}; topic={topic_txt}",
            )
        except Exception:
            pass

    def _handle_part(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        peer_hash: bytes,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle PART message."""
        room = env.get(K_ROOM)

        self.hub.stats_manager.inc("parts")
        if not isinstance(room, str) or not room:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="PART requires room name",
                )
            return

        try:
            r = self.hub._norm_room(room)
        except Exception as e:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text=str(e)
                )
            return

        sess["rooms"].discard(r)

        remaining_members = [
            member_link
            for member_link in self.hub.room_manager.get_room_members(r)
            if member_link != link
        ]

        if self.hub.room_manager.get_room_members(r):
            self.hub.room_manager.remove_member(r, link)
            if not self.hub.room_manager.get_room_members(r):
                self.hub.room_manager.remove_member(r, link)
                st = self.hub.room_manager._room_state_get(r)
                if st is not None:
                    self.hub.room_manager.touch_room(r)
                    if st.get("registered"):
                        self.hub.room_manager.persist_room_state(link, r)
                if st is not None and not st.get("registered"):
                    self.hub.room_manager._room_state.pop(r, None)

        if remaining_members and self.hub.identity is not None:
            notification_body = (
                [peer_hash] if self.hub.config.include_joined_member_list else None
            )
            member_notification = make_envelope(
                T_PARTED, src=self.hub.identity.hash, room=r, body=notification_body
            )
            member_notification_payload = encode(member_notification)
            for member_link in remaining_members:
                self.hub.message_helper.queue_payload(
                    outgoing, member_link, member_notification_payload
                )

        parted_body = (
            [peer_hash] if self.hub.config.include_joined_member_list else None
        )

        if self.hub.identity is not None:
            parted = make_envelope(
                T_PARTED, src=self.hub.identity.hash, room=r, body=parted_body
            )
            self.hub.message_helper.queue_env(outgoing, link, parted)

        self.log.info(
            "PART peer=%s nick=%r room=%s link_id=%s",
            self.hub._fmt_hash(peer_hash),
            sess.get("nick"),
            r,
            self.hub._fmt_link_id(link),
        )

    def _handle_message(
        self,
        link: RNS.Link,
        sess: dict[str, Any],
        peer_hash: bytes,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle MSG and NOTICE messages."""
        t = env.get(K_T)
        room = env.get(K_ROOM)
        body = env.get(K_BODY)

        if isinstance(body, str):
            cmdline = body.strip()
            if cmdline.startswith("/"):
                if self.log.isEnabledFor(logging.DEBUG):
                    self.log.debug(
                        "Slash command peer=%s link_id=%s cmd=%r room=%r",
                        self.hub._fmt_hash(peer_hash),
                        self.hub._fmt_link_id(link),
                        cmdline,
                        room,
                    )
                handled = self.hub.command_handler.handle_operator_command(
                    link, peer_hash=peer_hash, room=room, text=body, outgoing=outgoing
                )
                if handled:
                    if self.log.isEnabledFor(logging.DEBUG):
                        self.log.debug(
                            "Slash command handled, queued=%d responses",
                            len(outgoing),
                        )
                    return
                if self.hub.identity is not None:
                    self.hub.message_helper.emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="unrecognized command",
                        room=room,
                    )
                return

        if t == T_MSG:
            if not isinstance(room, str) or not room:
                if self.hub.identity is not None:
                    self.hub.message_helper.emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="message requires room name",
                    )
                return

            # Validate message body size (UTF-8 bytes)
            if isinstance(body, str):
                body_bytes = len(body.encode("utf-8", errors="replace"))
                if body_bytes > self.hub.config.max_msg_body_bytes:
                    if self.hub.identity is not None:
                        self.hub.message_helper.emit_error(
                            outgoing,
                            link,
                            src=self.hub.identity.hash,
                            text=f"message too large: {body_bytes} bytes > {self.hub.config.max_msg_body_bytes} bytes",
                        )
                    self.log.info(
                        "Rejected oversized message peer=%s nick=%r body_bytes=%s limit=%s",
                        self.hub._fmt_hash(peer_hash),
                        sess.get("nick"),
                        body_bytes,
                        self.hub.config.max_msg_body_bytes,
                    )
                    return
        elif t == T_NOTICE:
            if not isinstance(room, str) or not room:
                return

        try:
            r = self.hub._norm_room(str(room)) if room else ""
        except Exception as e:
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing, link, src=self.hub.identity.hash, text=str(e)
                )
            return

        if r not in sess["rooms"]:
            st = None
            if r in self.hub.room_manager._room_registry:
                st = self.hub.room_manager._room_state_ensure(r)
            elif self.hub.room_manager.get_room_members(r):
                st = self.hub.room_manager._room_state_ensure(r)

            if st is None:
                if self.hub.identity is not None:
                    self.hub.message_helper.emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="no such room",
                        room=r,
                    )
                return

            if bool(st.get("no_outside_msgs", False)):
                if self.hub.identity is not None:
                    self.hub.message_helper.emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="no outside messages (+n)",
                        room=r,
                    )
                return

        if self.hub.room_manager.is_room_banned(r, peer_hash):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="banned from room",
                    room=r,
                )
            return
        if self.hub.room_manager.is_room_moderated(
            r
        ) and not self.hub.room_manager.is_room_voiced(r, peer_hash):
            if self.hub.identity is not None:
                self.hub.message_helper.emit_error(
                    outgoing,
                    link,
                    src=self.hub.identity.hash,
                    text="room is moderated (+m)",
                    room=r,
                )
            return

        if peer_hash is not None:
            env[K_SRC] = (
                bytes(peer_hash)
                if isinstance(peer_hash, (bytes, bytearray))
                else peer_hash
            )
        env[K_ROOM] = r

        incoming_nick = env.get(K_NICK)
        if incoming_nick is not None:
            n = normalize_nick(incoming_nick, max_bytes=self.hub.config.max_nick_bytes)
            if n is not None:
                old_session_nick = sess.get("nick")
                if old_session_nick != n:
                    sess["nick"] = n
                    self.hub.session_manager.update_nick_index(
                        link, old_session_nick, n
                    )
                env[K_NICK] = n
            else:
                env.pop(K_NICK, None)
        else:
            nick = sess.get("nick")
            n = normalize_nick(nick, max_bytes=self.hub.config.max_nick_bytes)
            if n is not None:
                env[K_NICK] = n

        payload = encode(env)
        for other in list(self.hub.room_manager.get_room_members(r)):
            self.hub.message_helper.queue_payload(outgoing, other, payload)

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(
                "Forwarded t=%s peer=%s nick=%r room=%s recipients=%s body_type=%s",
                t,
                self.hub._fmt_hash(peer_hash),
                sess.get("nick"),
                r,
                len(self.hub.room_manager.get_room_members(r)),
                type(body).__name__,
            )

        if t == T_MSG:
            self.hub.stats_manager.inc("msgs_forwarded")
        else:
            self.hub.stats_manager.inc("notices_forwarded")

    def _handle_ping(
        self,
        link: RNS.Link,
        env: dict,
        outgoing: list[tuple[RNS.Link, bytes]],
    ) -> None:
        """Handle PING message."""
        body = env.get(K_BODY)

        self.hub.stats_manager.inc("pings_in")
        if self.hub.identity is not None:
            pong = make_envelope(T_PONG, src=self.hub.identity.hash, body=body)
            self.hub.stats_manager.inc("pongs_out")
            self.hub.message_helper.queue_env(outgoing, link, pong)

    def _extract_caps(self, body: Any) -> dict[int, Any]:
        """Extract capabilities from HELLO body."""
        if not isinstance(body, dict):
            return {}
        caps = body.get(B_HELLO_CAPS)
        return caps if isinstance(caps, dict) else {}
