"""Message sending and queueing utilities for the RRC hub."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import RNS

from .codec import encode
from .constants import B_WELCOME_HUB, B_WELCOME_VER, T_ERROR, T_NOTICE, T_WELCOME
from .envelope import make_envelope

if TYPE_CHECKING:
    from .service import HubService


class MessageHelper:
    """
    Helper methods for sending and queueing messages.

    Handles:
    - Message queueing (outgoing lists)
    - Notice chunking for large messages
    - WELCOME message construction
    - Error and notice emission
    - Smart text sending (resource vs chunks)
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = hub.log

    def packet_would_fit(self, link: RNS.Link, payload: bytes) -> bool:
        """Check if payload fits within link MDU without creating/packing packets."""
        try:
            if hasattr(link, "MDU") and link.MDU is not None:
                return len(payload) <= link.MDU
            pkt = RNS.Packet(link, payload)
            pkt.pack()
            return True
        except Exception:
            return False

    def queue_payload(
        self, outgoing: list[tuple[RNS.Link, bytes]], link: RNS.Link, payload: bytes
    ) -> None:
        """Add a raw payload to the outgoing queue."""
        self.hub.stats_manager.inc("bytes_out", len(payload))
        outgoing.append((link, payload))

    def queue_env(
        self, outgoing: list[tuple[RNS.Link, bytes]], link: RNS.Link, env: dict
    ) -> None:
        """Encode and queue an envelope."""
        payload = encode(env)
        self.queue_payload(outgoing, link, payload)

    def queue_notice_chunks(
        self,
        outgoing: list[tuple[RNS.Link, bytes]],
        link: RNS.Link,
        *,
        room: str | None,
        text: str,
    ) -> None:
        """Split and queue a notice message into MTU-sized chunks."""
        if self.hub.identity is None:
            return
        if not text:
            return

        lines = text.splitlines() or [text]
        for line in lines:
            remaining = line
            if not remaining:
                continue

            max_chars = min(len(remaining), 512)
            while remaining:
                take = min(len(remaining), max_chars)
                chunk = remaining[:take]
                env = make_envelope(
                    T_NOTICE,
                    src=self.hub.identity.hash,
                    room=room,
                    body=chunk,
                )
                payload = encode(env)
                if self.packet_would_fit(link, payload):
                    self.queue_payload(outgoing, link, payload)
                    remaining = remaining[take:]
                    max_chars = min(max_chars, 512)
                    continue

                if max_chars <= 1:
                    self.log.warning(
                        "NOTICE chunk would not fit MTU; dropping remainder (%s chars)",
                        len(remaining),
                    )
                    break

                max_chars = max(1, max_chars // 2)

    def queue_welcome(
        self,
        outgoing: list[tuple[RNS.Link, bytes]],
        link: RNS.Link,
        *,
        peer_hash: Any,
        motd: str | None,
    ) -> None:
        """Queue a WELCOME message for a newly connected peer."""
        if self.hub.identity is None:
            return

        from . import __version__

        body_w: dict[int, Any] = {
            B_WELCOME_HUB: self.hub.config.hub_name,
            B_WELCOME_VER: str(__version__),
        }

        welcome = make_envelope(T_WELCOME, src=self.hub.identity.hash, body=body_w)
        welcome_payload = encode(welcome)

        if not self.packet_would_fit(link, welcome_payload):
            self.log.warning(
                "WELCOME would not fit MTU; cannot welcome peer=%s link_id=%s",
                self.hub._fmt_hash(peer_hash),
                self.hub._fmt_link_id(link),
            )
            return

        self.queue_payload(outgoing, link, welcome_payload)
        self.log.debug(
            "Queued WELCOME peer=%s link_id=%s",
            self.hub._fmt_hash(peer_hash),
            self.hub._fmt_link_id(link),
        )

    def send_text_smart(
        self,
        link: RNS.Link,
        *,
        msg_type: int,
        text: str,
        room: str | None = None,
        kind: str | None = None,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """
        Send text message using the most efficient method:
        - Resource transfer for large messages (if enabled and outgoing is None)
        - Chunked messages otherwise
        """
        from .constants import RES_KIND_MOTD, RES_KIND_NOTICE

        resource_kind = kind
        if resource_kind is None:
            resource_kind = (
                RES_KIND_MOTD
                if msg_type == T_NOTICE and room is None
                else RES_KIND_NOTICE
            )

        if (
            self.hub.config.enable_resource_transfer
            and outgoing is None
            and len(text.encode(encoding, errors="replace")) > 512
        ):
            self.log.debug(
                "Attempting resource transfer link_id=%s kind=%s chars=%s",
                self.hub._fmt_link_id(link),
                resource_kind,
                len(text),
            )
            if self.hub.resource_manager.send_via_resource(
                link,
                kind=resource_kind,
                payload=text.encode(encoding, errors="replace"),
                room=room,
                encoding=encoding,
            ):
                self.log.debug(
                    "Sent large text via resource link_id=%s kind=%s chars=%s",
                    self.hub._fmt_link_id(link),
                    resource_kind,
                    len(text),
                )
                return
            else:
                self.log.warning(
                    "Resource send failed, falling back to chunks link_id=%s",
                    self.hub._fmt_link_id(link),
                )

        if msg_type == T_NOTICE:
            self.log.debug(
                "Falling back to chunking link_id=%s outgoing_is_none=%s",
                self.hub._fmt_link_id(link),
                outgoing is None,
            )
            if outgoing is None:
                outgoing = []
                self.queue_notice_chunks(outgoing, link, room=room, text=text)
                for out_link, chunk_payload in outgoing:
                    self.hub.stats_manager.inc("bytes_out", len(chunk_payload))
                    try:
                        RNS.Packet(out_link, chunk_payload).send()
                    except Exception as e:
                        self.log.warning(
                            "Failed to send chunk link_id=%s: %s",
                            self.hub._fmt_link_id(out_link),
                            e,
                        )
            else:
                self.queue_notice_chunks(outgoing, link, room=room, text=text)
        else:
            self.log.error(
                "Message too large and not NOTICE link_id=%s type=%s",
                self.hub._fmt_link_id(link),
                msg_type,
            )

    def emit_notice(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        room: str | None,
        text: str,
    ) -> None:
        """Emit a notice message (queued or immediate)."""
        if self.hub.identity is None:
            return
        env = make_envelope(T_NOTICE, src=self.hub.identity.hash, room=room, body=text)
        if outgoing is None:
            self.send(link, env)
        else:
            self.queue_env(outgoing, link, env)

    def emit_error(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        *,
        src: bytes,
        text: str,
        room: str | None = None,
    ) -> None:
        """Emit an error message (queued or immediate)."""
        self.hub.stats_manager.inc("errors_sent")
        env = make_envelope(T_ERROR, src=src, room=room, body=text)
        if outgoing is None:
            self.send(link, env)
        else:
            self.queue_env(outgoing, link, env)

    def notice_to(self, link: RNS.Link, room: str | None, text: str) -> None:
        """Send a notice message immediately."""
        if self.hub.identity is None:
            return
        env = make_envelope(T_NOTICE, src=self.hub.identity.hash, room=room, body=text)
        self.send(link, env)

    def error(
        self, link: RNS.Link, src: bytes, text: str, room: str | None = None
    ) -> None:
        """Send an error message immediately."""
        self.emit_error(None, link, src=src, text=text, room=room)

    def send(self, link: RNS.Link, env: dict) -> None:
        """Send an envelope immediately (not queued)."""
        payload = encode(env)
        self.hub.stats_manager.inc("bytes_out", len(payload))
        try:
            RNS.Packet(link, payload).send()
        except OSError as e:
            self.log.warning(
                "Send failed link_id=%s bytes=%s err=%s",
                self.hub._fmt_link_id(link),
                len(payload),
                e,
            )
        except Exception:
            self.log.debug(
                "Send failed link_id=%s bytes=%s",
                self.hub._fmt_link_id(link),
                len(payload),
                exc_info=True,
            )
