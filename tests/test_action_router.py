from __future__ import annotations

import threading
from dataclasses import dataclass

from rrcd.codec import decode
from rrcd.constants import (
    B_WELCOME_CAPS,
    CAP_ACTION,
    CAP_DIRECT_NOTICE,
    CAP_RESOURCE_ENVELOPE,
    K_BODY,
    K_DST,
    K_NICK,
    K_SRC,
    K_T,
    T_ACTION,
    T_NOTICE,
)
from rrcd.envelope import make_envelope
from rrcd.messages import MessageHelper
from rrcd.router import MessageRouter


class _FakeStats:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    def inc(self, key: str, delta: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + delta


class _FakeCommandHandler:
    def __init__(self) -> None:
        self.called = False

    def handle_operator_command(self, *args, **kwargs) -> bool:
        self.called = True
        return False


class _FakeRoomManager:
    def __init__(self, members: list[object]) -> None:
        self._members = members
        self._room_registry: set[str] = set()

    def get_room_members(self, room: str) -> list[object]:
        return list(self._members)

    def _room_state_ensure(self, room: str) -> dict:
        return {}

    def is_room_banned(self, room: str, peer_hash: bytes) -> bool:
        return False

    def is_room_moderated(self, room: str) -> bool:
        return False

    def is_room_voiced(self, room: str, peer_hash: bytes) -> bool:
        return True


class _FakeSessionManager:
    def __init__(self) -> None:
        self.targets: dict[bytes, object] = {}

    def update_nick_index(
        self, link: object, old_nick: str | None, new_nick: str | None
    ) -> None:
        return

    def get_link_by_hash(self, peer_hash: bytes) -> object | None:
        return self.targets.get(bytes(peer_hash))


class _FakeMessageHelper:
    def __init__(self) -> None:
        self.errors: list[tuple[object, str, str | None]] = []

    def emit_error(
        self, outgoing, link, *, src: bytes, text: str, room: str | None = None
    ) -> None:
        self.errors.append((link, text, room))

    def queue_payload(self, outgoing, link, payload: bytes) -> None:
        outgoing.append((link, payload))


@dataclass
class _FakeIdentity:
    hash: bytes


@dataclass
class _FakeConfig:
    max_nick_bytes: int = 32
    max_msg_body_bytes: int = 350
    hub_name: str = "rrcd"
    max_room_name_bytes: int = 64
    max_rooms_per_session: int = 8
    rate_limit_msgs_per_minute: int = 240
    enable_resource_transfer: bool = False


class _FakeLink:
    MDU = 10000


class _FakeHub:
    def __init__(self, link: object, members: list[object] | None = None) -> None:
        import logging

        self.log = logging.getLogger("test")
        self.identity = _FakeIdentity(hash=b"hub")
        self.config = _FakeConfig()
        self.stats_manager = _FakeStats()
        self.command_handler = _FakeCommandHandler()
        self.room_manager = _FakeRoomManager(members if members is not None else [link])
        self.session_manager = _FakeSessionManager()
        self.message_helper = _FakeMessageHelper()
        self._state_lock = threading.RLock()

    def _norm_room(self, room: str) -> str:
        return room.lower()

    def _fmt_hash(self, value: bytes) -> str:
        return value.hex()

    def _fmt_link_id(self, link: object) -> str:
        return "link"


def test_action_is_forwarded_without_command_interpretation() -> None:
    link = _FakeLink()
    hub = _FakeHub(link)
    router = MessageRouter(hub)

    sess = {"rooms": {"#general"}, "nick": "alice"}
    env = make_envelope(T_ACTION, src=b"peer", room="#general", body="/me waves")
    outgoing: list[tuple[object, bytes]] = []

    router._handle_message(link, sess, b"peer", env, outgoing)

    assert hub.command_handler.called is False
    assert hub.message_helper.errors == []
    assert hub.stats_manager.counters.get("actions_forwarded") == 1
    assert len(outgoing) == 1

    decoded = decode(outgoing[0][1])
    assert decoded[K_T] == T_ACTION
    assert decoded[K_BODY] == "/me waves"


def test_welcome_advertises_action_capability() -> None:
    import logging

    class _WelcomeHub:
        def __init__(self) -> None:
            self.log = logging.getLogger("test")
            self.identity = _FakeIdentity(hash=b"hub")
            self.config = _FakeConfig(enable_resource_transfer=True)
            self.stats_manager = _FakeStats()

        def _fmt_hash(self, value: bytes) -> str:
            return value.hex()

        def _fmt_link_id(self, link: object) -> str:
            return "link"

    hub = _WelcomeHub()
    helper = MessageHelper(hub)
    link = _FakeLink()
    outgoing: list[tuple[object, bytes]] = []

    helper.queue_welcome(outgoing, link, peer_hash=b"peer", motd=None)

    assert len(outgoing) == 1
    decoded = decode(outgoing[0][1])
    caps = decoded[K_BODY][B_WELCOME_CAPS]
    assert caps[CAP_ACTION] is True
    assert caps[CAP_DIRECT_NOTICE] is True
    assert caps[CAP_RESOURCE_ENVELOPE] is True


def test_notice_is_forwarded_to_direct_destination() -> None:
    sender_link = _FakeLink()
    target_link = object()
    hub = _FakeHub(sender_link)
    hub.session_manager.targets[b"target"] = target_link
    router = MessageRouter(hub)

    sess = {"rooms": set(), "nick": "alice"}
    env = make_envelope(T_NOTICE, src=b"spoofed", dst=b"target", body="hello")
    outgoing: list[tuple[object, bytes]] = []

    router._handle_message(sender_link, sess, b"peer", env, outgoing)

    assert hub.message_helper.errors == []
    assert hub.stats_manager.counters.get("notices_forwarded") == 1
    assert len(outgoing) == 1
    assert outgoing[0][0] is target_link

    decoded = decode(outgoing[0][1])
    assert decoded[K_T] == T_NOTICE
    assert decoded[K_SRC] == b"peer"
    assert decoded[K_DST] == b"target"
    assert decoded[K_NICK] == "alice"
    assert decoded[K_BODY] == "hello"


def test_direct_notice_rejects_room_and_destination_combination() -> None:
    sender_link = _FakeLink()
    hub = _FakeHub(sender_link)
    hub.session_manager.targets[b"target"] = object()
    router = MessageRouter(hub)

    sess = {"rooms": {"#general"}, "nick": "alice"}
    env = make_envelope(
        T_NOTICE,
        src=b"peer",
        dst=b"target",
        room="#general",
        body="hello",
    )
    outgoing: list[tuple[object, bytes]] = []

    router._handle_message(sender_link, sess, b"peer", env, outgoing)

    assert outgoing == []
    assert hub.message_helper.errors == [
        (sender_link, "direct notice must not include room", None)
    ]


def test_direct_notice_rejects_unknown_destination() -> None:
    sender_link = _FakeLink()
    hub = _FakeHub(sender_link)
    router = MessageRouter(hub)

    sess = {"rooms": set(), "nick": "alice"}
    env = make_envelope(T_NOTICE, src=b"peer", dst=b"missing", body="hello")
    outgoing: list[tuple[object, bytes]] = []

    router._handle_message(sender_link, sess, b"peer", env, outgoing)

    assert outgoing == []
    assert hub.message_helper.errors == [
        (sender_link, "destination not connected", None)
    ]
