from __future__ import annotations

import threading
from dataclasses import dataclass

import RNS

from rrcd.codec import decode
from rrcd.constants import K_BODY, K_NICK, K_T, T_JOIN, T_JOINED, T_PART, T_PARTED
from rrcd.envelope import make_envelope
from rrcd.router import MessageRouter
from rrcd.session import SessionManager


class _FakeStats:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    def inc(self, key: str, delta: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + delta


class _FakeMessageHelper:
    def __init__(self) -> None:
        self.errors: list[tuple[object, str, str | None]] = []
        self.notices: list[tuple[object, str | None, str]] = []

    def emit_error(
        self, outgoing, link, *, src: bytes, text: str, room: str | None = None
    ) -> None:
        self.errors.append((link, text, room))

    def emit_notice(self, outgoing, link, room: str | None, text: str) -> None:
        self.notices.append((link, room, text))

    def queue_payload(self, outgoing, link, payload: bytes) -> None:
        outgoing.append((link, payload))

    def queue_env(self, outgoing, link, env: dict) -> None:
        from rrcd.codec import encode

        outgoing.append((link, encode(env)))


class _FakeRoomManager:
    def __init__(self, members_by_room: dict[str, list[object]]) -> None:
        self._members_by_room = {
            room: list(members) for room, members in members_by_room.items()
        }
        self._room_registry: set[str] = set(members_by_room)
        self._room_state: dict[str, dict] = {room: {} for room in members_by_room}

    def get_room_members(self, room: str) -> list[object]:
        return list(self._members_by_room.get(room, []))

    def _room_state_ensure(self, room: str, founder: bytes | None = None) -> dict:
        return self._room_state.setdefault(room, {})

    def _room_state_get(self, room: str) -> dict | None:
        return self._room_state.get(room)

    def add_member(self, room: str, link: object) -> None:
        self._members_by_room.setdefault(room, []).append(link)

    def remove_member(self, room: str, link: object) -> None:
        members = self._members_by_room.get(room, [])
        self._members_by_room[room] = [member for member in members if member != link]

    def touch_room(self, room: str) -> None:
        return

    def persist_room_state(self, link: object, room: str) -> None:
        return

    def get_room_mode_string(self, room: str) -> str:
        return "+"

    def is_invited(self, room: str, peer_hash: bytes) -> bool:
        return False

    def is_room_op(self, room: str, peer_hash: bytes) -> bool:
        return False

    def is_room_banned(self, room: str, peer_hash: bytes) -> bool:
        return False

    def is_room_moderated(self, room: str) -> bool:
        return False

    def is_room_voiced(self, room: str, peer_hash: bytes) -> bool:
        return True


class _FakeSessionManager:
    def __init__(self, sessions: dict[object, dict]) -> None:
        self.sessions = sessions

    def update_nick_index(
        self, link: object, old_nick: str | None, new_nick: str | None
    ) -> None:
        return


@dataclass
class _FakeIdentity:
    hash: bytes


@dataclass
class _FakeConfig:
    include_joined_member_list: bool = True
    max_nick_bytes: int = 32
    max_msg_body_bytes: int = 350
    max_rooms_per_session: int = 8
    rate_limit_msgs_per_minute: int = 240


class _FakeLink:
    MDU = 10000


class _FakeHub:
    def __init__(self, room_manager: _FakeRoomManager, session_manager) -> None:
        import logging

        self.log = logging.getLogger("test")
        self.identity = _FakeIdentity(hash=b"hub")
        self.config = _FakeConfig()
        self.stats_manager = _FakeStats()
        self.message_helper = _FakeMessageHelper()
        self.room_manager = room_manager
        self.session_manager = session_manager
        self._state_lock = threading.RLock()

    def _norm_room(self, room: str) -> str:
        return room.lower()

    def _fmt_hash(self, value: bytes) -> str:
        return value.hex()

    def _fmt_link_id(self, link: object) -> str:
        return "link"


def test_joined_fanout_includes_joiner_nick_for_existing_members() -> None:
    joining_link = _FakeLink()
    existing_link = object()
    joining_sess = {"rooms": set(), "nick": "alice", "peer": b"peer"}
    existing_sess = {"rooms": {"#general"}, "nick": "bob", "peer": b"other"}
    room_manager = _FakeRoomManager({"#general": [existing_link]})
    session_manager = _FakeSessionManager(
        {joining_link: joining_sess, existing_link: existing_sess}
    )
    hub = _FakeHub(room_manager, session_manager)
    router = MessageRouter(hub)
    outgoing: list[tuple[object, bytes]] = []

    router._handle_join(
        joining_link,
        joining_sess,
        b"peer",
        make_envelope(T_JOIN, src=b"peer", room="#general"),
        outgoing,
    )

    payloads = {link: decode(payload) for link, payload in outgoing}

    assert payloads[existing_link][K_T] == T_JOINED
    assert payloads[existing_link][K_BODY] == [b"peer"]
    assert payloads[existing_link][K_NICK] == "alice"

    assert payloads[joining_link][K_T] == T_JOINED
    assert payloads[joining_link][K_BODY] == [b"other", b"peer"]
    assert K_NICK not in payloads[joining_link]


def test_joined_fanout_omits_nick_when_joiner_has_no_nick() -> None:
    joining_link = _FakeLink()
    existing_link = object()
    joining_sess = {"rooms": set(), "nick": None, "peer": b"peer"}
    existing_sess = {"rooms": {"#general"}, "nick": "bob", "peer": b"other"}
    room_manager = _FakeRoomManager({"#general": [existing_link]})
    session_manager = _FakeSessionManager(
        {joining_link: joining_sess, existing_link: existing_sess}
    )
    hub = _FakeHub(room_manager, session_manager)
    router = MessageRouter(hub)
    outgoing: list[tuple[object, bytes]] = []

    router._handle_join(
        joining_link,
        joining_sess,
        b"peer",
        make_envelope(T_JOIN, src=b"peer", room="#general"),
        outgoing,
    )

    payloads = {link: decode(payload) for link, payload in outgoing}

    assert payloads[existing_link][K_T] == T_JOINED
    assert payloads[existing_link][K_BODY] == [b"peer"]
    assert K_NICK not in payloads[existing_link]


def test_parted_fanout_includes_departing_nick_for_existing_members() -> None:
    parting_link = _FakeLink()
    remaining_link = object()
    parting_sess = {"rooms": {"#general"}, "nick": "alice", "peer": b"peer"}
    remaining_sess = {"rooms": {"#general"}, "nick": "bob", "peer": b"other"}
    room_manager = _FakeRoomManager({"#general": [parting_link, remaining_link]})
    session_manager = _FakeSessionManager(
        {parting_link: parting_sess, remaining_link: remaining_sess}
    )
    hub = _FakeHub(room_manager, session_manager)
    router = MessageRouter(hub)
    outgoing: list[tuple[object, bytes]] = []

    router._handle_part(
        parting_link,
        parting_sess,
        b"peer",
        make_envelope(T_PART, src=b"peer", room="#general"),
        outgoing,
    )

    payloads = {link: decode(payload) for link, payload in outgoing}

    assert payloads[remaining_link][K_T] == T_PARTED
    assert payloads[remaining_link][K_BODY] == [b"peer"]
    assert payloads[remaining_link][K_NICK] == "alice"

    assert payloads[parting_link][K_T] == T_PARTED
    assert payloads[parting_link][K_BODY] == [b"peer"]
    assert K_NICK not in payloads[parting_link]


def test_disconnect_parted_fanout_includes_cached_nick(monkeypatch) -> None:
    closing_link = _FakeLink()
    remaining_link = object()
    room_manager = _FakeRoomManager({"#general": [closing_link, remaining_link]})
    hub = _FakeHub(room_manager, session_manager=None)
    session_manager = SessionManager(hub)
    hub.session_manager = session_manager
    session_manager.sessions = {
        closing_link: {"rooms": {"#general"}, "peer": b"peer", "nick": "alice"},
        remaining_link: {"rooms": {"#general"}, "peer": b"other", "nick": "bob"},
    }
    session_manager._rate = {closing_link: object(), remaining_link: object()}
    session_manager._index_by_hash = {b"peer": closing_link, b"other": remaining_link}
    sent_packets: list[tuple[object, bytes]] = []

    class _Packet:
        def __init__(self, link: object, payload: bytes) -> None:
            self.link = link
            self.payload = payload

        def send(self) -> None:
            sent_packets.append((self.link, self.payload))

    monkeypatch.setattr(RNS, "Packet", _Packet)

    peer_hash, nick, rooms_count = session_manager.on_link_closed(closing_link)

    assert peer_hash == b"peer"
    assert nick == "alice"
    assert rooms_count == 1
    assert len(sent_packets) == 1
    assert sent_packets[0][0] is remaining_link

    decoded = decode(sent_packets[0][1])
    assert decoded[K_T] == T_PARTED
    assert decoded[K_BODY] == [b"peer"]
    assert decoded[K_NICK] == "alice"
