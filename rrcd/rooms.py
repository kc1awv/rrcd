"""Room management for RRCD hub.

This module handles all room-related functionality including:
- Room membership tracking
- Room state (modes, topic, permissions)
- Room registry persistence to TOML
- Permission management (ops, voiced, bans)
- Invite tracking with expiration
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any

import RNS

if TYPE_CHECKING:
    from .service import HubService


class RoomManager:
    """Manages room memberships, state, permissions, and registry persistence."""

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = logging.getLogger("rrcd.rooms")
        self.rooms: dict[str, set[RNS.Link]] = {}
        self._room_state: dict[str, dict[str, Any]] = {}
        self._room_registry: dict[str, dict[str, Any]] = {}

        self._room_registry_write_lock = threading.Lock()

    def clear_all(self) -> None:
        """Clear all room state. Called during hub shutdown."""
        self.rooms.clear()
        self._room_state.clear()
        self._room_registry.clear()

    def get_room_members(self, room: str) -> set[RNS.Link]:
        """Get set of links currently in a room."""
        return self.rooms.get(room, set())

    def add_member(
        self, room: str, link: RNS.Link, *, founder: bytes | None = None
    ) -> None:
        """Add a link to a room, creating the room if needed."""
        if room not in self.rooms:
            self.rooms[room] = set()
            self._room_state_ensure(room, founder=founder)

        self.rooms.setdefault(room, set()).add(link)

    def remove_member(self, room: str, link: RNS.Link) -> None:
        """Remove a link from a room, cleaning up empty rooms."""
        if room in self.rooms:
            self.rooms[room].discard(link)
            if not self.rooms[room]:
                self.rooms.pop(room, None)
                st = self._room_state_get(room)
                if st is not None and not st.get("registered"):
                    self._room_state.pop(room, None)

    def remove_member_from_all(self, link: RNS.Link) -> int:
        """Remove a link from all rooms. Returns number of rooms left."""
        rooms_to_remove = [r for r, links in self.rooms.items() if link in links]
        for room in rooms_to_remove:
            self.remove_member(room, link)
        return len(rooms_to_remove)

    def get_member_rooms(self, link: RNS.Link) -> list[str]:
        """Get list of rooms a link is currently in."""
        return [room for room, links in self.rooms.items() if link in links]

    def get_stats(self) -> dict[str, Any]:
        """Get room statistics for hub stats."""
        rooms_total = len(self.rooms)
        memberships = sum(len(v) for v in self.rooms.values())
        top_rooms = sorted(
            ((room, len(links)) for room, links in self.rooms.items()),
            key=lambda x: (-x[1], x[0]),
        )[:5]
        return {
            "rooms_total": rooms_total,
            "memberships": memberships,
            "top_rooms": top_rooms,
        }

    def _room_state_get(self, room: str) -> dict[str, Any] | None:
        """Get room state dict if it exists."""
        return self._room_state.get(room)

    def _room_state_ensure(
        self, room: str, *, founder: bytes | None = None
    ) -> dict[str, Any]:
        """Ensure room state exists, creating from registry or defaults."""
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

    def touch_room(self, room: str) -> None:
        """Update last_used_ts for a room."""
        try:
            st = self._room_state_ensure(room)
            ts = float(time.time())
            st["last_used_ts"] = ts
            reg = self._room_registry.get(room)
            if isinstance(reg, dict):
                reg["last_used_ts"] = ts
        except Exception:
            pass

    def get_room_modes(self, room: str) -> dict[str, Any]:
        """Get dict of room mode flags."""
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

    def get_room_mode_string(self, room: str) -> str:
        """Get IRC-style mode string for a room."""
        m = self.get_room_modes(room)
        flags: list[str] = []
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

    def broadcast_room_mode(
        self, room: str, outgoing: list[tuple[RNS.Link, bytes]] | None = None
    ) -> None:
        """Broadcast current room mode to all members."""
        mode_txt = self.get_room_mode_string(room)
        recipients = list(self.get_room_members(room))
        for other in recipients:
            self.hub.message_helper.emit_notice(
                outgoing, other, room, f"mode for {room} is now: {mode_txt}"
            )

    def is_room_moderated(self, room: str) -> bool:
        """Check if room is moderated."""
        st = self._room_state_ensure(room)
        return bool(st.get("moderated", False))

    def is_room_op(self, room: str, peer_hash: bytes | None) -> bool:
        """Check if peer is a room operator."""
        if peer_hash is None:
            return False
        if self.hub.trust_manager.is_server_op(peer_hash):
            return True
        st = self._room_state_ensure(room)
        founder = st.get("founder")
        if isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash:
            return True
        ops = st.get("ops")
        return isinstance(ops, set) and peer_hash in ops

    def is_room_voiced(self, room: str, peer_hash: bytes | None) -> bool:
        """Check if peer has voice in room."""
        if peer_hash is None:
            return False
        if self.is_room_op(room, peer_hash):
            return True
        st = self._room_state_ensure(room)
        voiced = st.get("voiced")
        return isinstance(voiced, set) and peer_hash in voiced

    def is_room_banned(self, room: str, peer_hash: bytes | None) -> bool:
        """Check if peer is banned from room."""
        if peer_hash is None:
            return False
        st = self._room_state_ensure(room)
        bans = st.get("bans")
        return isinstance(bans, set) and peer_hash in bans

    def is_invited(self, room: str, peer_hash: bytes) -> bool:
        """Check if peer has a valid (non-expired) invite."""
        st = self._room_state_ensure(room)
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

    def prune_expired_invites(self, room: str) -> bool:
        """Remove expired invites from a room. Returns True if any were removed."""
        st = self._room_state_ensure(room)
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

    def load_registry_from_path(
        self, path: str, *, invite_timeout_s: float
    ) -> tuple[dict[str, dict[str, Any]], str | None]:
        """Load room registry from TOML file. Returns (registry, error_msg)."""
        if not path or not os.path.exists(path):
            return {}, None

        try:
            from tomlkit import parse  # type: ignore
        except ImportError:
            return {}, "missing dependency tomlkit"

        try:
            with open(path, encoding="utf-8") as f:
                doc = parse(f.read())
        except Exception as e:
            return {}, f"parse error: {e}"

        rooms_section = doc.get("rooms")
        if not isinstance(rooms_section, dict):
            return {}, None

        registry: dict[str, dict[str, Any]] = {}
        now = float(time.time())

        for room_name, room_data in rooms_section.items():
            if not isinstance(room_data, dict):
                continue

            founder = room_data.get("founder")
            if isinstance(founder, str):
                try:
                    founder = bytes.fromhex(founder.strip().lower().removeprefix("0x"))
                except Exception:
                    founder = None

            topic = room_data.get("topic")
            if not isinstance(topic, str):
                topic = None

            moderated = bool(room_data.get("moderated", False))
            invite_only = bool(room_data.get("invite_only", False))
            topic_ops_only = bool(room_data.get("topic_ops_only", False))
            no_outside_msgs = bool(room_data.get("no_outside_msgs", False))
            private = bool(room_data.get("private", False))

            key = room_data.get("key")
            if not isinstance(key, str):
                key = None

            operators = room_data.get("operators", [])
            ops: set[bytes] = set()
            if isinstance(operators, list):
                for op in operators:
                    if isinstance(op, str):
                        try:
                            ops.add(
                                bytes.fromhex(op.strip().lower().removeprefix("0x"))
                            )
                        except Exception:
                            continue

            voiced_list = room_data.get("voiced", [])
            voiced: set[bytes] = set()
            if isinstance(voiced_list, list):
                for v in voiced_list:
                    if isinstance(v, str):
                        try:
                            voiced.add(
                                bytes.fromhex(v.strip().lower().removeprefix("0x"))
                            )
                        except Exception:
                            continue

            bans_list = room_data.get("bans", [])
            bans: set[bytes] = set()
            if isinstance(bans_list, list):
                for b in bans_list:
                    if isinstance(b, str):
                        try:
                            bans.add(
                                bytes.fromhex(b.strip().lower().removeprefix("0x"))
                            )
                        except Exception:
                            continue

            invited_dict = room_data.get("invited", {})
            invited: dict[bytes, float] = {}
            if isinstance(invited_dict, dict):
                for h, exp in invited_dict.items():
                    if isinstance(h, str):
                        try:
                            h_bytes = bytes.fromhex(
                                h.strip().lower().removeprefix("0x")
                            )
                            exp_f = float(exp)
                            if exp_f > now:
                                invited[h_bytes] = exp_f
                        except Exception:
                            continue

            last_used_ts = room_data.get("last_used_ts")
            try:
                last_used_ts = float(last_used_ts) if last_used_ts is not None else None
            except Exception:
                last_used_ts = None

            registry[room_name] = {
                "founder": founder,
                "topic": topic,
                "moderated": moderated,
                "invite_only": invite_only,
                "topic_ops_only": topic_ops_only,
                "no_outside_msgs": no_outside_msgs,
                "private": private,
                "key": key,
                "ops": ops,
                "voiced": voiced,
                "bans": bans,
                "invited": invited,
                "last_used_ts": last_used_ts,
            }

        return registry, None

    def diff_registry_summary(
        self, old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]
    ) -> list[str]:
        """Generate human-readable summary of registry changes."""
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

    def get_registry_path_for_writes(self) -> str | None:
        """Get path to room registry file for write operations."""
        from .util import expand_path

        p = self.hub.config.room_registry_path
        if not p:
            return None
        return expand_path(str(p))

    def persist_room_state(self, link: RNS.Link, room: str | None) -> None:
        """Persist room state to registry TOML file."""
        if room is None:
            return
        reg_path = self.get_registry_path_for_writes()
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
            self.hub.message_helper.notice_to(
                link, room, f"room config persist failed: {e}"
            )

    def delete_room_from_registry(self, link: RNS.Link, room: str) -> None:
        """Remove a room from the registry TOML file."""
        reg_path = self.get_registry_path_for_writes()
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
            self.hub.message_helper.notice_to(
                link, room, f"room unregister persist failed: {e}"
            )

    def prune_unused_registered_rooms(
        self, prune_after_s: float, started_wall_time: float
    ) -> list[str]:
        """
        Prune registered rooms that haven't been used recently.

        Returns list of pruned room names.
        """
        now = float(time.time())
        rooms_to_prune: list[str] = []

        for room, reg in list(self._room_registry.items()):
            if room in self.rooms and self.rooms.get(room):
                continue

            last_used = reg.get("last_used_ts")
            try:
                last_used = float(last_used) if last_used is not None else None
            except Exception:
                last_used = None
            if last_used is None:
                last_used = started_wall_time

            if (now - float(last_used)) < prune_after_s:
                continue

            self._room_registry.pop(room, None)
            self._room_state.pop(room, None)
            rooms_to_prune.append(room)

        return rooms_to_prune

    def merge_registry_into_state(self, registry: dict[str, dict[str, Any]]) -> None:
        """
        Merge registry into live room state.

        Updates in-memory state for active rooms with registry data.
        """
        for r, st in list(self._room_state.items()):
            if not isinstance(st, dict):
                continue

            reg = registry.get(r)
            if reg is None:
                if st.get("registered"):
                    st["registered"] = False
                continue

            st["registered"] = True

            founder = reg.get("founder")
            if isinstance(founder, (bytes, bytearray)):
                st["founder"] = bytes(founder)

            topic = reg.get("topic")
            if isinstance(topic, str):
                st["topic"] = topic

            st["moderated"] = bool(reg.get("moderated", False))
            st["invite_only"] = bool(reg.get("invite_only", False))
            st["topic_ops_only"] = bool(reg.get("topic_ops_only", False))
            st["no_outside_msgs"] = bool(reg.get("no_outside_msgs", False))
            st["private"] = bool(reg.get("private", False))

            key = reg.get("key")
            if isinstance(key, str):
                st["key"] = key

            ops = reg.get("ops")
            if isinstance(ops, set):
                st["ops"] = set(ops)

            voiced = reg.get("voiced")
            if isinstance(voiced, set):
                st["voiced"] = set(voiced)

            bans = reg.get("bans")
            if isinstance(bans, set):
                st["bans"] = set(bans)

            invited = reg.get("invited")
            if isinstance(invited, dict):
                st["invited"] = dict(invited)

            last_used_ts = reg.get("last_used_ts")
            if last_used_ts is not None:
                st["last_used_ts"] = last_used_ts
