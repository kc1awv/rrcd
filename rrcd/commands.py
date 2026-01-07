"""Command handling for RRCD operator commands."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import RNS

from rrcd.constants import T_ERROR, T_NOTICE
from rrcd.envelope import make_envelope

if TYPE_CHECKING:
    from rrcd.service import HubService


class CommandHandler:
    """Handles operator commands for the RRC hub."""

    def __init__(self, hub: HubService) -> None:
        self.hub = hub

    def handle_operator_command(
        self,
        link: RNS.Link,
        peer_hash: bytes,
        room: str | None,
        text: str,
        *,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
    ) -> bool:
        """Handle an operator command.
        
        Returns True if it was a recognized command (handled). Unknown commands
        return False so the message can be forwarded as normal chat.
        """
        cmdline = text.strip()
        if not cmdline.startswith("/"):
            return False

        parts = [p for p in cmdline[1:].split() if p]
        if not parts:
            return False

        cmd = parts[0].lower()

        if cmd == "reload":
            if not self.hub.trust_manager.is_server_op(peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True
            # Hub-level command - send responses without room field
            self.hub._reload_config_and_rooms(link, None, outgoing)
            return True

        # Global/server-operator commands
        if cmd == "stats":
            if not self.hub.trust_manager.is_server_op(peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True
            # Send response without room field for hub-level command
            self.hub.message_helper.emit_notice(outgoing, link, None, self.hub.stats_manager.format_stats())
            return True

        if cmd == "list":
            # List all registered, non-private rooms with their topics
            with self.hub._state_lock:
                registered_rooms = []
                for room_name, st in self.hub.room_manager._room_state.items():
                    if st.get("registered") and not st.get("private"):
                        topic = st.get("topic")
                        registered_rooms.append((room_name, topic))
                
                # Also check room registry for rooms not currently in room_state
                for room_name, reg in self.hub.room_manager._room_registry.items():
                    if room_name not in self.hub.room_manager._room_state:
                        if not reg.get("private"):
                            topic = reg.get("topic")
                            registered_rooms.append((room_name, topic))

            if not registered_rooms:
                self.hub.message_helper.emit_notice(outgoing, link, None, "No public rooms registered")
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
            
            self.hub.message_helper.emit_notice(outgoing, link, None, "\n".join(lines))
            return True

        if cmd in ("who", "names"):
            target_room = room
            if len(parts) >= 2:
                target_room = parts[1]
            if not isinstance(target_room, str) or not target_room:
                self.hub.message_helper.emit_notice(outgoing, link, None, "usage: /who [room]")
                return True
            try:
                r = self.hub._norm_room(target_room)
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            # Check if room is private - only server operators can see private rooms
            st = self.hub.room_manager._room_state_get(r)
            if st and st.get("private"):
                if not self.hub.trust_manager.is_server_op(peer_hash):
                    self.hub.message_helper.emit_notice(outgoing, link, None, f"room {r} is private")
                    return True

            members = []
            for other in sorted(self.hub.room_manager.get_room_members(r), key=lambda x: id(x)):
                s = self.hub.session_manager.sessions.get(other)
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
            self.hub.message_helper.emit_notice(
                outgoing,
                link,
                None,
                f"members in {r}: " + (", ".join(members) if members else "(none)"),
            )
            return True

        if cmd == "kick":
            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing, link, None, "usage: /kick <room> <nick|hashprefix>"
                )
                return True
            target_room = parts[1]
            target = parts[2]
            try:
                r = self.hub._norm_room(target_room)
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, room, f"bad room: {e}")
                return True

            if not self.hub.room_manager.is_room_op(r, peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            target_link = self._find_target_link(target, room=r)
            if target_link is None:
                # Check if ambiguous or just not found
                all_matches = self._find_target_links(target, room=r)
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(target, all_matches)
                )
                return True

            tsess = self.hub.session_manager.sessions.get(target_link)
            if not tsess or r not in tsess.get("rooms", set()):
                self.hub.message_helper.emit_notice(outgoing, link, room, "target not in room")
                return True

            tsess["rooms"].discard(r)
            if self.hub.room_manager.get_room_members(r):
                self.hub.room_manager.rooms[r].discard(target_link)
                if not self.hub.room_manager.rooms[r]:
                    pass  # room cleanup handled by room_manager

            if self.hub.identity is not None:
                self._emit_error(
                    outgoing,
                    target_link,
                    src=self.hub.identity.hash,
                    text=f"kicked from {r}",
                    room=r,
                )
            self.hub.message_helper.emit_notice(outgoing, link, room, f"kicked {target} from {r}")
            return True

        if cmd == "kline":
            if not self.hub.trust_manager.is_server_op(peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=None,
                    )
                return True

            # Hub-level command - all responses without room field
            if len(parts) < 2:
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /kline add|del|list [nick|hashprefix|hash]",
                )
                return True

            op = parts[1].strip().lower()
            if op == "list":
                with self.hub._state_lock:
                    items = sorted(h.hex() for h in self.hub.trust_manager._banned)
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "klines: " + (", ".join(items) if items else "(none)"),
                )
                return True

            if op not in ("add", "del"):
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /kline add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing, link, None, f"usage: /kline {op} <nick|hashprefix|hash>"
                )
                return True

            target = parts[2]
            if op == "add":
                target_link = self._find_target_link(target)
                if target_link is not None:
                    tsess = self.hub.session_manager.sessions.get(target_link)
                    ph = tsess.get("peer") if tsess else None
                    if isinstance(ph, (bytes, bytearray)):
                        self.hub.trust_manager.add_ban(bytes(ph))
                        self.hub.trust_manager.persist_banned_identities_to_config(link, None, outgoing)
                    try:
                        target_link.teardown()
                    except Exception:
                        pass
                    self.hub.message_helper.emit_notice(outgoing, link, None, f"kline added for {target}")
                    return True

                # Not found as active link - check if ambiguous or try as raw hash
                all_matches = self._find_target_links(target, room=None)
                if all_matches:
                    # Ambiguous
                    self.hub.message_helper.emit_notice(
                        outgoing, link, None, self._format_ambiguous_targets(target, all_matches)
                    )
                    return True

                # Try as raw hash
                try:
                    h = self.hub._parse_identity_hash(target)
                except Exception as e:
                    self.hub.message_helper.emit_notice(outgoing, link, None, f"bad identity hash: {e}")
                    return True
                self.hub.trust_manager.add_ban(h)
                self.hub.trust_manager.persist_banned_identities_to_config(link, None, outgoing)
                self.hub.message_helper.emit_notice(outgoing, link, None, f"kline added for {h.hex()}")
                return True

            # op == "del"
            try:
                h = self.hub._parse_identity_hash(target)
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad identity hash: {e}")
                return True

            if self.hub.trust_manager.is_banned(h):
                self.hub.trust_manager.remove_ban(h)
                self.hub.trust_manager.persist_banned_identities_to_config(link, None, outgoing)
                self.hub.message_helper.emit_notice(outgoing, link, None, f"kline removed for {h.hex()}")
            else:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"not klined: {h.hex()}")
            return True

        # Room-scoped moderation and maintenance
        if cmd == "register":
            if len(parts) < 2:
                self.hub.message_helper.emit_notice(outgoing, link, None, "usage: /register <room>")
                return True
            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            # Registration rules: requester must be in the room and must be the founder.
            # (No server-op override by design.)
            if (
                not room
                or self.hub._norm_room(room) != r
                or r not in self.hub.session_manager.sessions.get(link, {}).get("rooms", set())
            ):
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, "must be present in the room to register it"
                )
                return True

            st = self.hub.room_manager._room_state_ensure(r)

            # Clean up expired invites (best-effort).
            if self.hub.room_manager.prune_expired_invites(r) and bool(st.get("registered")):
                self.hub.room_manager.persist_room_state(link, r)
            founder = st.get("founder")
            if not (
                isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash
            ):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="only the room founder can register",
                        room=r,
                    )
                return True

            if not self.hub.room_manager.get_registry_path_for_writes():
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, "cannot register room: no room_registry_path"
                )
                return True
            st["registered"] = True
            # Default modes for registered rooms: +nrt
            st["no_outside_msgs"] = True
            st["topic_ops_only"] = True
            if isinstance(founder, (bytes, bytearray)):
                st.setdefault("ops", set()).add(bytes(founder))
            self.hub.room_manager.touch_room(r)

            # Ensure registry mirrors registered rooms.
            self.hub.room_manager._room_registry[r] = {
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

            self.hub.room_manager.persist_room_state(link, r)
            self.hub.message_helper.emit_notice(outgoing, link, room, f"registered room {r}")
            return True

        if cmd == "unregister":
            if len(parts) < 2:
                self.hub.message_helper.emit_notice(outgoing, link, None, "usage: /unregister <room>")
                return True
            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            if (
                not room
                or self.hub._norm_room(room) != r
                or r not in self.hub.session_manager.sessions.get(link, {}).get("rooms", set())
            ):
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, "must be present in the room to unregister it"
                )
                return True

            st = self.hub.room_manager._room_state_ensure(r)
            founder = st.get("founder")
            if not (
                isinstance(founder, (bytes, bytearray)) and bytes(founder) == peer_hash
            ):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="only the room founder can unregister",
                        room=r,
                    )
                return True

            if not st.get("registered"):
                self.hub.message_helper.emit_notice(outgoing, link, room, f"room {r} is not registered")
                return True

            st["registered"] = False
            self.hub.room_manager._room_registry.pop(r, None)
            self.hub._delete_room_from_registry(link, r)
            # Drop state if empty.
            if not self.hub.room_manager.get_room_members(r) or not self.hub.room_manager.get_room_members(r):
                self.hub.room_manager._room_state.pop(r, None)
            self.hub.message_helper.emit_notice(outgoing, link, room, f"unregistered room {r}")
            return True

        if cmd == "topic":
            if len(parts) < 2:
                self.hub.message_helper.emit_notice(outgoing, link, None, "usage: /topic <room> [topic]")
                return True
            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            st = self.hub.room_manager._room_state_ensure(r)
            if len(parts) == 2:
                topic = st.get("topic")
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    room,
                    f"topic for {r}: {topic if topic else '(none)'}",
                )
                return True

            if not self.hub.room_manager.is_room_op(r, peer_hash):
                st = self.hub.room_manager._room_state_ensure(r)
                if bool(st.get("topic_ops_only", False)):
                    if self.hub.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.hub.identity.hash,
                            text="not authorized (+t)",
                            room=r,
                        )
                    return True

            topic = " ".join(parts[2:]).strip()
            st["topic"] = topic if topic else None
            self.hub.room_manager.touch_room(r)
            self.hub.room_manager.persist_room_state(link, r)
            # Broadcast topic change to current members.
            for other in list(self.hub.room_manager.get_room_members(r)):
                self.hub.message_helper.emit_notice(
                    outgoing,
                    other,
                    r,
                    f"topic for {r} is now: {topic if topic else '(cleared)'}",
                )
            return True

        if cmd in ("op", "deop", "voice", "devoice"):
            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing, link, None, f"usage: /{cmd} <room> <nick|hashprefix|hash>"
                )
                return True
            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            if not self.hub.room_manager.is_room_op(r, peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True
            
            target_hash, all_matches = self.hub._resolve_identity_hash_with_matches(parts[2], room=r)
            if target_hash is None:
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[2], all_matches)
                )
                return True
            
            st = self.hub.room_manager._room_state_ensure(r)
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
                    self.hub.room_manager.touch_room(r)
                    self.hub.room_manager.persist_room_state(link, r)
                    self.hub.message_helper.emit_notice(outgoing, link, room, f"op granted in {r}")
                    return True
                else:
                    if founder_b is not None and target_hash == founder_b:
                        self.hub.message_helper.emit_notice(outgoing, link, room, "cannot deop founder")
                        return True
                    ops.discard(target_hash)
                    self.hub.room_manager.touch_room(r)
                    self.hub.room_manager.persist_room_state(link, r)
                    self.hub.message_helper.emit_notice(outgoing, link, room, f"op removed in {r}")
                    return True

            voiced = st.setdefault("voiced", set())
            if not isinstance(voiced, set):
                voiced = set()
                st["voiced"] = voiced
            if cmd == "voice":
                voiced.add(target_hash)
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.message_helper.emit_notice(outgoing, link, room, f"voice granted in {r}")
                return True
            else:
                voiced.discard(target_hash)
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.message_helper.emit_notice(outgoing, link, room, f"voice removed in {r}")
                return True

        if cmd == "mode":
            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /mode <room> (+m|-m|+i|-i|+t|-t|+n|-n|+p|-p|+k|-k|+r|-r) [key] | /mode <room> (+o|-o|+v|-v) <nick|hashprefix|hash>",
                )
                return True
            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True
            if not self.hub.room_manager.is_room_op(r, peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True
            flag = parts[2].strip().lower()
            st = self.hub.room_manager._room_state_ensure(r)

            if flag in ("+m", "-m"):
                st["moderated"] = flag == "+m"
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+i", "-i"):
                st["invite_only"] = flag == "+i"
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+t", "-t"):
                st["topic_ops_only"] = flag == "+t"
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+n", "-n"):
                st["no_outside_msgs"] = flag == "+n"
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+p", "-p"):
                st["private"] = flag == "+p"
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+k", "-k"):
                if flag == "+k":
                    if len(parts) < 4:
                        self.hub.message_helper.emit_notice(
                            outgoing, link, room, "usage: /mode <room> +k <key>"
                        )
                        return True
                    key = " ".join(parts[3:]).strip()
                    if not key:
                        self.hub.message_helper.emit_notice(outgoing, link, room, "key must not be empty")
                        return True
                    st["key"] = key
                else:
                    st["key"] = None
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                self.hub.room_manager.broadcast_room_mode(r, outgoing)
                return True

            if flag in ("+r", "-r"):
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, "use /register or /unregister to change +r"
                )
                return True

            if flag in ("+o", "-o", "+v", "-v"):
                if len(parts) < 4:
                    self.hub.message_helper.emit_notice(
                        outgoing,
                        link,
                        room,
                        "usage: /mode <room> (+o|-o|+v|-v) <nick|hashprefix|hash>",
                    )
                    return True

                target_hash, all_matches = self.hub._resolve_identity_hash_with_matches(parts[3], room=r)
                if target_hash is None:
                    self.hub.message_helper.emit_notice(
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
                            self.hub.message_helper.emit_notice(
                                outgoing, link, room, "cannot deop founder"
                            )
                            return True
                        ops.discard(target_hash)

                    self.hub.room_manager.touch_room(r)
                    self.hub.room_manager.persist_room_state(link, r)
                    for other in list(self.hub.room_manager.get_room_members(r)):
                        self.hub.message_helper.emit_notice(
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

                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)
                for other in list(self.hub.room_manager.get_room_members(r)):
                    self.hub.message_helper.emit_notice(
                        outgoing,
                        other,
                        r,
                        f"mode for {r} is now: {flag} {target_hash.hex()[:12]}",
                    )
                return True

            self.hub.message_helper.emit_notice(
                outgoing,
                link,
                room,
                "supported modes: +m -m +i -i +k -k +t -t +n -n +p -p +r -r +o -o +v -v",
            )
            return True

        if cmd == "ban":
            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /ban <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            op = parts[2].strip().lower()
            if op == "list":
                st = self.hub.room_manager._room_state_ensure(r)
                bans = st.get("bans")
                if not isinstance(bans, set) or not bans:
                    self.hub.message_helper.emit_notice(outgoing, link, room, f"no bans in {r}")
                    return True
                items = sorted(
                    bytes(x).hex() for x in bans if isinstance(x, (bytes, bytearray))
                )
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, f"bans in {r}: " + ", ".join(items)
                )
                return True

            if op not in ("add", "del"):
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    room,
                    "usage: /ban <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 4:
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, f"usage: /ban {r} {op} <nick|hashprefix|hash>"
                )
                return True

            if not self.hub.room_manager.is_room_op(r, peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            target_hash, all_matches = self.hub._resolve_identity_hash_with_matches(parts[3], room=r)
            if target_hash is None:
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[3], all_matches)
                )
                return True

            st = self.hub.room_manager._room_state_ensure(r)
            bans = st.setdefault("bans", set())
            if not isinstance(bans, set):
                bans = set()
                st["bans"] = bans

            if op == "add":
                bans.add(target_hash)
                self.hub.room_manager.touch_room(r)
                self.hub.room_manager.persist_room_state(link, r)

                # If currently present in room, remove them.
                for other in list(self.hub.room_manager.get_room_members(r)):
                    s = self.hub.session_manager.sessions.get(other)
                    ph = s.get("peer") if s else None
                    if isinstance(ph, (bytes, bytearray)) and bytes(ph) == target_hash:
                        s.get("rooms", set()).discard(r)
                        self.hub.room_manager.get_room_members(r).discard(other)
                        if self.hub.identity is not None:
                            self._emit_error(
                                outgoing,
                                other,
                                src=self.hub.identity.hash,
                                text=f"banned from {r}",
                                room=r,
                            )
                if self.hub.room_manager.get_room_members(r) and not self.hub.room_manager.rooms[r]:
                    pass  # room cleanup handled by room_manager
                self.hub.message_helper.emit_notice(outgoing, link, room, f"ban added in {r}")
                return True

            bans.discard(target_hash)
            self.hub.room_manager.touch_room(r)
            self.hub.room_manager.persist_room_state(link, r)
            self.hub.message_helper.emit_notice(outgoing, link, room, f"ban removed in {r}")
            return True

        if cmd == "invite":
            if len(parts) < 3:
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    None,
                    "usage: /invite <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            try:
                r = self.hub._norm_room(parts[1])
            except Exception as e:
                self.hub.message_helper.emit_notice(outgoing, link, None, f"bad room: {e}")
                return True

            if not self.hub.room_manager.is_room_op(r, peer_hash):
                if self.hub.identity is not None:
                    self._emit_error(
                        outgoing,
                        link,
                        src=self.hub.identity.hash,
                        text="not authorized",
                        room=r,
                    )
                return True

            op = parts[2].strip().lower()
            st = self.hub.room_manager._room_state_ensure(r)

            invited = st.setdefault("invited", {})
            if not isinstance(invited, dict):
                invited = {}
                st["invited"] = invited

            # Drop expired entries before operating.
            pruned = self.hub.room_manager.prune_expired_invites(r)

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
                    self.hub.room_manager.touch_room(r)
                    self.hub.room_manager.persist_room_state(link, r)
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    room,
                    f"invites in {r}: " + (", ".join(items) if items else "(none)"),
                )
                return True

            if op not in ("add", "del"):
                self.hub.message_helper.emit_notice(
                    outgoing,
                    link,
                    room,
                    "usage: /invite <room> add|del|list [nick|hashprefix|hash]",
                )
                return True

            if len(parts) < 4:
                self.hub.message_helper.emit_notice(
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
                    if self.hub.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.hub.identity.hash,
                            text=f"invite failed: {self._format_ambiguous_targets(token, all_matches)}",
                            room=r,
                        )
                    return True

                tsess = self.hub.session_manager.sessions.get(target_link)
                ph = tsess.get("peer") if tsess else None
                if not isinstance(ph, (bytes, bytearray)):
                    if self.hub.identity is not None:
                        self._emit_error(
                            outgoing,
                            link,
                            src=self.hub.identity.hash,
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
                    self.hub.message_helper.emit_notice(
                        outgoing,
                        target_link,
                        r,
                        f"You have been invited to join {r}. This invite allows joining without the key (+k).",
                    )
                else:
                    self.hub.message_helper.emit_notice(
                        outgoing, target_link, r, f"You have been invited to join {r}."
                    )

                # Persist an expiring invite only when it has semantics: +k bypass and/or +i allow.
                if is_keyed or is_invite_only:
                    ttl = (
                        float(self.hub.config.room_invite_timeout_s)
                        if self.hub.config.room_invite_timeout_s
                        else 0.0
                    )
                    if ttl <= 0:
                        ttl = 900.0
                    exp = float(time.time()) + ttl
                    invited[target_hash] = exp
                    self.hub.room_manager.touch_room(r)
                    self.hub.room_manager.persist_room_state(link, r)
                    self.hub.message_helper.emit_notice(
                        outgoing,
                        link,
                        room,
                        f"invite added in {r} (expires in {int(ttl)}s)",
                    )
                else:
                    self.hub.message_helper.emit_notice(
                        outgoing, link, room, f"invite sent to {token} for {r}"
                    )
                return True

            target_hash, all_matches = self.hub._resolve_identity_hash_with_matches(parts[3], room=None)
            if target_hash is None:
                self.hub.message_helper.emit_notice(
                    outgoing, link, room, self._format_ambiguous_targets(parts[3], all_matches)
                )
                return True

            if target_hash in invited:
                invited.pop(target_hash, None)
            self.hub.room_manager.touch_room(r)
            self.hub.room_manager.persist_room_state(link, r)
            self.hub.message_helper.emit_notice(outgoing, link, room, f"invite removed in {r}")
            return True

        return False

    # Helper methods
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
                with self.hub._state_lock:
                    # Search hash index for matching prefixes
                    matches: list[RNS.Link] = []
                    for peer_hash, candidate_link in self.hub.session_manager._index_by_hash.items():
                        if peer_hash.startswith(prefix):
                            # Check room membership if specified
                            if room is not None:
                                sess = self.hub.session_manager.sessions.get(candidate_link)
                                if sess and room not in sess.get("rooms", set()):
                                    continue
                            matches.append(candidate_link)
                
                return matches

        # Otherwise treat as nickname - use nick index for O(1) lookup
        with self.hub._state_lock:
            candidate_links = self.hub.session_manager._index_by_nick.get(t, set())
            if not candidate_links:
                return []
            
            # Filter by room membership if specified
            if room is not None:
                matches = []
                for candidate_link in candidate_links:
                    sess = self.hub.session_manager.sessions.get(candidate_link)
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
        
        with self.hub._state_lock:
            items = []
            for match_link in matches:
                sess = self.hub.session_manager.sessions.get(match_link)
                if not sess:
                    continue
                peer = sess.get("peer")
                nick = sess.get("nick")
                hash_str = self.hub._fmt_hash(peer, prefix=16) if peer else "?"
                nick_str = f"nick={nick!r}" if nick else "(no nick)"
                items.append(f"{hash_str} {nick_str}")
        
        if len(items) == 0:
            return f"target '{token}' not found"
        
        return (
            f"ambiguous: '{token}' matches {len(items)} identities:\n"
            + "\n".join(f"  - {item}" for item in items)
            + "\nUse full or longer identity hash to disambiguate."
        )

    def _emit_notice(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        room: str | None,
        text: str,
    ) -> None:
        if self.hub.identity is None:
            return
        env = make_envelope(T_NOTICE, src=self.hub.identity.hash, room=room, body=text)
        if outgoing is None:
            self.hub._send(link, env)
        else:
            self.hub._queue_env(outgoing, link, env)

    def _emit_error(
        self,
        outgoing: list[tuple[RNS.Link, bytes]] | None,
        link: RNS.Link,
        *,
        src: bytes,
        text: str,
        room: str | None = None,
    ) -> None:
        self.hub.stats_manager.inc("errors_sent")
        env = make_envelope(T_ERROR, src=src, room=room, body=text)
        if outgoing is None:
            self.hub._send(link, env)
        else:
            self.hub._queue_env(outgoing, link, env)
