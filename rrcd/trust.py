"""Trust and ban management for the RRC hub."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import RNS
    from .service import HubService


class TrustManager:
    """
    Manages trusted and banned identities for the hub.
    
    Handles:
    - Trusted identity lists (server operators)
    - Banned identity lists
    - Persistence of ban list to config
    - Trust/ban checks
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = hub.log
        
        self._trusted: set[bytes] = set()
        self._banned: set[bytes] = set()

    def load_from_config(self, trusted_list: list[str] | None, banned_list: list[str] | None) -> None:
        """Load trusted and banned identities from config lists."""
        self._trusted = {
            self.hub._parse_identity_hash(h)
            for h in (trusted_list or ())
            if str(h).strip()
        }
        self._banned = {
            self.hub._parse_identity_hash(h)
            for h in (banned_list or ())
            if str(h).strip()
        }

    def is_trusted(self, peer_hash: bytes | None) -> bool:
        """Check if a peer identity is in the trusted list."""
        if not peer_hash:
            return False
        with self.hub._state_lock:
            return peer_hash in self._trusted

    def is_server_op(self, peer_hash: bytes | None) -> bool:
        """Check if a peer is a server operator (currently same as trusted)."""
        return self.is_trusted(peer_hash)

    def is_banned(self, peer_hash: bytes | None) -> bool:
        """Check if a peer identity is in the banned list."""
        if not peer_hash:
            return False
        with self.hub._state_lock:
            return peer_hash in self._banned

    def add_ban(self, peer_hash: bytes) -> None:
        """Add a peer identity to the banned list."""
        with self.hub._state_lock:
            self._banned.add(peer_hash)

    def remove_ban(self, peer_hash: bytes) -> None:
        """Remove a peer identity from the banned list."""
        with self.hub._state_lock:
            self._banned.discard(peer_hash)

    def get_stats(self) -> dict[str, int]:
        """Get statistics about trusted and banned identities."""
        with self.hub._state_lock:
            return {
                "trusted_count": len(self._trusted),
                "banned_count": len(self._banned),
            }

    def update_from_config(self, trusted_list: list[str] | None, banned_list: list[str] | None) -> tuple[set[bytes], set[bytes]]:
        """
        Update trusted and banned lists from config.
        Returns the old (trusted, banned) sets for comparison.
        """
        with self.hub._state_lock:
            old_trusted = set(self._trusted)
            old_banned = set(self._banned)

        new_trusted = {
            self.hub._parse_identity_hash(h)
            for h in (trusted_list or ())
            if str(h).strip()
        }
        new_banned = {
            self.hub._parse_identity_hash(h)
            for h in (banned_list or ())
            if str(h).strip()
        }

        with self.hub._state_lock:
            self._trusted = new_trusted
            self._banned = new_banned

        return old_trusted, old_banned

    def persist_banned_identities_to_config(
        self,
        link: RNS.Link,
        room: str | None,
        outgoing: list[tuple[RNS.Link, bytes]] | None = None,
    ) -> None:
        """Persist the current banned identities list to the config file."""
        cfg_path = self.hub.config_manager.get_config_path_for_writes()
        if not cfg_path:
            self.hub._emit_notice(
                outgoing, link, room, "ban updated (not persisted; no config_path)"
            )
            return

        try:
            from tomlkit import dumps, parse, table  # type: ignore
        except Exception:
            self.hub._emit_notice(
                outgoing,
                link,
                room,
                "ban updated (not persisted; missing dependency tomlkit)",
            )
            return

        try:
            with self.hub.config_manager.get_write_lock():
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

                with self.hub._state_lock:
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
            self.hub._emit_notice(
                outgoing, link, room, f"ban updated (persist failed: {e})"
            )
