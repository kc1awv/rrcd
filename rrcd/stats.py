"""Statistics tracking and reporting for the RRC hub."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .service import HubService


class StatsManager:
    """
    Manages hub statistics collection and reporting.

    Tracks counters for:
    - Bytes in/out
    - Packets processed
    - Rate limiting events
    - Errors sent
    - Room joins/parts
    - Messages forwarded
    - Ping/pong activity
    - Announces
    - Resource transfers
    """

    def __init__(self, hub: HubService) -> None:
        self.hub = hub
        self.log = hub.log

        self.started_wall_time: float | None = None
        self.started_monotonic: float | None = None

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

    def set_start_time(self) -> None:
        """Set the start time for uptime calculations."""
        self.started_wall_time = time.time()
        self.started_monotonic = time.monotonic()

    def inc(self, key: str, delta: int = 1) -> None:
        """Increment a counter by the given delta."""
        try:
            with self.hub._state_lock:
                self._counters[key] = int(self._counters.get(key, 0)) + int(delta)
        except Exception:
            pass

    def format_stats(self) -> str:
        """Format current statistics as a human-readable string."""
        from . import __version__

        now_mono = time.monotonic()
        started_mono = self.started_monotonic
        uptime_s = (now_mono - started_mono) if started_mono is not None else 0.0

        with self.hub._state_lock:
            session_stats = self.hub.session_manager.get_stats()
            sessions_total = session_stats["total"]
            sessions_welcomed = session_stats["welcomed"]
            sessions_identified = session_stats["identified"]

            room_stats = self.hub.room_manager.get_stats()
            rooms_total = room_stats["rooms_total"]
            memberships = room_stats["memberships"]
            top_rooms = room_stats["top_rooms"]

            trust_stats = self.hub.trust_manager.get_stats()
            trusted_count = trust_stats["trusted_count"]
            banned_count = trust_stats["banned_count"]
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
            f"limits: rate_limit_msgs_per_minute={self.hub.config.rate_limit_msgs_per_minute} "
            f"max_rooms_per_session={self.hub.config.max_rooms_per_session} "
            f"max_room_name_bytes={self.hub.config.max_room_name_bytes} "
            f"max_nick_bytes={self.hub.config.max_nick_bytes}"
        )
        lines.append(
            f"features: ping_interval_s={self.hub.config.ping_interval_s} "
            f"ping_timeout_s={self.hub.config.ping_timeout_s} "
            f"announce_on_start={self.hub.config.announce_on_start} "
            f"announce_period_s={self.hub.config.announce_period_s}"
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
