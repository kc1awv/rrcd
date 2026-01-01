# Changelog

This project follows the versioning policy in VERSIONING.md.

## 0.1.2 - 2026-01-01

- Implemented RNS.Resource transfer for messages exceeding MTU limits, with resource envelope handling and automatic fallback
- Allow hub-directed commands (e.g., `/stats`, `/reload`, `/who`, `/kline`) to be sent without a room field
- Removed validation that rejected empty room fields in envelopes, per RRC specification
- Hub-level commands now send responses with no room field (`room=None`) for better client compatibility
- Refactored greeting messages to use dedicated MOTD resource kind for clearer semantics
- Added missing configuration options to default config template


## 0.1.1 - 2025-12-30

- Protocol extension: hub may attach an optional nickname (`K_NICK = 7`) to forwarded `MSG`/`NOTICE` envelopes for improved user identification


## 0.1.0 - 2025-12-29

Initial public release.

- Standalone Reticulum Relay Chat daemon (hub service)
- RRC v1 envelope + CBOR wire encoding
- Core hub features: HELLO/WELCOME gating, JOIN/PART, MSG/NOTICE forwarding, PING/PONG
- Operator and moderation commands via slash-command convention in MSG/NOTICE bodies
- Persistent config + room registry in TOML (`rrcd.toml`, `rooms.toml`)
- Reduced lock contention by flushing outbound packets outside the shared state lock
- Added small packaging metadata and README polish
