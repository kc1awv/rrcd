# Changelog

This project follows the versioning policy in VERSIONING.md.

## 0.1.0 - 2025-12-29

Initial public release.

- Standalone Reticulum Relay Chat daemon (hub service)
- RRC v1 envelope + CBOR wire encoding
- Core hub features: HELLO/WELCOME gating, JOIN/PART, MSG/NOTICE forwarding, PING/PONG
- Operator and moderation commands via slash-command convention in MSG/NOTICE bodies
- Persistent config + room registry in TOML (`rrcd.toml`, `rooms.toml`)
- Reduced lock contention by flushing outbound packets outside the shared state lock
- Added small packaging metadata and README polish

## 0.1.1 - 2025-12-30

- Protocol extension: hub may attach an optional nickname (`K_NICK = 7`) to forwarded `MSG`/`NOTICE` envelopes based on the nickname provided in `HELLO`.
