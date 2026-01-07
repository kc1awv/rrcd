# Changelog

This project follows the versioning policy in VERSIONING.md.

## 0.2.0 - 2026-01-07

- **Major internal refactoring**: Improved code organization and maintainability
- Extracted modular components from monolithic service class:
  - `SessionManager`: Centralized session lifecycle and state management
  - `MessageRouter`: Message routing and forwarding logic
  - `CommandHandler`: Slash-command parsing and execution
  - `RoomManager`: Room state, membership, and mode management
  - `ResourceManager`: RNS.Resource transfer handling and coordination
  - `TrustManager`: Operator and ban list management
  - `StatsManager`: Statistics tracking and reporting
  - `ConfigManager`: Enhanced configuration loading and validation
- Moved message chunking and encoding logic to dedicated `messages` module
- Consolidated constants and improved code organization
- Reduced service.py from ~4000 lines to <600 lines by delegating to specialized managers
- No breaking changes to protocol, configuration format, or user-facing behavior

Future development will focus on testing, feature enhancements, and optimizations rather than large structural changes.

## 0.1.3 - 2026-01-05

- Added `/list` command to discover registered public rooms with their topics (available to all users)
- Added `+p` (private) channel mode to hide rooms from `/list` and `/who` commands
- Private rooms are only visible in `/who` to server operators
- Updated mode handling to support `+p`/`-p` flags and persist private status to room registry
- Consolidated version number to single source in `rrcd/__init__.py` (pyproject.toml now reads it dynamically)
- Documentation updates for new command and mode in README.md and EX1-RRCD.md

### Minor fixes

- Fix potential deadlock in _resource_advertised
- Add resource timeout cleanup
- Improve notice as resource handling and probe for link MDU with fallback
- Improve nickname updates, O(1) lookups, nick tracking, disambiguation on multiple matches


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
