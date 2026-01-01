# rrcd

`rrcd` is a standalone RRC hub daemon (server) built on Reticulum (RNS).

- License: MIT (see LICENSE)
- Changelog: CHANGELOG.md
- Versioning policy: VERSIONING.md

## Install (dev)

From the `rrcd/` directory:

To install from source (non-editable):

- `python -m pip install .`

- `python -m pip install -e .`

For contributors (lint + tests):

- `python -m pip install -e ".[dev]"`
- `ruff check .`
- `pytest -q`

## Run

To run a basic RRC hub with default settings:
- `rrcd`

You can also run it as a module:
- `python -m rrcd`

First run will create a default config file at `~/.rrcd/rrcd.toml` and
a default identity at `~/.rrcd/hub_identity`, plus a room registry at
`~/.rrcd/rooms.toml`. You should read and edit the config before starting again.

To override the default state directory (`~/.rrcd/`), set `RRCD_HOME`, e.g.
`RRCD_HOME=/tmp/rrcd rrcd`.
  
To specify a custom identity and destination name:
- `rrcd --identity ~/.rrcd/hub_identity --dest-name rrc.hub`

Optional:

- `rrcd --config rrcd.toml`

You need a working Reticulum configuration (see Reticulum docs).

## Logging

By default, `rrcd` logs to stderr (good for systemd/journald). You can configure
logging in `~/.rrcd/rrcd.toml`:

```toml
[logging]
level = "INFO"         # set to DEBUG for connection/packet tracing
rns_level = "WARNING"  # python-logging level for the "RNS" logger (if used)
console = true
file = ""              # e.g. "~/.rrcd/rrcd.log" (empty disables)
format = "%(asctime)s %(levelname)s %(name)s[%(threadName)s]: %(message)s"
datefmt = ""
```

CLI overrides are also available:

- `rrcd --log-level DEBUG`
- `rrcd --log-file ~/.rrcd/rrcd.log`

If you use `/reload`, logging settings are applied immediately.

### Troubleshooting: connect times out after HELLO

If a client connects, sends `HELLO`, and then times out waiting for `WELCOME`,
check the hub logs for an error like:

- `Packet size of ... exceeds MTU of ... bytes`

This usually means the hub tried to send a `WELCOME` (or other message) that is
too large for the current Reticulum link MTU.

Mitigations:

- `WELCOME` sent by `rrcd` is intentionally minimal (hub name/version/caps).
- The hub `greeting` is delivered after `WELCOME` via one or more `NOTICE`
    messages chunked to fit the link MTU.

## Compatibility

`rrcd` implements the core RRC protocol as described in the RRC docs.

Protocol alignment notes (for implementers):

- `HELLO` and `WELCOME` bodies are CBOR maps with unsigned integer keys.
- Capabilities are carried in body key `2` as a CBOR map (not a bitmask). Keys
    inside the capabilities map are unsigned integers; values are advisory.
- `WELCOME` is intentionally minimal (hub name/version/caps only). Any hub
    greeting text is delivered after `WELCOME` via one or more `NOTICE` messages.

Extensions beyond core RRC will be documented in the Extensions section of this
README as they are added.

In addition to the core protocol, `rrcd` includes operator-facing and
policy-level features that are allowed by the spec:

- **First-run bootstrap**: if the default config and identity are missing,
	`rrcd` will create them and exit with a note asking you to edit the config
	before starting again.
- **Rate limiting**: per-link message rate limiting may reject messages with
	`ERROR`.
- **Room and input limits**: limits such as maximum rooms per session and
	maximum room name length.
- **Optional `JOINED` member list**: can include a best-effort list of members.
- **Optional hub-initiated `PING`**: can periodically ping clients and
	optionally close links that do not respond in time.

## Extensions

### Suggested reading: EX1-RRCD.md

`rrcd` intentionally avoids adding new on-wire message types. Operator features
use a hub-local convention: if a client sends a `MSG`/`NOTICE` whose body is a
string beginning with `/`, and the command is recognized, the hub treats it as a
command and does not forward it.

Wire-level extensions (backwards-compatible):

- **Optional envelope nickname**: the hub may include an additional envelope key
    `K_NICK = 7` (string) when forwarding `MSG`/`NOTICE`. This is an optional
    hint associated with `K_SRC` so clients can display a human-friendly
    nickname instead of only the sender identity hash.

    The hub learns this value from the client's optional envelope nickname field
    `K_NICK = 7` on inbound messages, and treats it as the authoritative nickname
    for that link. Clients should treat `K_NICK` as optional and fall back to
    `K_SRC` when it is missing.

    Nicknames are advisory only; clients should treat them as display hints.
    The hub may ignore, sanitize, replace, or omit them.

    Current hub sanitation policy: store/emit only trimmed nicknames that are
    UTF-8 encodable, contain no newlines/NUL, and are at most `nick_max_chars`
    characters (default: 32).

- **Large payload transfer via RNS.Resource**: For messages that exceed the link
    MTU (Maximum Data Unit), `rrcd` can automatically use RNS.Resource for
    reliable large payload transfer instead of manual chunking.

    This is implemented as a two-part protocol:
    1. Send a small `RESOURCE_ENVELOPE` message (type 50) via normal packet,
       announcing the incoming resource with metadata (id, kind, size, SHA256).
    2. Send the actual payload via `RNS.Resource`.

    The receiving side matches the resource to the expectation and validates
    integrity. Supported resource kinds include:
    - `notice`: Large NOTICE text messages
    - `motd`: Message of the day / server greeting
    - `blob`: Generic binary data

    Configuration (in `rrcd.toml`):
    ```toml
    [hub]
    enable_resource_transfer = true       # default: true
    max_resource_bytes = 262144           # 256 KiB default
    max_pending_resource_expectations = 8  # per link
    resource_expectation_ttl_s = 30.0     # expectation timeout
    ```

    Safety controls:
    - Resources are only accepted if they match a recent expectation
    - Size limits enforced (default 256 KiB)
    - SHA256 verification for integrity
    - TTL-based expectation expiry (default 30 seconds)
    - Per-link expectation limit to prevent memory exhaustion

    Fallback: If resource transfer is disabled or fails, NOTICE messages fall
    back to the original line-based chunking method.

Configure trusted operators and banned identities in the TOML config:

- `trusted_identities`: list of Reticulum Identity hashes (hex) allowed to run
    commands
- `banned_identities`: list of Identity hashes (hex) that are disconnected on
    identify

Implemented commands (best-effort):

Server operator commands (require identity in `trusted_identities`):

- `/stats` — show hub stats (uptime, clients, rooms, counters)
- `/reload` — reload `rrcd.toml` and `rooms.toml` from disk
- `/who [room]` — list members (nick and/or hash prefix)
- `/kline add <nick|hashprefix|hash>` — add a server-global ban (persists to
    `banned_identities`)
- `/kline del <hash>` — remove a server-global ban (persists to
    `banned_identities`)
- `/kline list` — list global bans

Room moderation commands (room founder/ops; some actions may also work for
server operators):

- `/kick <room> <nick|hashprefix>` — remove a client from a room
- `/register <room>` — persist room settings to `rooms.toml` (founder only; must
    be in the room)
- `/unregister <room>` — remove room settings from `rooms.toml` (founder only;
    must be in the room)
- `/topic <room> [topic]` — show or set a room topic
- `/mode <room> (+m|-m)` — set moderated mode
- `/mode <room> (+i|-i)` — set invite-only mode
- `/mode <room> (+k|-k) [key]` — set/clear room key (password)
- `/mode <room> (+t|-t)` — set topic-ops-only (only ops can change topic)
- `/mode <room> (+n|-n)` — set no-outside-messages
- `/mode <room> (+r|-r)` — read-only; use /register or /unregister
- `/mode <room> (+o|-o|+v|-v) <nick|hashprefix|hash>` — IRC-style user modes
    (alias for op/voice)
- `/op <room> <nick|hashprefix|hash>` / `/deop ...` — grant/revoke room operator
- `/voice <room> <nick|hashprefix|hash>` / `/devoice ...` — grant/revoke voice
    (for moderated rooms)
- `/ban <room> add <nick|hashprefix|hash>` — add a room-local ban
- `/ban <room> del <nick|hashprefix|hash>` — remove a room-local ban
- `/ban <room> list` — list room-local bans
- `/invite <room> add <nick|hashprefix|hash>` — send a room invite (as a
    `NOTICE` to the target)
- `/invite <room> del <nick|hashprefix|hash>` — remove a room-local invite
- `/invite <room> list` — list room-local invites

Notes:

- On successful JOIN, the hub sends a follow-up `NOTICE` to the joining client
	with room info (registered/unregistered, mode flags, and topic).
- When a room is registered, default mode flags are `+nrt`.
- `/invite` always sends the target a `NOTICE` (and fails if the target is not
    currently connected).
- If the room has join restrictions, the hub also records an expiring invite so
    the target can actually use it to join:
    - `+i` (invite-only): only an invite allows a user to JOIN.
    - `+k` (keyed): an invite allows a user to JOIN without knowing the key. The
        key can then be disseminated in-band (in room) if desired.

    These stored invites are consumed on successful JOIN or discarded when they
    expire. Configure the expiry with `room_invite_timeout_s` in `rrcd.toml`.
- Registered-but-empty rooms may be pruned after a period of inactivity.
	Configure `room_registry_prune_after_s` and `room_registry_prune_interval_s`
	in `rrcd.toml`.

## rooms.toml format

The room registry file (`~/.rrcd/rooms.toml` by default) is a TOML document with
a top-level `[rooms]` table. Each registered room is stored under a per-room
table.

Example:

- `[rooms."lobby"]`

Supported keys per room:

- `founder`: hex Reticulum Identity hash (string)
- `topic`: room topic (string, optional)
- `moderated`: whether the room is in +m (bool)
- `invite_only`: whether the room is in +i (bool)
- `topic_ops_only`: whether the room is in +t (bool)
- `no_outside_msgs`: whether the room is in +n (bool)
- `key`: room key/password for +k (string, optional)
- `operators`: list of identity hashes (strings)
- `voiced`: list of identity hashes (strings)
- `bans`: list of identity hashes (strings)
- `invited`: table mapping identity hash (hex string) -> expiry unix timestamp
    seconds (float)
- `last_used_ts`: unix timestamp seconds (float; used for pruning)

Note: room names are TOML keys. Quote room names that contain spaces or other
non-identifier characters, e.g. `[rooms."my room"]`.

## Security and threat model

This section describes what `rrcd` is designed to protect against, what it is
*not* designed to protect against, and the assumptions you should keep in mind
when deploying it.

Assumptions:

- Reticulum link establishment and remote identity are authoritative for who a
    peer “is” (the hub uses the Link’s remote identity hash as the peer
    identity).
- The host running `rrcd` is trusted by the operator (if the host is
    compromised, the hub and its policy controls are compromised).

What `rrcd` aims to protect against:

- **Unauthenticated pre-handshake traffic**: inbound packets are ignored until
    the Link’s remote identity is available.
- **Protocol misuse**: clients must `HELLO` before they can perform other
    actions (WELCOME gating).
- **Accidental resource exhaustion**: basic per-link rate limiting and input
    limits (rooms per session, room name length).
- **Basic abuse controls**: operator identities, global bans (`/kline`), and
    per-room bans/modes.

What `rrcd` does *not* protect against (non-goals):

- **Denial of service by a determined attacker**: rate limiting is best-effort
    and does not prevent all forms of DoS.
- **A malicious or compromised operator**: identities in `trusted_identities`
    can enforce policy; they can also abuse that power.
- **Metadata/privacy leakage outside the hub’s control**: your threat model
    depends on Reticulum’s transport and your network topology.
- **Confidentiality against the hub itself**: the hub can observe and forward
    traffic; do not treat it as a “zero trust” component.

Operational guidance:

- Keep the hub identity file and config directory private (the default storage
    directory is `~/.rrcd/`).
- Treat `trusted_identities` like admin keys.
- Prefer running `rrcd` under a dedicated OS user with locked-down permissions,
    aka “least privilege” principle. TL;DR: don’t run it as root.