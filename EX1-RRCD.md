# EX1-RRCD: rrcd Extensions to the RRC Specification

If you're reading this document, you're probably implementing something that
needs to talk to `rrcd`, or you're building your own hub and want to understand
what liberties we've taken with the core RRC specification. This is that
document.

The RRC specification is intentionally minimal and deliberately vague about
certain implementation details, presumably because the authors enjoy watching
implementers squirm. We don't hate you *quite* that much, so we're documenting
our extensions here.

**Important**: If you're implementing a basic RRC client, you can safely ignore
most of this document. The core protocol works fine. These extensions are
optional capabilities that clients may choose to support (or not).

## Philosophy

rrcd implements the core RRC protocol as specified, with the following
principles:

1. **Wire format compatibility first**: All core message types (`HELLO`,
    `WELCOME`, `JOIN`, `JOINED`, `PART`, `PARTED`, `MSG`, `NOTICE`, `PING`,
    `PONG`, `ERROR`) are implemented per spec.
2. **Envelope keys are unsigned integers**: If you send string keys in your CBOR
    maps, we will reject your messages. The spec says unsigned integers. We mean
    it.
3. **Bodies are CBOR maps with unsigned integer keys**: Not bitmasks, not
    strings, not "whatever feels right". Unsigned. Integer. Keys.
4. **Capabilities are advisory**: When we advertise capabilities, they're hints.
    You're allowed to ignore them if you hate yourself.

## Extension: Resource Transfer (T_RESOURCE_ENVELOPE)

**Message Type**: `50` (`T_RESOURCE_ENVELOPE`)  
**Capability Key**: `0` (`CAP_RESOURCE_ENVELOPE`)  
**Status**: Implemented (optional, configurable)

The RRC specification has no concept of large message delivery beyond "chunk it
yourself, good luck." This is fine for small messages but becomes obnoxious for:

- Large MOTD/greeting text
- Binary blobs (theoretically)
- Anything approaching the link MTU

We added a resource transfer mechanism using Reticulum's built-in `RNS.Resource`
class. This is **entirely optional** - clients that don't support it will simply
not receive messages that exceed MTU. (If you're a client implementer and you
want to receive verbose MOTDs, you'll need to support this.)

### Protocol Flow

1. **Sender sends `T_RESOURCE_ENVELOPE` message**: This is a regular RRC
    envelope (type `50`) containing metadata about the incoming resource.

   **Envelope structure**:
   ```python
   {
       0: 1,              # protocol version (K_V)
       1: 50,             # message type T_RESOURCE_ENVELOPE (K_T)
       2: <8-byte-id>,    # message ID (K_ID)
       3: <timestamp>,    # millisecond timestamp (K_TS)
       4: <sender-hash>,  # sender identity hash (K_SRC)
       5: <room>,         # optional: room name (K_ROOM)
       6: <body>          # body (K_BODY) - see below
   }
   ```

   **Body structure** (unsigned integer keys):
   ```python
   {
       0: <resource-id>,      # B_RES_ID: 8 bytes, unique identifier
       1: <kind>,             # B_RES_KIND: string ("notice", "motd", "blob")
       2: <size>,             # B_RES_SIZE: integer, total bytes
       3: <sha256>,           # B_RES_SHA256: 32 bytes (optional but recommended)
       4: <encoding>          # B_RES_ENCODING: string, e.g. "utf-8" (optional)
   }
   ```

2. **Sender advertises Reticulum Resource**: Immediately after sending the
    envelope, the sender creates an `RNS.Resource` and advertises it over the
    link. The resource ID in the envelope is for correlation only (currently
    unused but reserved for future use).

3. **Receiver accepts or rejects**: The receiver may accept the resource (if it
    recognizes the `kind` and the size is acceptable) or reject it (if resources
    are disabled, size exceeds limits, or no matching expectation exists).

4. **Resource transfer completes**: Reticulum handles the chunked transfer. On
    completion, the receiver verifies the SHA256 hash (if provided) and
    dispatches the payload based on `kind`.

### Resource Kinds

- **`"notice"`**: UTF-8 text delivered as a `NOTICE` message after
   reconstruction. Used for large announcements.
- **`"motd"`**: UTF-8 text delivered as a `NOTICE` message, specifically the
   hub's message-of-the-day. Sent after `WELCOME`.
- **`"blob"`**: Binary data (reserved for future use; currently unused).

**Encoding**: For text-based kinds (`notice`, `motd`), the `B_RES_ENCODING`
field should specify the text encoding (default: `"utf-8"`). For `blob`,
encoding is irrelevant.

### Configuration

Resource transfer is controlled by hub configuration:

```toml
enable_resource_transfer = true      # default: true
max_resource_bytes = 262144          # 256 KiB default
max_pending_resource_expectations = 8
resource_expectation_ttl_s = 30.0
```

Clients: if you don't want to deal with resources, don't advertise
`CAP_RESOURCE_ENVELOPE` in your `HELLO`. The hub will fall back to chunked
`NOTICE` messages (which may be truncated if they exceed MTU).

### Why?

Because the RRC spec doesn't define how to send a 5KB MOTD over a 500-byte MTU
link without making everyone cry. That's why.

## Extension: WELCOME Minimalism + Greeting-via-NOTICE

The RRC specification is vague about what goes in the `WELCOME` body. Some
implementations send the entire hub greeting, user count, room list, kitchen
sink, and a partridge in a pear tree.

We don't do that.

**rrcd's WELCOME body contains**:

- `B_WELCOME_HUB` (key `0`): Hub name (string)
- `B_WELCOME_VER` (key `1`): Hub version (string)
- `B_WELCOME_CAPS` (key `2`): Capabilities map (reserved for future use)
- `B_WELCOME_LIMITS` (key `3`): Hub limits map (see below)

That's it. No greeting, no room list, no user count. Why? Because `WELCOME`
needs to fit in a single packet on low-MTU links. If the hub has a greeting
configured, it's delivered **after** `WELCOME` via one or more `NOTICE` messages
(chunked to fit MTU, or sent via resource transfer if supported).

### Hub Limits Map

The `B_WELCOME_LIMITS` field contains a map with unsigned integer keys that
inform clients about operational limits:

- `B_LIMIT_MAX_NICK_BYTES` (key `0`): Maximum nickname length in bytes
- `B_LIMIT_MAX_ROOM_NAME_BYTES` (key `1`): Maximum room name length in bytes
- `B_LIMIT_MAX_MSG_BODY_BYTES` (key `2`): Maximum message body length in bytes
- `B_LIMIT_MAX_ROOMS_PER_SESSION` (key `3`): Maximum rooms a client can join
- `B_LIMIT_RATE_LIMIT_MSGS_PER_MINUTE` (key `4`): Messages per minute limit

**Important**: These limits are **enforced by the hub**. Clients may use them to
validate input before sending messages, but the hub will reject any messages
that violate these limits regardless of whether the client honors them or not.

**Client implementers**: Don't expect the hub greeting in the `WELCOME` body.
Wait for the `NOTICE` message(s) that follow. Or don't. We're not your
supervisor.

## Extension: HELLO Legacy Nickname Field

**Body Key**: `64` (`B_HELLO_NICK_LEGACY`)  
**Status**: Deprecated, supported for compatibility

Some pre-specification implementations sent the client nickname in the `HELLO`
body under key `64`. This is **deprecated**. The RRC spec defines envelope-level
nickname field (`K_NICK`, key `7`), which should be used instead.

rrcd supports **both**:
- If `K_NICK` (envelope-level) is present, use it.
- If `B_HELLO_NICK_LEGACY` (body key `64`) is present and `K_NICK` is absent,
   fall back to it.

**Client implementers**: Use `K_NICK` (envelope key `7`). Don't use body key
`64` unless you enjoy living in the past.

## Extension: Hub Commands

The RRC specification has no concept of "hub commands" or "slash commands"
beyond what individual implementations invent. rrcd implements a set of
IRC-style commands for room and hub management.

**How it works**: Any `MSG` message sent to a room (or without a room field)
that starts with `/` is interpreted as a command. If the command is recognized,
it's handled by the hub and **not forwarded** to the room. If unrecognized, it's
forwarded as a normal chat message (so you can still say "/shrug" without
triggering a command parser meltdown).

### Global/Hub Commands

These work from any room (or no room):

- `/reload`: Reload hub configuration (server operator only)
- `/stats`: Display hub statistics (server operator only)
- `/who [room]`: List members in a room. Private rooms (`+p`) are hidden from
    non-operators.
- `/names [room]`: Alias for `/who`
- `/list`: List all registered public rooms with their topics. Excludes private
    rooms (`+p`) and ephemeral (non-registered) rooms.

### Room Management Commands

Room founders and operators can use these:

- `/register <room>`: Register a room (makes it persistent). Founder only, must
   be present in room.
- `/unregister <room>`: Unregister a room. Founder only, must be present in
   room.
- `/topic <room> [text]`: View or set room topic. Operators can always set;
   regular users can set if `-t` mode.
- `/mode <room> <flag>`: Set room modes (see below).

### Moderation Commands

- `/kick <room> <nick|hashprefix>`: Remove a user from a room (operator only)
- `/kline add|del|list [hash]`: Global ban by identity hash (server operator
   only)
- `/ban <room> add|del|list [hash]`: Room-specific ban (operator only)
- `/invite <room> add|del|list [hash]`: Manage invite list for invite-only rooms
   (operator only)
- `/op <room> <nick|hashprefix>`: Grant operator status (operator only)
- `/deop <room> <nick|hashprefix>`: Remove operator status (operator only,
   cannot deop founder)
- `/voice <room> <nick|hashprefix>`: Grant voice in moderated rooms (operator
   only)
- `/devoice <room> <nick|hashprefix>`: Remove voice (operator only)

### Room Modes

IRC-style mode flags (set via `/mode <room> <flag>`):

- `+m` / `-m`: Moderated (only voiced/ops can speak)
- `+i` / `-i`: Invite-only (must be invited to join)
- `+t` / `-t`: Topic protected (only operators can set topic)
- `+n` / `-n`: No outside messages (must be in room to send messages)
- `+p` / `-p`: Private room (hidden from `/list` command and `/who` for
   non-operators)
- `+k <key>` / `-k`: Room key/password (must provide key to join)
- `+r` / `-r`: Registered room (read-only; use `/register` or `/unregister`)
- `+o <hash>` / `-o <hash>`: Grant/remove operator status
- `+v <hash>` / `-v <hash>`: Grant/remove voice

**Note**: These commands and modes are **not** part of the RRC specification.
They are rrcd-specific and hub-local. Other hubs may implement entirely
different command sets (or none at all). Clients should not assume these
commands exist.

## Extension: Room Registry and Persistence

The RRC specification says nothing about persistent rooms. rrcd implements a
room registry system that persists room state (modes, operators, bans, topic,
etc.) to disk.

**Registry file**: `~/.rrcd/rooms.toml` (configurable via `room_registry_path`)

**Registered rooms**:
- Survive hub restarts
- Retain operators, bans, topic, modes
- Can be configured with default modes (`+nrt` by default)
- Are pruned if unused for a configurable period (default: 30 days)

**Unregistered rooms**:
- Exist only while members are present
- Ephemeral state (lost on last member departure)

**Founder**: The first person to create a room is the founder. Only the founder
can register or unregister the room. Founders cannot be de-opped.

This is entirely hub-local and transparent to clients. Clients don't need to do
anything special.

## Extension: Invite Timeout

When a room is invite-only (`+i`), operators can add users to the invite list
via `/invite <room> add <hash>`. Invites have a configurable timeout (default:
900 seconds / 15 minutes).

This prevents the invite list from growing unbounded. Expired invites are pruned
periodically.

**Configuration**:
```toml
room_invite_timeout_s = 900.0
```

## Extension: JOINED and PARTED Room Notifications

The RRC specification defines `JOINED` and `PARTED` messages but doesn't specify
whether room members should be notified when users join or leave. rrcd
implements dual-mode notifications:

### JOIN Behavior

When a user joins a room:

1. **Joining user receives**: A `JOINED` message containing the full list of
   room members (if `include_joined_member_list` is enabled in config). This
   allows the client to know who is already in the room.
   
   ```python
   {
       0: 1,                    # protocol version
       1: T_JOINED,             # message type 
       2: <msg-id>,
       3: <timestamp>,
       4: <hub-identity-hash>,  # src
       5: <room-name>,
       6: [<hash1>, <hash2>, ...] # body: list of all member identity hashes
   }
   ```

2. **Existing room members receive**: A `JOINED` message containing **only** the
   identity hash of the user who just joined. This allows room members to update
   their member lists.
   
   ```python
   {
       0: 1,
       1: T_JOINED,
       2: <msg-id>,
       3: <timestamp>,
       4: <hub-identity-hash>,
       5: <room-name>,
       6: [<new-user-hash>]     # body: single-element list
   }
   ```

### PART Behavior

When a user leaves a room, all users (including the departing user) receive a
`PARTED` message containing **only** the departing user's identity hash (if
`include_joined_member_list` is enabled).

```python
{
    0: 1,
    1: T_PARTED,
    2: <msg-id>,
    3: <timestamp>,
    4: <hub-identity-hash>,
    5: <room-name>,
    6: [<departed-user-hash>] # body: single-element list
}
```

### Configuration

```toml
include_joined_member_list = true  # default: true
```

When disabled, all `JOINED` and `PARTED` messages have `null` or empty bodies.

### Client Implementation Notes

- **JOINED bodies** may contain either a full member list (multiple hashes) or a
  single hash. Clients should handle both cases.
- **PARTED bodies** always contain a single hash (the departing user's identity).
- The message source (`K_SRC`) is always the hub's identity hash, not the
  joining/parting user.
- This extension allows clients to maintain accurate room member lists without
  polling or issuing `/who` commands after every join/part.

## Extension: Nickname Normalization

The RRC spec says nicknames are "advisory" and may be "ridiculous." rrcd
normalizes nicknames:

- Maximum length: configurable (default: 32 characters)
- Leading/trailing whitespace stripped
- Control characters rejected
- Empty nicknames rejected

If a nickname fails validation, it's rejected and the user is assigned no
nickname (hash-only identification).

**Configuration**:
```toml
nick_max_chars = 32
```

## Extension: Rate Limiting

To prevent abuse, rrcd implements per-session rate limiting using a token bucket
algorithm.

**Default**: 240 messages per minute  
**Configuration**:
```toml
rate_limit_msgs_per_minute = 240
```

If a client exceeds the rate limit, excess messages are dropped (not queued).
The client is **not** disconnected or notified. This is intentional: rate limits
are for abuse prevention, not chat flow control.

## Extension: Ping/Pong Timeout

The RRC spec defines `PING` and `PONG` messages but doesn't specify timeout
behavior. rrcd allows configurable ping intervals and timeouts:

```toml
ping_interval_s = 0.0    # 0 = disabled
ping_timeout_s = 0.0     # 0 = no timeout
```

If enabled, the hub sends `PING` periodically. If a client fails to respond with
`PONG` within the timeout, the connection is terminated.

**Default**: Disabled (because Reticulum already has link-level keepalives).

## Extension: Trusted Identities (Server Operators)

Server operators can configure a list of trusted identity hashes. Trusted
identities are granted **server operator** privileges, allowing them to execute
administrative commands.

```toml
trusted_identities = [
    "a1b2c3d4e5f67890abcdef...",  # full 32-byte identity hash in hex
]
```

**Server operator commands** (requires trusted identity):
- `/reload` - Reload hub configuration and room registry
- `/who <room>` - List members in a room if it exists
- `/stats` - View hub statistics (messages, bytes, resources, sessions)
- `/kline` - Global ban management (add/del/list)

**Implementation**: The hub checks the peer's identity hash against the
`trusted_identities` list. If a non-trusted user attempts a server operator
command, they receive an `ERROR` message with "not authorized" and the command
is rejected.

**Security note**: Server operators also have implicit room operator status in
all rooms, allowing them to moderate any room without being explicitly granted
`+o` status.

This is a hub-local concept and not exposed to clients (no capability flag or
protocol message).

## Extension: Banned Identities (K-Lines)

Server operators can ban identity hashes globally via `/kline` commands or
configuration:

```toml
banned_identities = [
    "deadbeef...",
]
```

Banned identities are rejected at connection establishment (before `HELLO`).

## Extension: Statistics Tracking

rrcd tracks various counters (messages sent/received, bytes in/out, resources
transferred, etc.). Server operators can view stats via `/stats`.

**This is hub-local and not exposed to regular users.**

## What We Deliberately Did NOT Extend

Some things we intentionally **did not** add, despite IRC implementing them:

- **Channel services (ChanServ, NickServ, etc.)**: Not needed. Identity hashes
   are cryptographically unique. Use them.
- **Server-to-server linking**: RRC is designed for single-hub deployments over
   Reticulum. Federating hubs is out of scope.
- **DCC/file transfer**: Use Reticulum's file transfer mechanisms directly if
   you need them.
- **Flood protection beyond rate limiting**: We rate limit. If you're getting
   flooded, ban the offender.

## For Implementers: Compatibility Checklist

If you're implementing a client or another hub, here's what you need to know:

### Minimum Compatibility (Basic RRC Client)
- Implement core message types (HELLO, WELCOME, JOIN, JOINED, PART, PARTED, MSG,
   NOTICE, PING, PONG, ERROR)
- Use CBOR encoding
- Use unsigned integer keys in envelopes and bodies
- Handle `K_NICK` (envelope key 7) for nicknames
- Gracefully ignore unknown message types

### Enhanced Compatibility (Recommended)
- Support `T_RESOURCE_ENVELOPE` (message type 50) and Reticulum resources
- Advertise `CAP_RESOURCE_ENVELOPE` in your `HELLO` capabilities if you support
   resources
- Expect hub greeting to arrive via `NOTICE` messages after `WELCOME`
- Handle chunked `NOTICE` messages (multiple messages with the same content
   type)

### Full Compatibility (Hub Implementers)
- Implement resource transfer with envelope-first protocol
- Keep `WELCOME` minimal (hub name, version, caps only)
- Chunk large messages or use resources to stay within MTU
- Support legacy `B_HELLO_NICK_LEGACY` (body key 64) for old clients
- Normalize and validate nicknames before accepting them
- Implement rate limiting to prevent abuse
- Consider implementing room persistence (optional)

## Non-Normative Advice for the Weary

1. **Use resources**: If you're sending anything over ~500 bytes, use resource
    transfer. Your users will thank you.
2. **Ignore capabilities you don't support**: We won't be offended. Much.
3. **Don't over-engineer**: The RRC spec is minimal for a reason. Don't add
    features just because IRC has them.
4. **Test with low MTU**: If your client works over a 500-byte MTU link, it'll
    work everywhere.
5. **Read the rrcd source**: If this doc is unclear, the code is (arguably)
    clearer. Or at least executable.

---

*If you find a bug, inconsistency, or deeply offensive opinion in this document, file an issue. Or don't. We'll probably find it eventually.*
