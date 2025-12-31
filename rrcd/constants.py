# RRC protocol constants (numeric keys and message types)

RRC_VERSION = 1

# Envelope keys
K_V = 0
K_T = 1
K_ID = 2
K_TS = 3
K_SRC = 4
K_ROOM = 5
K_BODY = 6
K_NICK = 7

# Message types
T_HELLO = 1
T_WELCOME = 2

T_JOIN = 10
T_JOINED = 11
T_PART = 12
T_PARTED = 13

T_MSG = 20
T_NOTICE = 21

T_PING = 30
T_PONG = 31

T_ERROR = 40

T_RESOURCE_ENVELOPE = 50

# HELLO body keys
# Per spec: key assignments are fixed.
B_HELLO_NAME = 0
B_HELLO_VER = 1
B_HELLO_CAPS = 2

# Legacy / pre-spec implementations may have sent nick in HELLO body.
# Prefer the envelope-level nickname field (K_NICK=7) going forward.
B_HELLO_NICK_LEGACY = 64

# WELCOME body keys
B_WELCOME_HUB = 0
B_WELCOME_VER = 1
B_WELCOME_CAPS = 2

# Capabilities map keys (values are advisory). Keep these small and numeric.
CAP_RESOURCE_ENVELOPE = 0

# RESOURCE_ENVELOPE body keys
B_RES_ID = 0
B_RES_KIND = 1
B_RES_SIZE = 2
B_RES_SHA256 = 3
B_RES_ENCODING = 4

# Resource kinds (string values)
RES_KIND_NOTICE = "notice"
RES_KIND_MOTD = "motd"
RES_KIND_BLOB = "blob"
