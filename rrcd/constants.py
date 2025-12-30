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
NICK_MAX_CHARS = 32

# Message types
T_HELLO = 1
T_WELCOME = 2

T_JOIN = 10
T_JOINED = 11
T_PART = 12

T_MSG = 20
T_NOTICE = 21

T_PING = 30
T_PONG = 31

T_ERROR = 40

# HELLO body keys
B_HELLO_NICK = 0
B_HELLO_NAME = 1
B_HELLO_VER = 2
B_HELLO_CAPS = 3

# WELCOME body keys
B_WELCOME_HUB = 0
B_WELCOME_GREETING = 1
B_WELCOME_CAPS = 2
