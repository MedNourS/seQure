from enum import Enum


class PacketType(Enum):
    HELLO = 0
    DATA = 1
    BYE = 2
    PING = 3
    PONG = 4
    FILE_META = 5
    FILE_CHUNK = 6
    FILE_END = 7
    KEM = 8
