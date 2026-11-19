"""探测报文编解码。

报文格式（大端，定长 28 字节头 + 零填充）::

    | 0..3   | 4..19        | 20..23 | 24..27 | 28 .. size-1 |
    | magic  | 本次探测编号  | seq    | size   | padding      |
    | "MTUP" | UUID(16B)    | uint32 | uint32 | 0x00 ...     |

- 每个报文都携带本次探测编号（session UUID）与序号 seq；
- size 字段为整个 UDP 负载长度，接收方据此校验报文未被截断/拼装；
- 只有 magic / 探测编号 / seq / size 全部对应的回包才被采信。
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

MAGIC = b"MTUP"
_HEADER = struct.Struct("!4s16sII")
HEADER_SIZE = _HEADER.size  # 28
# UDP 负载理论上限：65535 - 20(IPv4 头) - 8(UDP 头)
MAX_UDP_PAYLOAD = 65507


@dataclass(frozen=True)
class Packet:
    session_id: uuid.UUID
    seq: int
    size: int  # 整个 UDP 负载长度


def build_packet(session_id: uuid.UUID, seq: int, size: int) -> bytes:
    """构造一个总长恰好为 size 字节的探测报文。"""
    if size < HEADER_SIZE:
        raise ValueError(f"报文长度 {size} 小于头部长度 {HEADER_SIZE}")
    if size > MAX_UDP_PAYLOAD:
        raise ValueError(f"报文长度 {size} 超过 UDP 负载上限 {MAX_UDP_PAYLOAD}")
    return _HEADER.pack(MAGIC, session_id.bytes, seq, size) + bytes(size - HEADER_SIZE)


def parse_packet(data: bytes) -> Packet | None:
    """解析报文；magic 不符或长度不自洽时返回 None。"""
    if len(data) < HEADER_SIZE:
        return None
    magic, sid, seq, size = _HEADER.unpack(data[:HEADER_SIZE])
    if magic != MAGIC or size != len(data):
        return None
    return Packet(session_id=uuid.UUID(bytes=sid), seq=seq, size=size)
