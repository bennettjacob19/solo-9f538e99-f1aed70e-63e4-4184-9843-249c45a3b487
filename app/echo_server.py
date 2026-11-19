"""本地 UDP 回显端。

行为可通过 API 动态配置：
- ``drop_threshold``: UDP 负载超过该字节数即丢弃（模拟"大包不通"）；
- ``mode = "disconnect"``: 丢弃一切报文（模拟断联）。

每次成功变更配置都会使 ``epoch`` 单调递增。探测任务在开始与结束时比对
epoch：若探测期间配置发生变化，本次结论作废。
"""
from __future__ import annotations

import asyncio
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .packets import MAX_UDP_PAYLOAD, parse_packet


class EchoConfig(BaseModel):
    """回显端行为配置。校验失败时调用方不得改动现有状态。"""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["normal", "disconnect"] = Field(
        default="normal",
        description="normal=按阈值丢弃；disconnect=断联，丢弃一切报文",
    )
    drop_threshold: Optional[int] = Field(
        default=None,
        ge=0,
        le=MAX_UDP_PAYLOAD,
        description="UDP 负载超过该字节数即丢弃；null 表示不丢弃",
    )


class EchoState:
    """回显端共享状态（配置 + 世代号）。仅在事件循环内访问，替换是原子的。"""

    def __init__(self) -> None:
        self.config = EchoConfig()
        self.epoch = 0

    def apply(self, cfg: EchoConfig) -> int:
        """应用已通过校验的新配置，返回新 epoch。校验失败时不应调用本方法。"""
        self.config = cfg
        self.epoch += 1
        return self.epoch


class EchoProtocol(asyncio.DatagramProtocol):
    """回显协议：原样回送合法探测报文，按配置丢弃。"""

    def __init__(self, state: EchoState) -> None:
        self.state = state
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.echoed = 0
        self.dropped = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        cfg = self.state.config
        if cfg.mode == "disconnect":
            self.dropped += 1
            return
        if cfg.drop_threshold is not None and len(data) > cfg.drop_threshold:
            self.dropped += 1
            return
        if parse_packet(data) is None:
            self.dropped += 1
            return
        assert self.transport is not None
        self.transport.sendto(data, addr)
        self.echoed += 1

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass
