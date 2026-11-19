"""探测引擎：在 [min_size, max_size] 内二分搜索可确认的最大 UDP 负载。

判定规则（与需求一一对应）：
- 每次探测运行使用独立 socket（临时端口）与独立探测编号（UUID），
  并发探测、迟到回包不会串入其他结论；
- 探测 socket 设置 DF 位，禁止 IP 分片；发送失败（如 EMSGSIZE）与超时
  同等对待；
- 大包超时或发送失败时，先用小包（small_size）复核链路：
  小包通 → 链路正常，确为尺寸受限，继续二分；
  小包也不通 → 链路不确定，立即终止，绝不把该失败记为尺寸上限；
- 探测期间回显端配置（epoch）变化 → 本次结论作废（invalidated）；
- 范围内全部确认 → 达到范围上限（reached_range_max）；
- 范围下限都确认不了（但链路正常）→ below_range。
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .echo_server import EchoState
from .netutil import set_dont_fragment
from .packets import HEADER_SIZE, MAX_UDP_PAYLOAD, build_packet, parse_packet

# ---------------------------------------------------------------------------
# API 模型
# ---------------------------------------------------------------------------


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_size: int = Field(576, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="探测范围下限（字节）")
    max_size: int = Field(1400, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="探测范围上限（字节）")
    timeout_ms: int = Field(500, ge=20, le=30000, description="单次探测等待回包超时（毫秒）")
    small_size: int = Field(64, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="链路复核小包长度（字节）")
    target_host: Optional[str] = Field(None, description="回显端地址，缺省为本地回显端")
    target_port: Optional[int] = Field(None, ge=1, le=65535, description="回显端端口，缺省为本地回显端")

    @model_validator(mode="after")
    def _check_range(self) -> "ProbeRequest":
        if self.min_size > self.max_size:
            raise ValueError("min_size 不能大于 max_size")
        return self


class AttemptOut(BaseModel):
    seq: int
    size: int
    purpose: Literal["probe", "link-verify"]
    outcome: Literal["ok", "timeout", "send_error"]
    rtt_ms: Optional[float] = None
    detail: Optional[str] = None


class ProbeResult(BaseModel):
    probe_id: str
    status: Literal["ok", "below_range", "undetermined", "invalidated"]
    max_confirmed_size: Optional[int] = Field(
        None, description="本次确认可用的最大 UDP 负载；undetermined 时为已确认下界，invalidated 时作废为 null"
    )
    reason: Optional[str] = Field(None, description="无法判定 / 结论作废 / 低于范围时的原因")
    reached_range_max: bool = False
    min_size: int
    max_size: int
    attempts: list[AttemptOut]
    stray_replies: int = Field(0, description="被丢弃的迟到/不对应回包数")
    config_epoch_start: int
    config_epoch_end: int
    df_enabled: bool = Field(..., description="探测 socket 是否成功设置 DF（禁止 IP 分片）")
    target: str
    started_at: datetime
    finished_at: datetime
    duration_ms: float


# ---------------------------------------------------------------------------
# 探测引擎
# ---------------------------------------------------------------------------


class _Inbound(asyncio.DatagramProtocol):
    """把收到的数据报/发送错误塞进队列，由探测协程自行匹配。

    注意：asyncio 的 DatagramTransport.sendto 不会把 OSError 抛给调用方，
    发送失败（如 EMSGSIZE）经 error_received 回调上报。
    """

    def __init__(self) -> None:
        self.queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        self.queue.put_nowait(("data", data))

    def error_received(self, exc: Exception) -> None:
        # 发送失败（EMSGSIZE 等）或连通型 UDP 的异步 ICMP 错误
        self.queue.put_nowait(("error", exc))


class Prober:
    def __init__(self, state: EchoState, default_target: tuple[str, int]) -> None:
        self._state = state
        self._default_target = default_target

    async def probe(self, req: ProbeRequest) -> ProbeResult:
        probe_id = uuid.uuid4()
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        host, port = self._default_target
        if req.target_host is not None:
            host = req.target_host
        if req.target_port is not None:
            port = req.target_port
        target = f"{host}:{port}"

        epoch_start = self._state.epoch
        attempts: list[AttemptOut] = []
        stray = 0
        seq = 0

        # 每次探测运行独立 socket（独立临时端口），并 connect 到回显端：
        # 其他运行的回包、无关数据报在内核层就被过滤，不会到达本 socket。
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_datagram_endpoint(
            _Inbound, remote_addr=(host, port)
        )
        sock = transport.get_extra_info("socket")
        df_ok = set_dont_fragment(sock) if sock is not None else False
        queue: asyncio.Queue[tuple[str, object]] = proto.queue

        async def attempt(size: int, purpose: Literal["probe", "link-verify"]) -> AttemptOut:
            nonlocal seq, stray
            seq += 1
            my_seq = seq
            payload = build_packet(probe_id, my_seq, size)
            t_send = time.monotonic()
            transport.sendto(payload)
            deadline = t_send + req.timeout_ms / 1000.0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return AttemptOut(seq=my_seq, size=size, purpose=purpose, outcome="timeout")
                try:
                    kind, obj = await asyncio.wait_for(queue.get(), remaining)
                except asyncio.TimeoutError:
                    return AttemptOut(seq=my_seq, size=size, purpose=purpose, outcome="timeout")
                if kind == "error":
                    # 发送失败（如 EMSGSIZE：DF 下超过路径 MTU）
                    exc = obj
                    return AttemptOut(
                        seq=my_seq, size=size, purpose=purpose,
                        outcome="send_error",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                pkt = parse_packet(obj)  # type: ignore[arg-type]
                if (
                    pkt is not None
                    and pkt.session_id == probe_id
                    and pkt.seq == my_seq
                    and pkt.size == size
                ):
                    rtt = (time.monotonic() - t_send) * 1000.0
                    return AttemptOut(
                        seq=my_seq, size=size, purpose=purpose,
                        outcome="ok", rtt_ms=round(rtt, 3),
                    )
                # 迟到/不对应回包：丢弃不采信，继续等到超时为止
                stray += 1

        def epoch_broken() -> bool:
            return self._state.epoch != epoch_start

        def invalidated_result() -> tuple[str, str]:
            return (
                "invalidated",
                f"探测期间回显端配置发生变化（epoch {epoch_start} → {self._state.epoch}），本次结论作废",
            )

        status: Literal["ok", "below_range", "undetermined", "invalidated"] = "ok"
        reason: Optional[str] = None
        best: Optional[int] = None
        lo, hi = req.min_size, req.max_size

        try:
            while lo <= hi:
                if epoch_broken():
                    status, reason = invalidated_result()
                    best = None
                    break
                mid = (lo + hi) // 2
                att = await attempt(mid, "probe")
                attempts.append(att)
                if att.outcome == "ok":
                    best = mid
                    lo = mid + 1
                    continue
                # 大包失败（超时或发送失败）→ 小包复核链路
                verify = await attempt(req.small_size, "link-verify")
                attempts.append(verify)
                if verify.outcome == "ok":
                    hi = mid - 1  # 链路正常，确为尺寸受限
                    continue
                if epoch_broken():
                    status, reason = invalidated_result()
                    best = None
                else:
                    status = "undetermined"
                    reason = (
                        f"{mid} 字节探测{('超时' if att.outcome == 'timeout' else '发送失败')}后，"
                        f"{req.small_size} 字节小包复核亦失败（{verify.outcome}），"
                        "链路状态不确定，不能将该失败记为尺寸上限"
                    )
                    # 保留此前已确认的下界，但绝不把失败尺寸当作上限
                break
            else:
                pass

            if status == "ok":
                if epoch_broken():
                    status, reason = invalidated_result()
                    best = None
                elif best is None:
                    status = "below_range"
                    reason = (
                        f"链路正常（{req.small_size} 字节小包复核通过），但范围下限 "
                        f"{req.min_size} 字节未获确认，可确认上限低于探测范围"
                    )
        finally:
            transport.close()

        finished_at = datetime.now(timezone.utc)
        return ProbeResult(
            probe_id=str(probe_id),
            status=status,
            max_confirmed_size=best,
            reason=reason,
            reached_range_max=(status == "ok" and best == req.max_size),
            min_size=req.min_size,
            max_size=req.max_size,
            attempts=attempts,
            stray_replies=stray,
            config_epoch_start=epoch_start,
            config_epoch_end=self._state.epoch,
            df_enabled=df_ok,
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
        )
