"""FastAPI 入口：探测 API + 本地回显端配置 + TCP 入口核对。

- ``GET  /``                服务简介
- ``GET  /echo/config``     查看回显端当前配置与 epoch
- ``PUT  /echo/config``     设置丢弃阈值 / 断联（校验失败保留原状态）
- ``POST /probe``           发起一次探测（默认范围 576~1400 字节）
- ``GET  /probe/{id}``      查询历史探测结论
- ``GET  /probes``          历史探测结论列表
- ``POST /tcp-check``       经 TCP 入口逐帧核对 UDP 回显（实际 TCP 连接发帧并半关闭）

TCP 入口（默认 9998 端口）：维护网只放行 TCP 时，巡检终端用两字节大端
长度分帧把 MTUP 探测报文发给本入口，由本入口转发本地 UDP 回显端并按
请求顺序回写结果。交互式文档见 ``/docs``。
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Annotated, AsyncIterator, List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .echo_server import EchoConfig, EchoProtocol, EchoState
from .netutil import set_dont_fragment
from .packets import HEADER_SIZE, MAX_UDP_PAYLOAD, build_packet
from .prober import ProbeRequest, ProbeResult, Prober
from .tcp_entry import TcpEntryServer, run_tcp_check

ECHO_HOST = os.environ.get("ECHO_HOST", "0.0.0.0")
ECHO_PORT = int(os.environ.get("ECHO_PORT", "9999"))
PROBE_TARGET_HOST = os.environ.get("PROBE_TARGET_HOST", "127.0.0.1")
TCP_ENTRY_HOST = os.environ.get("TCP_ENTRY_HOST", "0.0.0.0")
TCP_ENTRY_PORT = int(os.environ.get("TCP_ENTRY_PORT", "9998"))

MAX_RESULTS = 200  # 内存中保留的探测结论条数上限


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    state = EchoState()

    # 回显端 socket：设置 DF，回包同样禁止 IP 分片
    echo_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    set_dont_fragment(echo_sock)
    echo_sock.bind((ECHO_HOST, ECHO_PORT))
    echo_sock.setblocking(False)

    loop = asyncio.get_running_loop()
    echo_protocol = EchoProtocol(state)
    echo_transport, _ = await loop.create_datagram_endpoint(
        lambda: echo_protocol, sock=echo_sock
    )

    # TCP 入口：两字节大端长度分帧，把有效 MTUP 帧转发给本地 UDP 回显端
    tcp_entry = TcpEntryServer((PROBE_TARGET_HOST, ECHO_PORT))
    tcp_server = await loop.create_server(tcp_entry, TCP_ENTRY_HOST, TCP_ENTRY_PORT)

    app.state.echo_state = state
    app.state.echo_protocol = echo_protocol
    app.state.prober = Prober(state, (PROBE_TARGET_HOST, ECHO_PORT))
    app.state.results = OrderedDict()  # probe_id -> ProbeResult
    app.state.tcp_server = tcp_server
    try:
        yield
    finally:
        echo_transport.close()
        tcp_server.close()
        await tcp_server.wait_closed()


app = FastAPI(
    title="遥测网关 UDP 最大负载探测",
    version="1.1.0",
    description=(
        "小包能到回显端、大包却超时？用本服务确认遥测网关可用的最大 UDP 负载。\n\n"
        "- 探测报文带 DF 位（禁止 IP 分片）与本次探测编号，只有对应回包才算成功；\n"
        "- 大包超时/发送失败先用小包复核，小包也失败则报告链路不确定；\n"
        "- 探测期间改动回显端配置会使本次结论作废；\n"
        "- 在下方 `PUT /echo/config` 设置丢弃阈值或断联，再 `POST /probe` 验证；\n"
        "- 维护网只放行 TCP 时，巡检终端可连 TCP 入口（默认 9998 端口，两字节大端\n"
        "  长度分帧）逐条核对 UDP 回显，也可用 `POST /tcp-check` 一键核对。"
    ),
    lifespan=lifespan,
)


@app.get("/", summary="服务简介")
async def index() -> dict:
    return {
        "service": "telemetry-gateway-udp-probe",
        "docs": "/docs",
        "endpoints": {
            "config": ["GET /echo/config", "PUT /echo/config"],
            "probe": ["POST /probe", "GET /probes", "GET /probe/{probe_id}"],
            "tcp_check": ["POST /tcp-check"],
        },
        "tcp_entry": {
            "port": TCP_ENTRY_PORT,
            "framing": "uint16be length + payload（收发相同）",
            "valid_frame_bytes": [HEADER_SIZE, 1400],
        },
    }


@app.get("/echo/config", summary="查看回显端配置")
async def get_config(request: Request) -> dict:
    state: EchoState = request.app.state.echo_state
    proto: EchoProtocol = request.app.state.echo_protocol
    return {
        "epoch": state.epoch,
        "config": state.config,
        "stats": {"echoed": proto.echoed, "dropped": proto.dropped},
    }


@app.put("/echo/config", summary="设置丢弃阈值或断联")
async def put_config(cfg: EchoConfig, request: Request) -> dict:
    # 入参先经 Pydantic 校验；校验失败直接 422，不会进入这里，原状态保持不变
    state: EchoState = request.app.state.echo_state
    epoch = state.apply(cfg)
    return {"epoch": epoch, "config": state.config}


@app.post("/probe", response_model=ProbeResult, summary="发起一次最大负载探测")
async def run_probe(req: ProbeRequest, request: Request) -> ProbeResult:
    prober: Prober = request.app.state.prober
    try:
        result = await prober.probe(req)
    except OSError as exc:
        # 目标地址无法解析/不可达等，探测未能发起
        raise HTTPException(status_code=400, detail=f"无法发起探测: {exc}") from exc
    results: OrderedDict[str, ProbeResult] = request.app.state.results
    results[result.probe_id] = result
    while len(results) > MAX_RESULTS:
        results.popitem(last=False)
    return result


@app.get("/probe/{probe_id}", response_model=ProbeResult, summary="查询历史探测结论")
async def get_probe(probe_id: str, request: Request) -> ProbeResult:
    results: OrderedDict[str, ProbeResult] = request.app.state.results
    try:
        return results[probe_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="probe_id 不存在或已被淘汰") from None


@app.get("/probes", summary="历史探测结论列表")
async def list_probes(request: Request) -> list[dict]:
    results: OrderedDict[str, ProbeResult] = request.app.state.results
    return [
        {
            "probe_id": r.probe_id,
            "status": r.status,
            "max_confirmed_size": r.max_confirmed_size,
            "reason": r.reason,
            "finished_at": r.finished_at,
        }
        for r in reversed(list(results.values()))
    ]


# ---------------------------------------------------------------------------
# TCP 入口核对：输入一组报文长度，走实际 TCP 连接发帧并半关闭，当次返回结果
# ---------------------------------------------------------------------------


class TcpCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sizes: List[Annotated[int, Field(ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD)]] = Field(
        ...,
        min_length=1,
        max_length=64,
        description=(
            f"要逐条核对的报文长度列表（每项 {HEADER_SIZE}～{MAX_UDP_PAYLOAD} 字节）。"
            "超过 1400 字节的帧不在 TCP 入口有效请求范围内，将核对为未回显"
        ),
    )


class TcpCheckFrame(BaseModel):
    seq: int = Field(..., description="帧序号（本次连接内从 1 递增）")
    size: int = Field(..., description="请求帧长度（字节）")
    echoed: bool = Field(..., description="是否收到 UDP 回显")
    echo_bytes: int = Field(..., description="回显字节数；未回显为 0")


class TcpCheckResult(BaseModel):
    check_id: str = Field(..., description="本次核对使用的探测编号（每条 TCP 连接一个新编号）")
    entry: str = Field(..., description="实际连接的 TCP 入口地址")
    total: int = Field(..., description="核对的帧数")
    echoed_count: int = Field(..., description="收到回显的帧数")
    frames: List[TcpCheckFrame]
    duration_ms: float


@app.post(
    "/tcp-check",
    response_model=TcpCheckResult,
    summary="经 TCP 入口逐帧核对 UDP 回显",
    description=(
        "为每个长度生成一帧 MTUP 探测报文（新探测编号、序号递增），"
        "经实际 TCP 连接发帧并半关闭写端，当次返回各帧的回显字节数或未回显。"
    ),
)
async def tcp_check(req: TcpCheckRequest) -> TcpCheckResult:
    check_id = uuid.uuid4()
    packets = [build_packet(check_id, seq, size) for seq, size in enumerate(req.sizes, 1)]
    host = TCP_ENTRY_HOST if TCP_ENTRY_HOST not in ("0.0.0.0", "", "::") else "127.0.0.1"

    t0 = time.monotonic()
    try:
        replies = await run_tcp_check(host, TCP_ENTRY_PORT, packets)
    except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
        raise HTTPException(status_code=502, detail=f"经 TCP 入口核对失败: {exc}") from exc

    frames: List[TcpCheckFrame] = []
    for seq, size in enumerate(req.sizes, 1):
        payload = replies[seq - 1] if seq - 1 < len(replies) else b""
        frames.append(
            TcpCheckFrame(seq=seq, size=size, echoed=len(payload) > 0, echo_bytes=len(payload))
        )
    return TcpCheckResult(
        check_id=str(check_id),
        entry=f"{host}:{TCP_ENTRY_PORT}",
        total=len(frames),
        echoed_count=sum(1 for f in frames if f.echoed),
        frames=frames,
        duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
    )
