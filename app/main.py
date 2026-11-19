"""FastAPI 入口：探测 API + 本地回显端配置。

- ``GET  /``                服务简介
- ``GET  /echo/config``     查看回显端当前配置与 epoch
- ``PUT  /echo/config``     设置丢弃阈值 / 断联（校验失败保留原状态）
- ``POST /probe``           发起一次探测（默认范围 576~1400 字节）
- ``GET  /probe/{id}``      查询历史探测结论
- ``GET  /probes``          历史探测结论列表

交互式文档见 ``/docs``。
"""
from __future__ import annotations

import asyncio
import os
import socket
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request

from .echo_server import EchoConfig, EchoProtocol, EchoState
from .netutil import set_dont_fragment
from .prober import ProbeRequest, ProbeResult, Prober

ECHO_HOST = os.environ.get("ECHO_HOST", "0.0.0.0")
ECHO_PORT = int(os.environ.get("ECHO_PORT", "9999"))
PROBE_TARGET_HOST = os.environ.get("PROBE_TARGET_HOST", "127.0.0.1")

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

    app.state.echo_state = state
    app.state.echo_protocol = echo_protocol
    app.state.prober = Prober(state, (PROBE_TARGET_HOST, ECHO_PORT))
    app.state.results = OrderedDict()  # probe_id -> ProbeResult
    try:
        yield
    finally:
        echo_transport.close()


app = FastAPI(
    title="遥测网关 UDP 最大负载探测",
    version="1.0.0",
    description=(
        "小包能到回显端、大包却超时？用本服务确认遥测网关可用的最大 UDP 负载。\n\n"
        "- 探测报文带 DF 位（禁止 IP 分片）与本次探测编号，只有对应回包才算成功；\n"
        "- 大包超时/发送失败先用小包复核，小包也失败则报告链路不确定；\n"
        "- 探测期间改动回显端配置会使本次结论作废；\n"
        "- 在下方 `PUT /echo/config` 设置丢弃阈值或断联，再 `POST /probe` 验证。"
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
