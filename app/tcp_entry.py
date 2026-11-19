"""TCP 入口：维护网只放行 TCP，巡检终端经本入口用 MTUP 报文逐条核对 UDP 回显。

协议与行为（与需求一一对应）：

- 收发均为两字节大端长度分帧：``uint16be length + payload``；
- 28～1400 字节的有效 MTUP 请求帧原样转发给本地 UDP 回显端；
  无效帧（长度越界 / 报文不自洽）不转发，立即回写零长度帧占位；
- 单连接流水线：先前帧未回也可继续发；未回写结果达到 8 帧即暂停收新帧
  （``transport.pause_reading`` 背压，结果回写后自动恢复）；
- 每条连接使用独立 UDP socket（独立临时端口，connect 到回显端），
  其他连接/无关数据报在内核层就被过滤，各连接结果互不影响；
- UDP 回包按内容与待回帧精确匹配；即使乱序到达，也按请求顺序
  把原始回包写回 TCP；
- 帧发出后 500ms 未收到匹配回包，或发送失败，回写零长度帧占位；
  迟到回包丢弃（计入 ``stray_replies``）；
- 对端半关闭写端（EOF）后：截断帧不转发，完整帧的结果全部写完再关闭连接。
"""
from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from .packets import HEADER_SIZE, MAX_UDP_PAYLOAD, parse_packet

MIN_FRAME_SIZE = HEADER_SIZE  # 28：有效请求帧下限（MTUP 头长）
MAX_FRAME_SIZE = 1400         # 有效请求帧上限
MAX_OUTSTANDING = 8           # 单连接未回写结果达到该值即暂停收新帧
REPLY_TIMEOUT = 0.5           # 帧发出后 500ms 未匹配 → 零长度帧占位
CHECK_OVERALL_TIMEOUT = 10.0  # /tcp-check 一次核对的整体兜底时限（秒）


class _UdpProtocol(asyncio.DatagramProtocol):
    """单连接专用 UDP 端：connected socket，只会收到本连接的回包。"""

    def __init__(self, conn: "TcpEntryConnection") -> None:
        self._conn = conn

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        self._conn.udp_reply_received(data)

    def error_received(self, exc: Exception) -> None:
        # 异步发送错误（如 ICMP 不可达）无法可靠归属到某一帧；
        # 对应帧 500ms 后按超时回写零长度帧，可观察行为一致。
        self._conn.udp_error_received(exc)


class TcpEntryConnection(asyncio.Protocol):
    """一条巡检终端连接的状态机。

    帧序号（index）按收到的完整帧顺序分配；结果字典 ``_results`` 就绪后
    由 ``_flush_writes`` 严格按序号写回 TCP，保证乱序回包也按请求顺序输出。
    """

    def __init__(
        self,
        target: Tuple[str, int],
        reply_timeout: float = REPLY_TIMEOUT,
        max_outstanding: int = MAX_OUTSTANDING,
    ) -> None:
        self._target = target
        self._reply_timeout = reply_timeout
        self._max_outstanding = max_outstanding

        self._transport: Optional[asyncio.Transport] = None
        self._udp: Optional[asyncio.DatagramTransport] = None
        self._udp_failed = False  # UDP 端建立失败：后续帧一律回写零长度帧
        self._setup_task: "Optional[asyncio.Task[None]]" = None

        self._buf = bytearray()                 # 已接收但未处理的字节
        self._next_index = 0                    # 下一个帧序号（按完整帧接收顺序）
        self._pending: Dict[int, Tuple[bytes, asyncio.TimerHandle]] = {}
        self._by_content: Dict[bytes, Deque[int]] = {}  # 请求内容 → 待回帧序号（FIFO）
        self._results: Dict[int, bytes] = {}    # 已就绪待写回的结果（序号 → 回包/空）
        self._write_next = 0                    # 下一个待写回的帧序号
        self._paused = False
        self._pumping = False
        self._eof = False
        self._closed = False

        self.stray_replies = 0  # 被丢弃的迟到/不对应回包数

    # ------------------------------------------------------------------ asyncio.Protocol

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        self._setup_task = asyncio.get_running_loop().create_task(self._setup_udp())

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self._buf += data
        self._pump()

    def eof_received(self) -> Optional[bool]:
        # 对端半关闭写端：截断帧不转发，完整帧的结果写完再关闭连接
        self._eof = True
        if self._udp_ready():
            self._drain_buffer()
        self._pump()
        return True  # 连接由我们在所有结果写完后自行关闭

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._closed = True
        if self._setup_task is not None:
            self._setup_task.cancel()
        for _, timer in self._pending.values():
            timer.cancel()
        self._pending.clear()
        self._by_content.clear()
        if self._udp is not None:
            self._udp.close()

    # ------------------------------------------------------------------ UDP 端

    async def _setup_udp(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self), remote_addr=self._target
            )
        except OSError:
            # 目标地址无法解析/不可达：本连接所有帧都将回写零长度帧
            self._udp_failed = True
        else:
            if self._closed:
                transport.close()
                return
            self._udp = transport  # type: ignore[assignment]
        # UDP 就绪前收到的帧一直攒在缓冲里，就绪后统一处理
        if self._eof:
            self._drain_buffer()
        self._pump()

    def udp_reply_received(self, data: bytes) -> None:
        if self._closed:
            return
        queue = self._by_content.get(data)
        if not queue:
            self.stray_replies += 1  # 迟到/不对应回包：丢弃
            return
        self._resolve(queue[0], data)

    def udp_error_received(self, exc: Exception) -> None:
        pass  # 见 _UdpProtocol.error_received 注释

    # ------------------------------------------------------------------ 状态机核心

    def _udp_ready(self) -> bool:
        return self._udp is not None or self._udp_failed

    def _outstanding(self) -> int:
        """已取出但未回写结果的帧数。"""
        return self._next_index - self._write_next

    def _has_complete_frame(self) -> bool:
        return len(self._buf) >= 2 and len(self._buf) >= 2 + int.from_bytes(self._buf[:2], "big")

    def _pump(self) -> None:
        """推进状态机：取帧 → 转发/占位 → 按序写回 → 背压 → 收尾关闭。

        所有事件回调（TCP 数据、EOF、UDP 回包、超时）都汇入本方法；
        用 ``_pumping`` 防止同步链式调用造成的重入。
        """
        if self._closed or self._transport is None or self._pumping:
            return
        self._pumping = True
        try:
            while True:
                progressed = False
                if not self._eof and self._udp_ready():
                    while self._outstanding() < self._max_outstanding and self._has_complete_frame():
                        self._take_frame()
                        progressed = True
                if self._flush_writes():
                    progressed = True
                if not progressed:
                    break
        finally:
            self._pumping = False
        self._update_reading()
        self._maybe_close()

    def _take_frame(self) -> None:
        """从缓冲取出一个完整帧并处理（转发或立即占位）。"""
        n = int.from_bytes(self._buf[:2], "big")
        frame = bytes(self._buf[2 : 2 + n])
        del self._buf[: 2 + n]
        idx = self._next_index
        self._next_index += 1

        valid = (
            self._udp is not None
            and MIN_FRAME_SIZE <= n <= MAX_FRAME_SIZE
            and parse_packet(frame) is not None
        )
        if not valid:
            # 无效请求帧（长度越界/报文不自洽/UDP 不可用）：零长度帧占位
            self._results[idx] = b""
            return

        loop = asyncio.get_running_loop()
        timer = loop.call_later(self._reply_timeout, self._on_reply_timeout, idx)
        self._pending[idx] = (frame, timer)
        self._by_content.setdefault(frame, deque()).append(idx)
        try:
            self._udp.sendto(frame)  # 原样转发给本地 UDP 回显端
        except OSError:
            self._resolve(idx, b"")  # 发送失败 → 零长度帧占位

    def _drain_buffer(self) -> None:
        """EOF 时取尽缓冲中的完整帧（不再受未回写上限约束），丢弃截断帧。"""
        while self._has_complete_frame():
            self._take_frame()
        self._buf.clear()  # 截断帧不转发

    def _resolve(self, idx: int, payload: bytes) -> bool:
        """登记一帧的结果（回包原文或空占位）；已解决的帧返回 False。"""
        entry = self._pending.pop(idx, None)
        if entry is None:
            return False
        frame, timer = entry
        timer.cancel()
        queue = self._by_content.get(frame)
        if queue is not None:
            queue.remove(idx)
            if not queue:
                del self._by_content[frame]
        self._results[idx] = payload
        self._pump()
        return True

    def _on_reply_timeout(self, idx: int) -> None:
        if not self._closed:
            self._resolve(idx, b"")  # 500ms 未收到匹配回包 → 零长度帧占位

    def _flush_writes(self) -> bool:
        """把已就绪的结果严格按帧序号写回 TCP；返回是否有实际写入。"""
        assert self._transport is not None
        wrote = False
        while self._write_next in self._results:
            payload = self._results.pop(self._write_next)
            self._transport.write(len(payload).to_bytes(2, "big") + payload)
            self._write_next += 1
            wrote = True
        return wrote

    def _update_reading(self) -> None:
        """背压：未回写结果达到上限即暂停收新帧，回落后恢复。"""
        if self._closed or self._transport is None or self._eof:
            return
        if self._outstanding() >= self._max_outstanding:
            if not self._paused:
                self._paused = True
                with contextlib.suppress(Exception):
                    self._transport.pause_reading()
        elif self._paused:
            self._paused = False
            with contextlib.suppress(Exception):
                self._transport.resume_reading()

    def _maybe_close(self) -> None:
        """EOF 且所有完整帧的结果都已写回 → 关闭连接。"""
        if (
            self._eof
            and not self._closed
            and self._transport is not None
            and self._udp_ready()
            and self._write_next == self._next_index
        ):
            self._transport.close()


class TcpEntryServer:
    """TCP 入口连接工厂：持有共享配置，为每条连接创建独立状态机。"""

    def __init__(
        self,
        target: Tuple[str, int],
        reply_timeout: float = REPLY_TIMEOUT,
        max_outstanding: int = MAX_OUTSTANDING,
    ) -> None:
        self._target = target
        self._reply_timeout = reply_timeout
        self._max_outstanding = max_outstanding

    def __call__(self) -> TcpEntryConnection:
        return TcpEntryConnection(self._target, self._reply_timeout, self._max_outstanding)


async def run_tcp_check(
    host: str,
    port: int,
    packets: List[bytes],
    overall_timeout: float = CHECK_OVERALL_TIMEOUT,
) -> List[bytes]:
    """走实际 TCP 连接逐帧发出探测报文并半关闭写端，按序读回全部响应帧。

    返回与 ``packets`` 一一对应的响应帧负载列表；空字节表示该帧未回显
    （入口回写的零长度占位帧）。入口保证每帧必有一个响应并在写完后关闭
    连接，因此读到 EOF 即结束；``overall_timeout`` 仅为兜底。
    """
    reader, writer = await asyncio.open_connection(host, port)
    try:
        for pkt in packets:
            writer.write(len(pkt).to_bytes(2, "big") + pkt)
        await writer.drain()
        writer.write_eof()  # 半关闭写端：告知入口不再发新帧

        async def _read_all() -> List[bytes]:
            replies: List[bytes] = []
            while True:
                try:
                    header = await reader.readexactly(2)
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        raise ConnectionError("TCP 入口的响应帧被截断") from exc
                    break  # 入口写完所有结果后正常关闭
                n = int.from_bytes(header, "big")
                replies.append(await reader.readexactly(n) if n else b"")
            return replies

        return await asyncio.wait_for(_read_all(), overall_timeout)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
