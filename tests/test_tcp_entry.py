"""TCP 入口端到端测试：真实 TCP 连接（同步 socket）+ TestClient 生命周期。"""
from __future__ import annotations

import socket
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import TCP_ENTRY_PORT, app
from app.packets import HEADER_SIZE, build_packet


@pytest.fixture()
def client():
    # 每个用例一套全新 lifespan：回显端状态、epoch、TCP 入口都重置
    with TestClient(app) as c:
        yield c


def set_config(client, **kw):
    r = client.put("/echo/config", json=kw)
    assert r.status_code == 200, r.text
    return r.json()["epoch"]


class TcpClient:
    """巡检终端模拟：两字节大端长度分帧，可半关闭写端。"""

    def __init__(self, port: int = TCP_ENTRY_PORT):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.file = self.sock.makefile("rb")

    def send_frame(self, payload: bytes):
        self.sock.sendall(len(payload).to_bytes(2, "big") + payload)

    def send_raw(self, data: bytes):
        self.sock.sendall(data)

    def half_close(self):
        self.sock.shutdown(socket.SHUT_WR)

    def read_frame(self):
        """读一个响应帧；对端正常关闭返回 None。"""
        hdr = self.file.read(2)
        if not hdr:
            return None
        assert len(hdr) == 2, "响应帧长度前缀被截断"
        n = int.from_bytes(hdr, "big")
        payload = self.file.read(n) if n else b""
        assert len(payload) == n, "响应帧负载被截断"
        return payload

    def read_all(self):
        out = []
        while True:
            frame = self.read_frame()
            if frame is None:
                return out
            out.append(frame)

    def close(self):
        try:
            self.sock.close()
        finally:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def make_packets(sizes):
    """模拟巡检终端：每次连接一个新探测编号，序号从 1 递增。"""
    sid = uuid.uuid4()
    return [build_packet(sid, seq, size) for seq, size in enumerate(sizes, 1)]


# ---------------------------------------------------------------- 基本分帧与回显


class TestTcpEntryEcho:
    def test_roundtrip_in_order(self, client):
        sizes = [HEADER_SIZE, 100, 1400, 64]
        packets = make_packets(sizes)
        with TcpClient() as tcp:
            for pkt in packets:
                tcp.send_frame(pkt)
            tcp.half_close()
            replies = tcp.read_all()  # 入口写完所有结果后关闭连接
        assert replies == packets  # 原始回包按请求顺序写回

    def test_zero_length_placeholder_when_dropped(self, client):
        set_config(client, mode="disconnect")
        packets = make_packets([64, 128])
        with TcpClient() as tcp:
            for pkt in packets:
                tcp.send_frame(pkt)
            tcp.half_close()
            replies = tcp.read_all()
        assert replies == [b"", b""]  # 500ms 未匹配 → 零长度帧占位

    def test_ordered_writeback_with_mixed_outcomes(self, client):
        # 中间帧被丢弃（500ms 后才有结果），后续帧立即回显：
        # 写回顺序仍必须是请求顺序
        set_config(client, mode="normal", drop_threshold=100)
        packets = make_packets([64, 200, 64])
        with TcpClient() as tcp:
            for pkt in packets:
                tcp.send_frame(pkt)
            tcp.half_close()
            replies = tcp.read_all()
        assert replies == [packets[0], b"", packets[2]]

    def test_pipelining_without_half_close(self, client):
        # 先前帧未回也可继续发；超过 8 帧未回写时入口暂停收新帧，
        # 结果回写后恢复，最终 10 帧全部得到响应（不断联也正常服务）
        set_config(client, mode="disconnect")
        packets = make_packets([64] * 10)
        with TcpClient() as tcp:
            for pkt in packets:
                tcp.send_frame(pkt)
            replies = [tcp.read_frame() for _ in packets]
        assert replies == [b""] * 10


# ---------------------------------------------------------------- 无效帧与截断帧


class TestTcpEntryInvalidFrames:
    def test_invalid_frames_get_zero_length(self, client):
        good = make_packets([100])[0]
        too_short = b"x" * (HEADER_SIZE - 1)          # 不足 MTUP 头长
        bad_magic = b"y" * 100                         # magic 不符
        too_long = make_packets([1401])[0]             # 超过 1400 上限
        with TcpClient() as tcp:
            for frame in (too_short, bad_magic, too_long, good):
                tcp.send_frame(frame)
            tcp.half_close()
            replies = tcp.read_all()
        assert replies == [b"", b"", b"", good]

    def test_truncated_frame_not_forwarded_after_half_close(self, client):
        good = make_packets([100])[0]
        with TcpClient() as tcp:
            tcp.send_frame(good)
            # 截断帧：声明 200 字节只发 50，随后半关闭
            tcp.send_raw((200).to_bytes(2, "big") + b"z" * 50)
            tcp.half_close()
            replies = tcp.read_all()
        assert replies == [good]  # 截断帧不转发，完整帧结果写完后关闭

    def test_empty_connection_half_close(self, client):
        with TcpClient() as tcp:
            tcp.half_close()
            assert tcp.read_all() == []


# ---------------------------------------------------------------- 连接隔离


class TestTcpEntryIsolation:
    def test_connections_are_independent(self, client):
        set_config(client, mode="normal", drop_threshold=100)
        pkts_a = make_packets([64, 200])   # A：小帧回显、大帧丢弃
        pkts_b = make_packets([200, 64])   # B：大帧丢弃、小帧回显
        with TcpClient() as a, TcpClient() as b:
            for pkt in pkts_a:
                a.send_frame(pkt)
            for pkt in pkts_b:
                b.send_frame(pkt)
            a.half_close()
            b.half_close()
            assert a.read_all() == [pkts_a[0], b""]
            assert b.read_all() == [b"", pkts_b[1]]

    def test_concurrent_connections_do_not_interfere(self, client):
        results = {}

        def worker(name, sizes):
            packets = make_packets(sizes)
            with TcpClient() as tcp:
                for pkt in packets:
                    tcp.send_frame(pkt)
                tcp.half_close()
                results[name] = (tcp.read_all(), packets)

        threads = [
            threading.Thread(target=worker, args=("a", [64, 128, 256])),
            threading.Thread(target=worker, args=("b", [100, 200])),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for replies, packets in results.values():
            assert replies == packets


# ---------------------------------------------------------------- /tcp-check API


class TestTcpCheckApi:
    def test_tcp_check_all_echoed(self, client):
        r = client.post("/tcp-check", json={"sizes": [64, 100, 1400]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 3
        assert body["echoed_count"] == 3
        assert body["check_id"]
        assert [f["seq"] for f in body["frames"]] == [1, 2, 3]
        for f, size in zip(body["frames"], [64, 100, 1400]):
            assert f["size"] == size
            assert f["echoed"] is True
            assert f["echo_bytes"] == size

    def test_tcp_check_reports_unechoed(self, client):
        set_config(client, mode="normal", drop_threshold=100)
        r = client.post("/tcp-check", json={"sizes": [64, 500, 1500]})
        assert r.status_code == 200, r.text
        frames = r.json()["frames"]
        # 500 被回显端阈值丢弃；1500 超过入口有效帧上限
        assert [(f["echoed"], f["echo_bytes"]) for f in frames] == [
            (True, 64),
            (False, 0),
            (False, 0),
        ]
        assert r.json()["echoed_count"] == 1

    def test_tcp_check_disconnect(self, client):
        set_config(client, mode="disconnect")
        r = client.post("/tcp-check", json={"sizes": [64, 64]})
        assert r.status_code == 200, r.text
        assert r.json()["echoed_count"] == 0
        assert all(f["echo_bytes"] == 0 for f in r.json()["frames"])

    def test_tcp_check_validation(self, client):
        assert client.post("/tcp-check", json={"sizes": []}).status_code == 422
        assert client.post("/tcp-check", json={"sizes": [10]}).status_code == 422
        assert client.post("/tcp-check", json={"sizes": [65508]}).status_code == 422
        assert client.post("/tcp-check", json={"sizes": [64], "extra": 1}).status_code == 422

    def test_tcp_check_in_openapi(self, client):
        spec = client.get("/openapi.json").json()
        assert "/tcp-check" in spec["paths"]
