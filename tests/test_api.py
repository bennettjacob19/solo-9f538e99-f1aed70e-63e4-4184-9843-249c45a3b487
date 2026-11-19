"""端到端测试：真实 UDP 回显端 + TestClient。"""
from __future__ import annotations

import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.packets import HEADER_SIZE, build_packet, parse_packet


@pytest.fixture()
def client():
    # 每个用例一套全新 lifespan：回显端状态、epoch、历史记录都重置
    with TestClient(app) as c:
        yield c


def set_config(client, **kw):
    r = client.put("/echo/config", json=kw)
    assert r.status_code == 200, r.text
    return r.json()["epoch"]


def run_probe(client, **kw):
    kw.setdefault("timeout_ms", 150)
    r = client.post("/probe", json=kw)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- 报文编解码


class TestPackets:
    def test_roundtrip(self):
        sid = uuid.uuid4()
        data = build_packet(sid, 7, 576)
        assert len(data) == 576
        pkt = parse_packet(data)
        assert pkt is not None
        assert pkt.session_id == sid and pkt.seq == 7 and pkt.size == 576

    def test_min_and_max_size(self):
        sid = uuid.uuid4()
        assert len(build_packet(sid, 1, HEADER_SIZE)) == HEADER_SIZE
        assert len(build_packet(sid, 1, 65507)) == 65507
        with pytest.raises(ValueError):
            build_packet(sid, 1, HEADER_SIZE - 1)
        with pytest.raises(ValueError):
            build_packet(sid, 1, 65508)

    def test_reject_garbage(self):
        assert parse_packet(b"") is None
        assert parse_packet(b"x" * HEADER_SIZE) is None  # magic 不符
        data = bytearray(build_packet(uuid.uuid4(), 1, 100))
        data[-1] = 1
        assert parse_packet(bytes(data[:-1])) is None  # 长度不自洽


# ---------------------------------------------------------------- 配置接口


class TestConfig:
    def test_default_config(self, client):
        r = client.get("/echo/config")
        assert r.status_code == 200
        body = r.json()
        assert body["epoch"] == 0
        assert body["config"] == {"mode": "normal", "drop_threshold": None}

    def test_update_and_epoch_increments(self, client):
        e1 = set_config(client, mode="normal", drop_threshold=1000)
        e2 = set_config(client, mode="disconnect", drop_threshold=None)
        assert e2 == e1 + 1 == 2
        assert client.get("/echo/config").json()["config"]["mode"] == "disconnect"

    def test_invalid_config_keeps_original_state(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        before = client.get("/echo/config").json()

        for bad in (
            {"mode": "bogus"},
            {"drop_threshold": -1},
            {"drop_threshold": 70000},
            {"mode": "normal", "drop_threshold": 1000, "extra": 1},
            {"drop_threshold": "abc"},
        ):
            r = client.put("/echo/config", json=bad)
            assert r.status_code == 422, bad

        after = client.get("/echo/config").json()
        assert after["epoch"] == before["epoch"]
        assert after["config"] == before["config"]


# ---------------------------------------------------------------- 探测


class TestProbe:
    def test_no_drop_reaches_range_max(self, client):
        res = run_probe(client)
        assert res["status"] == "ok"
        assert res["max_confirmed_size"] == 1400
        assert res["reached_range_max"] is True
        assert res["df_enabled"] is True
        assert res["reason"] is None
        assert all(a["outcome"] == "ok" for a in res["attempts"])
        assert res["config_epoch_start"] == res["config_epoch_end"]

    def test_threshold_1000(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        res = run_probe(client)
        assert res["status"] == "ok"
        assert res["max_confirmed_size"] == 1000
        assert res["reached_range_max"] is False
        # 失败的大包后面必须紧跟一次小包复核，且复核通过
        attempts = res["attempts"]
        for i, a in enumerate(attempts):
            if a["purpose"] == "probe" and a["outcome"] != "ok":
                assert a["size"] > 1000
                nxt = attempts[i + 1]
                assert nxt["purpose"] == "link-verify" and nxt["outcome"] == "ok"
        # 所有确认成功的大包都不超过阈值
        assert all(
            a["size"] <= 1000
            for a in attempts
            if a["purpose"] == "probe" and a["outcome"] == "ok"
        )

    def test_disconnect_reports_undetermined(self, client):
        set_config(client, mode="disconnect")
        res = run_probe(client, timeout_ms=100)
        assert res["status"] == "undetermined"
        assert res["max_confirmed_size"] is None
        assert "链路状态不确定" in res["reason"]
        purposes = [a["purpose"] for a in res["attempts"]]
        assert "link-verify" in purposes
        assert all(a["outcome"] != "ok" for a in res["attempts"])

    def test_below_range(self, client):
        # 阈值 100：小包(64B)能通，范围下限 576 通不了
        set_config(client, mode="normal", drop_threshold=100)
        res = run_probe(client, timeout_ms=100)
        assert res["status"] == "below_range"
        assert res["max_confirmed_size"] is None
        assert "低于探测范围" in res["reason"]

    def test_config_change_during_probe_invalidates(self, client):
        set_config(client, mode="normal", drop_threshold=700)

        def change_config():
            time.sleep(0.15)
            client.put("/echo/config", json={"mode": "normal", "drop_threshold": 1400})

        t = threading.Thread(target=change_config)
        t.start()
        # 首次二分 mid=988 > 700 会超时（600ms），期间配置被修改
        res = run_probe(client, timeout_ms=600)
        t.join()
        assert res["status"] == "invalidated"
        assert res["max_confirmed_size"] is None
        assert "作废" in res["reason"]
        assert res["config_epoch_start"] != res["config_epoch_end"]

    def test_concurrent_probes_do_not_interfere(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        out: dict[str, dict] = {}

        def worker(name, **kw):
            out[name] = run_probe(client, **kw)

        threads = [
            threading.Thread(target=worker, args=("a",), kwargs={"timeout_ms": 200}),
            threading.Thread(
                target=worker,
                args=("b",),
                kwargs={"min_size": 576, "max_size": 900, "timeout_ms": 200},
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        a, b = out["a"], out["b"]
        assert a["probe_id"] != b["probe_id"]
        assert a["status"] == "ok" and a["max_confirmed_size"] == 1000
        assert b["status"] == "ok" and b["max_confirmed_size"] == 900
        # 各自结论只由各自探测编号下的回包得出
        assert a["stray_replies"] == 0 and b["stray_replies"] == 0

    def test_probe_result_is_stored(self, client):
        res = run_probe(client)
        r = client.get(f"/probe/{res['probe_id']}")
        assert r.status_code == 200
        assert r.json()["probe_id"] == res["probe_id"]
        listing = client.get("/probes").json()
        assert any(p["probe_id"] == res["probe_id"] for p in listing)
        assert client.get("/probe/nope").status_code == 404

    def test_probe_request_validation(self, client):
        assert client.post("/probe", json={"min_size": 1000, "max_size": 576}).status_code == 422
        assert client.post("/probe", json={"min_size": 10}).status_code == 422
        assert client.post("/probe", json={"timeout_ms": 5}).status_code == 422


class TestDocs:
    def test_docs_and_openapi(self, client):
        assert client.get("/docs").status_code == 200
        spec = client.get("/openapi.json").json()
        assert "/echo/config" in spec["paths"]
        assert "/probe" in spec["paths"]
