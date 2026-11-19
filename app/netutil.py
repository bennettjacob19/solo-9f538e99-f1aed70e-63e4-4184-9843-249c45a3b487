"""socket 工具：设置 DF（Don't Fragment）位，禁止 IP 分片。"""
from __future__ import annotations

import socket

# Linux 常量兜底（某些 Python 构建未导出）
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)


def set_dont_fragment(sock) -> bool:  # noqa: ANN001, ANN201
    """对 IPv4 UDP socket 设置 PMTUDISC_DO（DF=1）。

    设置后内核不会对本 socket 发出的报文做 IP 分片；
    若报文超过路径 MTU，发送将直接失败（EMSGSIZE），由上层按发送失败处理。
    返回是否设置成功（非 Linux 平台可能不支持，调用方应如实记录）。

    接受真实 socket 或 asyncio 的 TransportSocket（鸭子类型）。
    """
    if getattr(sock, "family", None) != socket.AF_INET:
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        return True
    except (OSError, AttributeError):
        return False
