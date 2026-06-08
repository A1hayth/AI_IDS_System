"""
深度协议解析模块 — 对 Scapy 原始数据包进行逐层解析。

职责:
    - IP  层: 提取 src_ip / dst_ip / ttl
    - TCP 层: 提取端口、flags（SYN/ACK/FIN/RST 等）
    - UDP 层: 提取端口
    - ICMP层: 识别 Echo Request / Echo Reply
    - HTTP层: 解析 method / host / uri / user_agent / payload
    - TLS 层: 识别 Client Hello / Server Hello（不解密）

在 capture.py 与 feature_extractor.py 之间承上启下:
    capture.py  ──raw packets──▶  parser.py  ──ParsedPacket──▶  feature_extractor.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import textwrap
from dataclasses import dataclass, fields
from typing import Any, Dict, List, Optional, Tuple

# 确保可以导入 capture 模块
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ---------------------------------------------------------------------------
# 可配置参数
# ---------------------------------------------------------------------------

LOG_PATH: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parser.log")
"""日志文件路径。"""

MAX_PAYLOAD_LENGTH: int = 2000
"""Payload 最大保存字符数。"""

# ---------------------------------------------------------------------------
# 日志系统
# ---------------------------------------------------------------------------

_logger = logging.getLogger("parser")
_logger.setLevel(logging.DEBUG)

if not _logger.handlers:
    _fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    _ch = logging.StreamHandler(sys.stdout)
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S",
    ))

    _logger.addHandler(_fh)
    _logger.addHandler(_ch)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ParsedPacket:
    """经过深度解析的数据包。

    分为三组字段:
        - 网络层:  timestamp, src_ip, dst_ip, ttl
        - 传输层:  src_port, dst_port, protocol, packet_length, tcp_flags
        - 应用层:  http_method, http_host, http_uri, user_agent, payload, is_http, is_https
    """

    # -- 网络层 --
    timestamp: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None

    # -- 传输层 --
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None       # TCP | UDP | ICMP | HTTP | HTTPS | UNKNOWN
    protocol_number: Optional[int] = None  # 协议号（TCP=6, UDP=17, ICMP=1）
    packet_length: Optional[int] = None
    tcp_flags: Optional[str] = None      # "SYN" | "SYN,ACK" | "FIN,ACK" | ...

    # -- 应用层 --
    http_method: Optional[str] = None    # GET | POST | PUT | DELETE | HEAD | OPTIONS
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    user_agent: Optional[str] = None
    payload: Optional[str] = None        # 原始载荷（截断至 2000 字符）
    is_http: bool = False
    is_https: bool = False

    # -- 统计标记 --
    _parse_errors: int = 0
    """非序列化字段，仅用于内部追踪。"""

    def to_dict(self) -> Dict[str, Any]:
        """转为字典（跳过私有字段）。"""
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if not f.name.startswith("_")
        }

    def to_json(self, indent: int = 2) -> str:
        """转为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _safe_int(value: Any) -> Optional[int]:
    """安全转 int。"""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_str(value: Any, max_len: int = MAX_PAYLOAD_LENGTH) -> Optional[str]:
    """安全字节流转 UTF-8 字符串，截断到 max_len。"""
    if value is None:
        return None
    try:
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = str(value)
        return text[:max_len] if len(text) > max_len else text
    except Exception:
        return None


def _strip_null(value: Optional[str]) -> Optional[str]:
    """去除字符串中的 null 字符和首尾空白。"""
    if value is None:
        return None
    return value.replace("\x00", "").strip() or None


# ---------------------------------------------------------------------------
# TCP Flags 解析
# ---------------------------------------------------------------------------

# Scapy 短标记 → 全名映射
_SCAPY_FLAG_CHAR: Dict[str, str] = {
    "S": "SYN",
    "A": "ACK",
    "F": "FIN",
    "R": "RST",
    "P": "PSH",
    "U": "URG",
}


def _parse_tcp_flags(flags_value: Any) -> Optional[str]:
    """将 Scapy TCP flags 转为可读字符串，如 "SYN,ACK"。

    Scapy 的 ``TCP.flags`` 返回 FlagValue 类型:
        - str() 得到短标记串如 'S', 'SA', 'PA'
        - int() 得到位掩码: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
    """
    if flags_value is None:
        return None

    try:
        v = int(flags_value)
    except (TypeError, ValueError):
        return None
    if v == 0:
        return None

    # 优先用 Scapy 短标记转换（如 'SA' → 'SYN,ACK'）
    raw_str = str(flags_value).strip()
    if raw_str and set(raw_str).issubset(set("S AFRPU")):
        mapped = [_SCAPY_FLAG_CHAR.get(c, c) for c in raw_str]
        return ",".join(mapped)

    # 备选：按位掩码解码
    _BIT_MAP: List[Tuple[int, str]] = [
        (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
        (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
    ]
    names = [name for mask, name in _BIT_MAP if v & mask]
    return ",".join(names) if names else None


# ---------------------------------------------------------------------------
# HTTP 解析
# ---------------------------------------------------------------------------

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"})


def _parse_http_request(raw_data: bytes) -> Dict[str, Optional[str]]:
    """从 HTTP 请求的原始字节中提取 method / host / uri / user_agent。

    安全解析，失败返回空字典。
    """
    result: Dict[str, Optional[str]] = {
        "method": None,
        "host": None,
        "uri": None,
        "user_agent": None,
    }
    try:
        text = raw_data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return result

        # 请求行: GET /path HTTP/1.1
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) >= 2:
            method = parts[0].upper()
            if method in _HTTP_METHODS:
                result["method"] = method
            result["uri"] = _strip_null(parts[1]) or result["uri"]

        # 头部字段
        for line in lines[1:]:
            if not line.strip():
                break
            if ":" in line:
                key, _, val = line.partition(":")
                kl = key.strip().lower().replace("\x00", "")
                vl = val.strip().replace("\x00", "")
                if kl == "host" and vl:
                    result["host"] = _strip_null(vl)
                elif kl == "user-agent" and vl:
                    result["user_agent"] = _strip_null(vl)

    except Exception:
        _logger.debug("HTTP 请求行解析未成功")

    return result


# ---------------------------------------------------------------------------
# TLS 检测
# ---------------------------------------------------------------------------

def _is_tls_handshake(payload: bytes) -> Tuple[bool, Optional[str]]:
    """检测 TLS 握手类型。

    TLS Record 格式 (RFC 5246):
        byte 0:     content_type (22 = Handshake)
        bytes 1-2:  version
        bytes 3-4:  length
        byte 5:     handshake_type (1 = ClientHello, 2 = ServerHello)

    Returns:
        (is_tls, handshake_label)
    """
    if len(payload) < 6:
        return False, None

    content_type = payload[0]
    if content_type != 22:  # TLS Handshake
        return False, None

    try:
        handshake_type = payload[5]
        if handshake_type == 1:
            return True, "Client Hello"
        elif handshake_type == 2:
            return True, "Server Hello"
        return True, f"Handshake({handshake_type})"
    except IndexError:
        return False, None


# ---------------------------------------------------------------------------
# PacketParser
# ---------------------------------------------------------------------------

class PacketParser:
    """深度协议解析器。

    对 Scapy 原始 Packet 进行逐层解析，输出统一的 ``ParsedPacket``。
    所有子解析方法均保护在 try/except 内，单个解析失败不影响整体。
    """

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "http": 0,
            "https": 0,
            "unknown": 0,
            "parse_errors": 0,
        }

    # ---- 主入口 ----------------------------------------------------------

    def parse_packet(self, packet: Any) -> ParsedPacket:
        """解析单个 Scapy 数据包为 ``ParsedPacket``。"""
        result = ParsedPacket()
        self._counters["total"] += 1

        try:
            # 时间戳
            pkt_time = getattr(packet, "time", None)
            if pkt_time is not None:
                from datetime import datetime, timezone
                result.timestamp = datetime.fromtimestamp(float(pkt_time), tz=timezone.utc).isoformat()

            # 包长度
            result.packet_length = _safe_int(getattr(packet, "len", None))

            # 逐层解析
            self._parse_ip(packet, result)
            self._parse_transport(packet, result)
            self._parse_application(packet, result)
            self._resolve_protocol(result)

        except Exception:
            _logger.exception("parse_packet 顶层异常")
            self._counters["parse_errors"] += 1
            result._parse_errors += 1

        return result

    def parse_packets(self, packets: List[Any]) -> List[ParsedPacket]:
        """批量解析，过滤掉完全无法解析的包。"""
        results: List[ParsedPacket] = []
        for pkt in packets:
            parsed = self.parse_packet(pkt)
            # 至少有一个非空字段才保留
            if parsed.src_ip or parsed.protocol or parsed.packet_length:
                results.append(parsed)
        _logger.info("批量解析完成 | 输入=%d | 有效=%d", len(packets), len(results))
        return results

    # ---- IP 层 ----------------------------------------------------------

    def _parse_ip(self, packet: Any, result: ParsedPacket) -> None:
        """提取 IP 层字段（含协议号）。"""
        if not packet.haslayer("IP"):
            return
        try:
            ip = packet["IP"]
            result.src_ip = getattr(ip, "src", None)
            result.dst_ip = getattr(ip, "dst", None)
            result.ttl = _safe_int(getattr(ip, "ttl", None))
            result.protocol_number = _safe_int(getattr(ip, "proto", None))
        except Exception:
            _logger.debug("IP 层解析失败", exc_info=True)

    # ---- 传输层 ----------------------------------------------------------

    def _parse_transport(self, packet: Any, result: ParsedPacket) -> None:
        """根据传输层协议分发解析。"""
        if packet.haslayer("TCP"):
            self._parse_tcp(packet, result)
        elif packet.haslayer("UDP"):
            self._parse_udp(packet, result)
        elif packet.haslayer("ICMP"):
            self._parse_icmp(packet, result)

    def _parse_tcp(self, packet: Any, result: ParsedPacket) -> None:
        """TCP 层解析。"""
        try:
            tcp = packet["TCP"]
            result.src_port = _safe_int(tcp.sport)
            result.dst_port = _safe_int(tcp.dport)
            result.tcp_flags = _parse_tcp_flags(getattr(tcp, "flags", None))
            result.protocol = "TCP"
            self._counters["tcp"] += 1
        except Exception:
            _logger.debug("TCP 层解析失败", exc_info=True)

    def _parse_udp(self, packet: Any, result: ParsedPacket) -> None:
        """UDP 层解析。"""
        try:
            udp = packet["UDP"]
            result.src_port = _safe_int(udp.sport)
            result.dst_port = _safe_int(udp.dport)
            result.protocol = "UDP"
            self._counters["udp"] += 1
        except Exception:
            _logger.debug("UDP 层解析失败", exc_info=True)

    def _parse_icmp(self, packet: Any, result: ParsedPacket) -> None:
        """ICMP 层解析，识别 Echo Request / Echo Reply。"""
        try:
            icmp = packet["ICMP"]
            icmp_type = _safe_int(getattr(icmp, "type", None))
            if icmp_type == 8:
                result.protocol = "ICMP Echo Request"
            elif icmp_type == 0:
                result.protocol = "ICMP Echo Reply"
            else:
                result.protocol = f"ICMP(type={icmp_type})"
            self._counters["icmp"] += 1
        except Exception:
            result.protocol = "ICMP"
            self._counters["icmp"] += 1

    # ---- 应用层 ----------------------------------------------------------

    def _parse_application(self, packet: Any, result: ParsedPacket) -> None:
        """应用层解析分发。"""
        # 仅 TCP 可能承载 HTTP/TLS
        if not packet.haslayer("TCP"):
            return

        port = result.dst_port or result.src_port

        # HTTPS 检测
        if self._detect_https(packet, result, port):
            return

        # HTTP 检测
        self._detect_http(packet, result, port)

    def _detect_https(self, packet: Any, result: ParsedPacket, port: Optional[int]) -> bool:
        """检测 TLS/HTTPS 流量。"""
        is_tls = False
        label: Optional[str] = None

        # 端口判断
        if port == 443:
            is_tls = True

        # Raw 层 TLS 握手检测
        if packet.haslayer("Raw"):
            try:
                raw_load = bytes(packet["Raw"].load)
                detected, label = _is_tls_handshake(raw_load)
                if detected:
                    is_tls = True
            except Exception:
                pass

        if is_tls:
            result.is_https = True
            result.protocol = "HTTPS"
            result.payload = _safe_str(label) if label else "TLS"
            self._counters["https"] += 1
            return True
        return False

    def _detect_http(self, packet: Any, result: ParsedPacket, port: Optional[int]) -> None:
        """检测并解析 HTTP 请求。"""
        if not packet.haslayer("Raw"):
            return

        try:
            raw_load = bytes(packet["Raw"].load)
        except Exception:
            return

        http_info = _parse_http_request(raw_load)
        method = http_info.get("method")

        if method is not None:
            result.is_http = True
            result.http_method = method
            result.http_host = http_info.get("host")
            result.http_uri = http_info.get("uri")
            result.user_agent = http_info.get("user_agent")
            result.payload = _safe_str(raw_load)
            result.protocol = "HTTP"
            self._counters["http"] += 1

        elif port in (80, 8080, 8000):
            # 常见 HTTP 端口但未识别出请求行，保留 Payload
            result.payload = _safe_str(raw_load)

    # ---- 协议判定 ---------------------------------------------------------

    def _resolve_protocol(self, result: ParsedPacket) -> None:
        """统合协议标签。"""
        if result.is_https:
            result.protocol = "HTTPS"
        elif result.is_http:
            result.protocol = "HTTP"
        elif result.protocol is None and result.src_ip is not None:
            result.protocol = "UNKNOWN"
            self._counters["unknown"] += 1

    # ---- 工具方法 ---------------------------------------------------------

    @staticmethod
    def to_dict(parsed: ParsedPacket) -> Dict[str, Any]:
        """ParsedPacket → dict。"""
        return parsed.to_dict()

    @staticmethod
    def to_json(parsed: ParsedPacket, indent: int = 2) -> str:
        """ParsedPacket → JSON 字符串。"""
        return parsed.to_json(indent=indent)

    @property
    def statistics(self) -> Dict[str, Any]:
        """返回解析统计。"""
        total = self._counters["total"]
        return {
            "total_parsed": total,
            "tcp": self._counters["tcp"],
            "udp": self._counters["udp"],
            "icmp": self._counters["icmp"],
            "http": self._counters["http"],
            "https": self._counters["https"],
            "unknown": self._counters["unknown"],
            "parse_errors": self._counters["parse_errors"],
            "http_ratio": round(self._counters["http"] / total, 4) if total > 0 else 0,
            "https_ratio": round(self._counters["https"] / total, 4) if total > 0 else 0,
        }


# ---------------------------------------------------------------------------
# 便捷函数 — 供 feature_extractor 与 SQL 检测模块调用
# ---------------------------------------------------------------------------

def extract_features(parsed: ParsedPacket) -> Dict[str, Any]:
    """从 ParsedPacket 提取 feature_extractor.py 所需的单包特征字段。

    对应 ``config.SELECTED_FEATURES``:
        Destination Port, Protocol, Flow Duration,
        Total Fwd Packets, Total Backward Packets,
        Fwd Packet Length Max, Bwd Packet Length Max

    注: 流级特征（Duration / Fwd/Bwd Packets / Max Lengths）需由
    feature_extractor 在时间窗口内按 (src_ip, dst_ip, src_port, dst_port, protocol)
    分组聚合计算。
    """
    return {
        "src_ip": parsed.src_ip,
        "dst_ip": parsed.dst_ip,
        "src_port": parsed.src_port,
        "dst_port": parsed.dst_port,
        "protocol": parsed.protocol,
        "protocol_number": parsed.protocol_number,
        "packet_length": parsed.packet_length,
        "ttl": parsed.ttl,
        "tcp_flags": parsed.tcp_flags,
        "timestamp": parsed.timestamp,
    }


def extract_sql_fields(parsed: ParsedPacket) -> Dict[str, Optional[str]]:
    """从 ParsedPacket 提取 SQL 注入检测模块所需字段。

    供后续 sql_detector.py 使用:
        http_method, http_uri, payload, user_agent
    """
    return {
        "http_method": parsed.http_method,
        "http_uri": parsed.http_uri,
        "payload": parsed.payload,
        "user_agent": parsed.user_agent,
    }


# ---------------------------------------------------------------------------
# main — 从 capture.py 读取数据包进行解析演示
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(
        description="AI-IDS 深度协议解析模块 — 演示程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            用法示例:
              # 从正在运行的抓包中获取最近 50 个原始包并解析
              python parser.py -n 50

              # 指定 capture.py 所在的路径
              python parser.py -n 100 --source capture
        """),
    )
    parser.add_argument("-n", "--count", type=int, default=50, help="解析数据包数量 (默认 50)")
    parser.add_argument("-j", "--json", action="store_true", help="以 JSON 格式输出")
    args = parser.parse_args()

    print("=" * 60)
    print("  AI-IDS 深度协议解析模块")
    print("=" * 60)

    # 从 capture 模块获取原始数据包
    try:
        from capture import get_recent_raw_packets, get_packet_count

        total_captured = get_packet_count()
        raw_packets = get_recent_raw_packets(args.count)

        print(f"\ncapture 模块状态: 缓存中有 {total_captured} 条 PacketInfo")
        print(f"获取到 {len(raw_packets)} 个原始 Scapy 数据包")
    except ImportError:
        print("\n[!] 无法导入 capture 模块，使用模拟数据演示...")
        # 构造模拟包用于演示
        from scapy.all import IP, TCP, Raw

        raw_packets = [
            IP(src="192.168.1.100", dst="93.184.216.34", ttl=64)
            / TCP(sport=54321, dport=80, flags="PA")
            / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
            IP(src="10.0.0.1", dst="10.0.0.2", ttl=128)
            / TCP(sport=443, dport=54322, flags="SA"),
            IP(src="192.168.1.1", dst="8.8.8.8", ttl=64)
            / TCP(sport=12345, dport=443, flags="S"),
            IP(src="10.0.0.3", dst="10.0.0.4", ttl=64)
            / TCP(sport=80, dport=49152, flags="A")
            / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
            IP(src="172.16.0.1", dst="172.16.0.2", ttl=62)
            / TCP(sport=9999, dport=8080, flags="PA")
            / Raw(load=b"POST /login HTTP/1.1\r\nHost: test.com\r\nUser-Agent: curl/7.88\r\n\r\nuser=admin&pass=123"),
        ]
        print(f"使用 {len(raw_packets)} 个模拟数据包\n")

    if not raw_packets:
        print("\n[!] 没有可解析的数据包。请先运行 capture.py 开始抓包。")
        print("  示例：python capture.py -t 30")
        sys.exit(0)

    # 解析
    pparser = PacketParser()
    parsed = pparser.parse_packets(raw_packets)

    print(f"\n解析结果 ({len(parsed)} 条有效):\n")

    if args.json:
        # JSON 批量输出
        json_list = [p.to_dict() for p in parsed]
        print(json.dumps(json_list, ensure_ascii=False, indent=2))
    else:
        # 表格输出
        header = (
            f"{'时间':<22} {'源IP:端口':<26} {'目的IP:端口':<26} {'协议':<8} "
            f"{'长度':<6} {'TTL':<4} {'Flags':<12} {'HTTP':<6} {'URI':<30}"
        )
        print(header)
        print("-" * len(header))
        for p in parsed:
            ts = (p.timestamp or "")[-8:]  # 只显示时间部分
            src = f"{p.src_ip or '-'}:{p.src_port or '-'}"
            # 截断 IP:Port
            if len(src) > 25:
                src = src[:22] + "..."
            dst = f"{p.dst_ip or '-'}:{p.dst_port or '-'}"
            if len(dst) > 25:
                dst = dst[:22] + "..."
            proto = p.protocol or "-"
            pkt_len = str(p.packet_length) if p.packet_length else "-"
            ttl = str(p.ttl) if p.ttl else "-"
            flags = p.tcp_flags or "-"
            method = p.http_method or "-"
            uri = (p.http_uri or "")[:29] if p.http_uri else "-"

            print(
                f"{ts:<22} {src:<26} {dst:<26} {proto:<8} "
                f"{pkt_len:<6} {ttl:<4} {flags:<12} {method:<6} {uri:<30}"
            )

    # 统计信息
    stats = pparser.statistics
    print(f"\n解析统计:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # 展示 JSON 示例
    if parsed and not args.json:
        print(f"\n第一条数据包 JSON 示例:")
        print(pparser.to_json(parsed[0]))

    print(f"\n日志文件: {LOG_PATH}")
