"""
网络流量采集模块 — 基于 Scapy 的实时抓包引擎。

职责：
    - 实时监听网络流量（支持指定网卡、BPF 过滤器）
    - 解析 TCP / UDP / ICMP 数据包的基础字段
    - 线程安全地缓存最近 N 条数据包
    - 导出为 CSV 供后续模块（parser、feature_extractor、AI 引擎）消费

对外接口：
    start_capture()      — 启动异步抓包
    stop_capture()       — 停止抓包
    get_packet_count()   — 获取已捕获数据包数量
    get_recent_packets() — 获取最近 N 条 PacketInfo
    export_csv()         — 导出缓存到 CSV 文件

与下游模块的对接：
    parser.py           — 读取 PacketInfo，做深度协议解析（HTTP/DNS/TLS）
    feature_extractor.py — 消费 PacketInfo 列表，提取 AI 所需特征向量
    AI 模块 (predictor)  — 消费 feature_extractor 输出的特征列表进行推理
"""

from __future__ import annotations

import csv
import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 可配置参数（通过模块级变量覆盖，避免写死）
# ---------------------------------------------------------------------------

DEFAULT_INTERFACE: Optional[str] = None
"""默认网卡；None 表示使用 Scapy 自动检测的默认网卡。"""

DEFAULT_FILTER: str = "ip or icmp"
"""默认 BPF 过滤器，捕获 IP 及 ICMP 流量。"""

MAX_PACKET_CACHE: int = 10000
"""流量缓存最大容量（条）。"""

MAX_RAW_CACHE: int = 2000
"""原始 Scapy 数据包缓存容量，供 parser.py 深度解析使用。"""

CSV_PATH: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic.csv")
"""CSV 导出目标路径。"""

LOG_PATH: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture.log")
"""日志文件路径。"""

# ---------------------------------------------------------------------------
# 日志系统
# ---------------------------------------------------------------------------

_logger = logging.getLogger("capture")
_logger.setLevel(logging.DEBUG)

# 防止重复添加 handler（模块 reload 场景）
if not _logger.handlers:
    _file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setLevel(logging.INFO)
    _console_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
    )

    _logger.addHandler(_file_handler)
    _logger.addHandler(_console_handler)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PacketInfo:
    """单个数据包的解析结果。

    所有字段均可为空值（None），调用方需做防御性判断。
    """

    timestamp: Optional[str] = None
    """ISO-8601 格式时间戳（UTC）。"""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    protocol_number: Optional[int] = None
    """协议号（TCP=6, UDP=17, ICMP=1），对接特征提取模块。"""

    packet_length: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        """转为字典，方便序列化与 CSV 导出。"""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def as_list(self) -> List[Any]:
        """按字段定义顺序返回列表，供特征提取使用。"""
        return [getattr(self, f.name) for f in fields(self)]


# ---------------------------------------------------------------------------
# 流量缓存（线程安全）
# ---------------------------------------------------------------------------

class PacketCache:
    """线程安全的定长数据包缓存。

    基于 ``collections.deque`` 实现，达到最大容量时自动淘汰最旧记录。
    """

    def __init__(self, maxlen: int = MAX_PACKET_CACHE) -> None:
        self._maxlen: int = maxlen
        self._deque: deque[PacketInfo] = deque(maxlen=maxlen)
        self._lock: threading.Lock = threading.Lock()

    def add(self, packet: PacketInfo) -> None:
        """追加一条数据包记录（线程安全）。"""
        with self._lock:
            self._deque.append(packet)

    def get_recent(self, count: Optional[int] = None) -> List[PacketInfo]:
        """返回最近 *count* 条记录（从旧到新）；count 为 None 时返回全部。"""
        with self._lock:
            if count is None or count >= len(self._deque):
                return list(self._deque)
            # deque 不支持切片，转 list 再取
            items = list(self._deque)
            return items[-count:]

    def clear(self) -> None:
        """清空缓存。"""
        with self._lock:
            self._deque.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._deque)


# ---------------------------------------------------------------------------
# 数据包解析
# ---------------------------------------------------------------------------

# 协议号 → 协议名映射（IP 协议号）
_IP_PROTO_TABLE: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Scapy 层名 → 统一协议名（fallback 用）
_LAYER_PROTO_MAP: Dict[str, str] = {
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP",
}


def _resolve_protocol(packet: Any) -> Optional[str]:
    """从 Scapy 数据包中解析协议名。

    策略：先查 IP 协议号 → 检查是否有 TCP/UDP/ICMP 层 → 回退到 IP 协议号表。
    """
    # 优先用 IP 层的 proto 字段
    ip_proto: Optional[int] = getattr(packet, "proto", None)
    if ip_proto is not None and ip_proto in _IP_PROTO_TABLE:
        return _IP_PROTO_TABLE[ip_proto]

    # fallback：检查 Scapy 层栈
    for layer_name, proto_name in _LAYER_PROTO_MAP.items():
        if packet.haslayer(layer_name):
            return proto_name

    # 最后回退到 IP 协议号映射（处理 SCTP/IGMP 等非主流协议）
    if ip_proto is not None:
        return _IP_PROTO_TABLE.get(ip_proto, f"IP-{ip_proto}")

    return None


def _safe_int(value: Any) -> Optional[int]:
    """安全转换为 int，失败返回 None。"""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_packet(packet: Any) -> Optional[PacketInfo]:
    """解析 Scapy 抓取的单个数据包为 ``PacketInfo``。

    支持 TCP / UDP / ICMP 三层协议。对于字段缺失的情况（如非 IP 包），
    对应字段置为 None，不会抛出异常。

    Returns:
        PacketInfo 或 None（当数据包不包含 IP 层且不包含 ICMP 层时）。
    """
    try:
        timestamp: Optional[str] = None
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol: Optional[str] = None
        protocol_number: Optional[int] = None
        packet_length: Optional[int] = None

        # 时间戳：优先用 Scapy 自带 time，其次用当前 UTC 时间
        pkt_time: Optional[float] = getattr(packet, "time", None)
        if pkt_time is not None:
            timestamp = datetime.fromtimestamp(pkt_time, tz=timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        # 包长度
        packet_length = _safe_int(getattr(packet, "len", None))

        # IP 层解析
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            src_ip = getattr(ip_layer, "src", None)
            dst_ip = getattr(ip_layer, "dst", None)
            protocol = _resolve_protocol(ip_layer)
            protocol_number = _safe_int(getattr(ip_layer, "proto", None))

            # TCP 层
            if packet.haslayer("TCP"):
                src_port = _safe_int(packet["TCP"].sport)
                dst_port = _safe_int(packet["TCP"].dport)
                if protocol is None:
                    protocol = "TCP"

            # UDP 层
            elif packet.haslayer("UDP"):
                src_port = _safe_int(packet["UDP"].sport)
                dst_port = _safe_int(packet["UDP"].dport)
                if protocol is None:
                    protocol = "UDP"

        # ICMP 层（ICMP 不承载在 IP 上时也能抓到）
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            protocol_number = 1  # ICMP 的 IP 协议号

        else:
            # 非 IP 且非 ICMP（如 ARP、IPv6 等），当前版本不处理
            return None

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            protocol_number=protocol_number,
            packet_length=packet_length,
        )

    except Exception:
        _logger.exception("解析数据包时发生未预期异常")
        return None


# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------

_cache = PacketCache(maxlen=MAX_PACKET_CACHE)
_raw_cache: deque[Any] = deque(maxlen=MAX_RAW_CACHE)
_raw_cache_lock = threading.Lock()
_sniffer_thread: Optional[threading.Thread] = None
_sniffer_lock = threading.Lock()
_stop_event = threading.Event()

# 统计标志
_start_time: Optional[float] = None
_stop_time: Optional[float] = None


# ---------------------------------------------------------------------------
# 回调函数
# ---------------------------------------------------------------------------

def _packet_callback(packet: Any) -> None:
    """Scapy sniff 的回调：解析 → 缓存。"""
    # 缓存原始 Scapy 数据包供 parser.py 使用
    with _raw_cache_lock:
        _raw_cache.append(packet)

    info = parse_packet(packet)
    if info is not None:
        _cache.add(info)


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------

def start_capture(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    timeout: Optional[int] = None,
    iface: Optional[str] = None,
) -> None:
    """启动异步抓包。

    Args:
        interface: 网卡名称，为 None 时使用 ``DEFAULT_INTERFACE``（即 Scapy 默认）。
        bpf_filter: BPF 过滤表达式，为 None 时使用 ``DEFAULT_FILTER``。
        timeout: 抓包超时（秒），为 None 时持续运行直到手动 stop。
        iface: ``interface`` 的别名，与 Scapy 参数名保持一致。

    Raises:
        RuntimeError: 抓包已在运行时重复调用。
    """
    global _sniffer_thread, _start_time, _stop_time

    with _sniffer_lock:
        if _sniffer_thread is not None and _sniffer_thread.is_alive():
            raise RuntimeError("抓包已在运行中，请先调用 stop_capture()")

        # iface 与 interface 二选一，iface 优先级更高
        _iface = iface if iface is not None else interface
        _iface = _iface if _iface is not None else DEFAULT_INTERFACE
        bp_filter = bpf_filter if bpf_filter is not None else DEFAULT_FILTER

        _logger.info("启动抓包 | iface=%s | filter=%s | timeout=%s",
                      _iface or "<default>", bp_filter, timeout)
        _logger.info("缓存容量: %d 条", MAX_PACKET_CACHE)

        _start_time = time.time()
        _stop_time = None
        _stop_event.clear()

        from scapy.all import sniff  # type: ignore[import-untyped]

        def _run_sniff() -> None:
            """在后台线程中运行 sniff，通过 stop_event 控制退出。"""
            try:
                sniff(
                    iface=_iface,
                    filter=bp_filter,
                    prn=_packet_callback,
                    store=False,
                    timeout=None,  # 不设空闲超时，完全由 stop_event 控制
                    stop_filter=lambda p: _stop_event.is_set(),
                )
            except Exception:
                _logger.exception("后台抓包线程异常退出")
            finally:
                _logger.debug("抓包线程已退出")

        _sniffer_thread = threading.Thread(target=_run_sniff, daemon=True, name="scapy-sniff")
        _sniffer_thread.start()


def stop_capture() -> None:
    """停止抓包并等待后台线程退出。"""
    global _sniffer_thread, _stop_time

    with _sniffer_lock:
        if _sniffer_thread is None:
            _logger.warning("stop_capture() 调用时无活跃抓包实例")
            return

        _logger.info("正在停止抓包…")
        _stop_event.set()

        # 等待后台 sniff 线程退出（最多等待 5 秒）
        _sniffer_thread.join(timeout=5)

        _stop_time = time.time()
        duration = _stop_time - _start_time if _start_time else 0
        _logger.info("抓包已停止 | 共捕获 %d 条数据包 | 运行 %.1f 秒",
                      len(_cache), duration)
        _sniffer_thread = None


def get_packet_count() -> int:
    """返回当前缓存中的数据包数量。"""
    return len(_cache)


def get_recent_packets(count: Optional[int] = None) -> List[PacketInfo]:
    """获取最近 *count* 条 ``PacketInfo``。

    Args:
        count: 获取条数，为 None 时返回缓存中全部数据。

    Returns:
        PacketInfo 列表（从旧到新）。
    """
    return _cache.get_recent(count)


def export_csv(path: Optional[str] = None, flush_cache: bool = False) -> str:
    """将缓存中的数据包导出为 CSV 文件。

    Args:
        path: 目标文件路径，为 None 时使用 ``CSV_PATH``。
        flush_cache: 是否在导出后清空缓存。

    Returns:
        实际写入的文件绝对路径。

    Raises:
        IOError: 文件写入失败。
    """
    target = path if path is not None else CSV_PATH
    packets = _cache.get_recent()

    _logger.info("导出 CSV | 路径=%s | 数据量=%d 条", target, len(packets))

    try:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)

        with open(target, mode="w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["timestamp", "src_ip", "dst_ip", "src_port",
                            "dst_port", "protocol", "protocol_number", "packet_length"],
            )
            writer.writeheader()
            for pkt in packets:
                writer.writerow(pkt.as_dict())

        _logger.info("CSV 导出完成 → %s", os.path.abspath(target))
    except IOError:
        _logger.exception("CSV 写入失败: %s", target)
        raise

    if flush_cache:
        _cache.clear()
        _logger.info("缓存已清空")

    return os.path.abspath(target)


def is_running() -> bool:
    """返回抓包是否正在运行。"""
    with _sniffer_lock:
        return _sniffer_thread is not None and _sniffer_thread.is_alive()


def get_statistics() -> Dict[str, Any]:
    """返回当前抓包统计信息。"""
    now = time.time()
    packet_count = len(_cache)
    stats: Dict[str, Any] = {
        "running": is_running(),
        "packet_count": packet_count,
        "cache_capacity": MAX_PACKET_CACHE,
    }
    if _start_time is not None:
        stats["start_time"] = datetime.fromtimestamp(_start_time, tz=timezone.utc).isoformat()
        if _stop_time is not None:
            elapsed = _stop_time - _start_time
        else:
            elapsed = now - _start_time
        stats["elapsed_seconds"] = round(elapsed, 2)
        if elapsed > 0:
            stats["packets_per_second"] = round(packet_count / elapsed, 2)
    return stats


# ---------------------------------------------------------------------------
# 与下游模块的对接接口
# ---------------------------------------------------------------------------

def get_recent_raw_packets(count: Optional[int] = None) -> List[Any]:
    """为 ``parser.py`` 提供最近 *count* 条原始 Scapy 数据包。

    Args:
        count: 获取条数，为 None 时返回全部。

    Returns:
        Scapy Packet 对象列表（从旧到新）。
    """
    with _raw_cache_lock:
        if count is None or count >= len(_raw_cache):
            return list(_raw_cache)
        items = list(_raw_cache)
        return items[-count:]


def get_packets_for_feature_extraction(count: int = 100) -> List[PacketInfo]:
    """为 ``feature_extractor.py`` 提供最近 N 条数据包。

    feature_extractor 可消费此接口，将 ``PacketInfo`` 列表转换为
    AI 引擎所需的特征向量（字段: src_port, dst_port, protocol, pkt_len, duration）。
    """
    return _cache.get_recent(count)


def get_packets_as_dicts(count: Optional[int] = None) -> List[Dict[str, Any]]:
    """以字典列表形式返回数据包，方便 pandas 或 JSON 序列化。"""
    return [p.as_dict() for p in _cache.get_recent(count)]


# ---------------------------------------------------------------------------
# main — 启动 30 秒抓包演示
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-IDS 网络流量采集模块 — 演示程序",
    )
    parser.add_argument(
        "-i", "--interface",
        default=DEFAULT_INTERFACE,
        help=f"监听的网卡（默认: {'自动检测' if DEFAULT_INTERFACE is None else DEFAULT_INTERFACE}）",
    )
    parser.add_argument(
        "-f", "--filter",
        default=DEFAULT_FILTER,
        help=f"BPF 过滤器（默认: {DEFAULT_FILTER}）",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="运行时长（秒），默认 30",
    )
    parser.add_argument(
        "-o", "--output",
        default=CSV_PATH,
        help=f"CSV 导出路径（默认: {CSV_PATH}）",
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="不导出 CSV",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  AI-IDS 网络流量采集模块")
    print("=" * 60)

    # 快速自检
    try:
        from scapy.all import sniff  # noqa: F401
    except ImportError:
        print("\n⚠️  未检测到 Scapy，请先安装：")
        print("    pip install scapy")
        print("    Windows 用户还需安装 Npcap: https://npcap.com/\n")
        sys.exit(1)

    print(f"\n网卡      : {args.interface or '<自动检测>'}")
    print(f"BPF 过滤  : {args.filter}")
    print(f"运行时长  : {args.timeout} 秒")
    print(f"缓存容量  : {MAX_PACKET_CACHE} 条")
    print(f"CSV 路径  : {args.output}")
    print(f"日志路径  : {LOG_PATH}\n")

    # 启动抓包
    start_capture(interface=args.interface, bpf_filter=args.filter, timeout=args.timeout)

    print(f"抓包运行中，{args.timeout} 秒后自动停止…\n")
    try:
        # 等待期间定期输出统计
        check_interval = 5
        remaining = args.timeout
        while remaining > 0 and is_running():
            time.sleep(min(check_interval, remaining))
            remaining -= check_interval
            count = get_packet_count()
            print(f"  [统计] 已捕获: {count} 条 | 剩余: {max(remaining, 0)} 秒")
    except KeyboardInterrupt:
        print("\n用户中断（Ctrl+C）")

    stop_capture()

    total = get_packet_count()
    print(f"\n✅ 抓包完成，共捕获 {total} 条数据包")

    if not args.no_export:
        exported_path = export_csv(args.output)
        print(f"📁 CSV 已导出至: {exported_path}")

    # 打印统计
    stats = get_statistics()
    print(f"\n统计信息:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # 打印前 5 条数据预览
    recent = get_recent_packets(5)
    if recent:
        print(f"\n前 {len(recent)} 条数据预览:")
        print("-" * 80)
        print(f"{'时间':<26} {'源IP':<16} {'目的IP':<16} {'源端口':<8} {'目的端口':<8} {'协议':<6} {'协议号':<6} {'长度'}")
        print("-" * 88)
        for pkt in recent:
            proto_num = str(pkt.protocol_number) if pkt.protocol_number is not None else '-'
            print(
                f"{pkt.timestamp or 'N/A':<26} "
                f"{pkt.src_ip or 'N/A':<16} "
                f"{pkt.dst_ip or 'N/A':<16} "
                f"{str(pkt.src_port) if pkt.src_port else '-':<8} "
                f"{str(pkt.dst_port) if pkt.dst_port else '-':<8} "
                f"{pkt.protocol or 'N/A':<6} "
                f"{proto_num:<6} "
                f"{pkt.packet_length if pkt.packet_length else '-'}"
            )
    else:
        print("\n⚠️  未捕获到任何数据包。请确认：")
        print("   1. 是否以管理员权限运行")
        print("   2. 网卡是否存在流量")
        print("   3. BPF 过滤器是否过于严格")
