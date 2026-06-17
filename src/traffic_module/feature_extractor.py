"""
流特征提取模块 (v3) — 将逐包 ParsedPacket 聚合为 AI 就绪的 Flow 特征。

v3 更新:
    - 特征从 6 维扩展到 15 维
    - 新增：平均包长、流速率、包到达间隔、TCP 标志计数
    - _FlowRecord 内部使用增量统计（避免大列表内存占用）

职责:
    - 按五元组 (src_ip, dst_ip, src_port, dst_port, protocol) 建立双向 Flow
    - 逐包更新 Flow 统计量
    - 超时回收 / TCP FIN 自动关闭 Flow
    - 导出符合 AI 模型输入格式的特征 CSV

数据流:
    parser.py  ──ParsedPacket──▶  feature_extractor.py  ──FlowFeature──▶  AI 引擎

输出字段（15 维，与 config.py MODEL_FEATURE_COLUMNS 严格一致）:
    基础 (6):
        Protocol, Flow_Duration, Total_Fwd_Packets, Total_Backward_Packets,
        Fwd_Packet_Length_Max, Bwd_Packet_Length_Max
    扩展 (9):
        Fwd_Packet_Length_Mean, Bwd_Packet_Length_Mean,
        Flow_Bytes_Per_Sec, Flow_Packets_Per_Sec,
        Fwd_IAT_Mean, Bwd_IAT_Mean,
        SYN_Flag_Count, FIN_Flag_Count, RST_Flag_Count
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, fields as dc_fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 可配置参数
# ---------------------------------------------------------------------------

FLOW_TIMEOUT: float = 60.0
"""Flow 空闲超时（秒），超时后 Flow 自动关闭。"""

MAX_ACTIVE_FLOWS: int = 10000
"""活跃 Flow 最大数量，超过后强制回收最旧的已完成 Flow。"""

CSV_PATH: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exports", "flow_features.csv")
"""特征 CSV 导出路径。"""

LOG_PATH: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "feature_extractor.log")
"""日志文件路径。"""

# ---------------------------------------------------------------------------
# 协议号常量
# ---------------------------------------------------------------------------

PROTO_TCP: int = 6
PROTO_UDP: int = 17
PROTO_ICMP: int = 1

# ICMP 无端口，用占位值
_ICMP_PORT_PLACEHOLDER: int = 0

# ---------------------------------------------------------------------------
# 日志系统
# ---------------------------------------------------------------------------

_logger = logging.getLogger("feature_extractor")
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
# 内部工具
# ---------------------------------------------------------------------------

def _parse_timestamp(ts: Any) -> Optional[float]:
    """将 timestamp 统一转为 epoch 浮点秒数。"""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _port_or_zero(port: Any) -> int:
    """将端口转为 int，None 返回 0（ICMP 等无端口协议）。"""
    if port is None:
        return _ICMP_PORT_PLACEHOLDER
    try:
        return int(port)
    except (TypeError, ValueError):
        return _ICMP_PORT_PLACEHOLDER


# ---------------------------------------------------------------------------
# 流 Key — 双向归一化
# ---------------------------------------------------------------------------

FlowKey = Tuple[str, str, int, int, int]


def make_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,
) -> FlowKey:
    """构造双向归一化的 Flow Key。

    通过排序 IP 和端口，使得 A→B 与 B→A 映射到同一 key。
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    else:
        return (dst_ip, src_ip, dst_port, src_port, protocol)


def is_forward(
    parsed_src_ip: str,
    parsed_src_port: int,
    flow_src_ip: str,
    flow_src_port: int,
    flow_dst_ip: str,
    flow_dst_port: int,
) -> bool:
    """判断该包属于 Flow 的前向还是后向。"""
    if (parsed_src_ip, parsed_src_port) == (flow_src_ip, flow_src_port):
        return True
    if (parsed_src_ip, parsed_src_port) == (flow_dst_ip, flow_dst_port):
        return False
    return parsed_src_ip == flow_src_ip


# ---------------------------------------------------------------------------
# 内部流记录 (v3: 扩展至 15 维特征追踪)
# ---------------------------------------------------------------------------

@dataclass
class _FlowRecord:
    """内部 Flow 状态，跟踪双向统计量（含增量 IAT 追踪）。"""

    key: FlowKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float = 0.0
    last_seen: float = 0.0

    # --- 基础统计 ---
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_pkt_len_max: float = 0.0
    bwd_pkt_len_max: float = 0.0

    # --- v3 新增: 扩展统计 ---
    fwd_pkt_len_sum: float = 0.0       # 前向包长总和（用于计算均值）
    bwd_pkt_len_sum: float = 0.0       # 后向包长总和
    fwd_last_time: float = 0.0         # 上一个前向包到达时间（用于 IAT）
    bwd_last_time: float = 0.0         # 上一个后向包到达时间
    fwd_iat_sum: float = 0.0           # 前向 IAT 累加
    bwd_iat_sum: float = 0.0           # 后向 IAT 累加
    fwd_iat_count: int = 0             # 前向 IAT 样本数
    bwd_iat_count: int = 0             # 后向 IAT 样本数
    syn_count: int = 0                 # SYN 标志计数
    fin_count: int = 0                 # FIN 标志计数
    rst_count: int = 0                 # RST 标志计数

    # --- 状态 ---
    is_closed: bool = False
    close_reason: str = ""
    flow_id: str = ""

    def update(self, parsed: Any, pkt_ts: float, pkt_len: float) -> None:
        """根据一个 ParsedPacket 更新统计量（含 v3 扩展）。"""
        self.last_seen = pkt_ts

        forward = is_forward(
            parsed.src_ip or "",
            _port_or_zero(parsed.src_port),
            self.src_ip, self.src_port,
            self.dst_ip, self.dst_port,
        )

        if forward:
            self.fwd_packets += 1
            self.fwd_pkt_len_sum += pkt_len
            if pkt_len > self.fwd_pkt_len_max:
                self.fwd_pkt_len_max = pkt_len

            # 前向 IAT（增量计算）
            if self.fwd_last_time > 0:
                iat = pkt_ts - self.fwd_last_time
                if iat >= 0:
                    self.fwd_iat_sum += iat
                    self.fwd_iat_count += 1
            self.fwd_last_time = pkt_ts
        else:
            self.bwd_packets += 1
            self.bwd_pkt_len_sum += pkt_len
            if pkt_len > self.bwd_pkt_len_max:
                self.bwd_pkt_len_max = pkt_len

            # 后向 IAT（增量计算）
            if self.bwd_last_time > 0:
                iat = pkt_ts - self.bwd_last_time
                if iat >= 0:
                    self.bwd_iat_sum += iat
                    self.bwd_iat_count += 1
            self.bwd_last_time = pkt_ts

        # TCP 标志计数
        if self.protocol == PROTO_TCP:
            tcp_flags = getattr(parsed, "tcp_flags", None) or ""
            if "SYN" in tcp_flags:
                self.syn_count += 1
            if "FIN" in tcp_flags:
                self.fin_count += 1
            if "RST" in tcp_flags:
                self.rst_count += 1

    def to_feature(self) -> FlowFeature:
        """转为对外发布的 FlowFeature（v3: 15 维）。"""
        duration = max(self.last_seen - self.start_time, 0.001)  # 避免除零

        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_pkt_len_sum + self.bwd_pkt_len_sum

        # 计算衍生特征
        fwd_mean = (self.fwd_pkt_len_sum / self.fwd_packets) if self.fwd_packets > 0 else 0.0
        bwd_mean = (self.bwd_pkt_len_sum / self.bwd_packets) if self.bwd_packets > 0 else 0.0
        bytes_per_sec = total_bytes / duration
        pkts_per_sec = total_pkts / duration
        fwd_iat_mean = (self.fwd_iat_sum / self.fwd_iat_count) if self.fwd_iat_count > 0 else 0.0
        bwd_iat_mean = (self.bwd_iat_sum / self.bwd_iat_count) if self.bwd_iat_count > 0 else 0.0

        return FlowFeature(
            # 基础 6 维
            Protocol=self.protocol,
            Flow_Duration=round(duration, 6),
            Total_Fwd_Packets=self.fwd_packets,
            Total_Backward_Packets=self.bwd_packets,
            Fwd_Packet_Length_Max=round(self.fwd_pkt_len_max, 1) if self.fwd_pkt_len_max else 0.0,
            Bwd_Packet_Length_Max=round(self.bwd_pkt_len_max, 1) if self.bwd_pkt_len_max else 0.0,
            # v3 扩展 9 维
            Fwd_Packet_Length_Mean=round(fwd_mean, 2),
            Bwd_Packet_Length_Mean=round(bwd_mean, 2),
            Flow_Bytes_Per_Sec=round(bytes_per_sec, 2),
            Flow_Packets_Per_Sec=round(pkts_per_sec, 2),
            Fwd_IAT_Mean=round(fwd_iat_mean, 6),
            Bwd_IAT_Mean=round(bwd_iat_mean, 6),
            SYN_Flag_Count=self.syn_count,
            FIN_Flag_Count=self.fin_count,
            RST_Flag_Count=self.rst_count,
            # 元信息
            flow_id=self.flow_id,
            start_time=datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            last_seen=datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
        )


# ---------------------------------------------------------------------------
# 输出数据结构 (v3: 15 维特征)
# ---------------------------------------------------------------------------

# v3: 15 个特征 CSV 列名
_FLOW_CSV_COLUMNS: Tuple[str, ...] = (
    # 基础 6
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    # 扩展 9
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
)

# CSV 列名 → FlowFeature 属性名映射
_FLOW_CSV_FIELD_MAP: Dict[str, str] = {
    "Protocol": "Protocol",
    "Flow Duration": "Flow_Duration",
    "Total Fwd Packets": "Total_Fwd_Packets",
    "Total Backward Packets": "Total_Backward_Packets",
    "Fwd Packet Length Max": "Fwd_Packet_Length_Max",
    "Bwd Packet Length Max": "Bwd_Packet_Length_Max",
    "Fwd Packet Length Mean": "Fwd_Packet_Length_Mean",
    "Bwd Packet Length Mean": "Bwd_Packet_Length_Mean",
    "Flow Bytes/s": "Flow_Bytes_Per_Sec",
    "Flow Packets/s": "Flow_Packets_Per_Sec",
    "Fwd IAT Mean": "Fwd_IAT_Mean",
    "Bwd IAT Mean": "Bwd_IAT_Mean",
    "SYN Flag Count": "SYN_Flag_Count",
    "FIN Flag Count": "FIN_Flag_Count",
    "RST Flag Count": "RST_Flag_Count",
}


@dataclass(slots=True)
class FlowFeature:
    """单条 Flow 的特征向量 (v3: 15 维)。

    字段名与 config.py 的 DB_FEATURE_COLUMNS 严格一致。
    """

    # --- 基础 6 维 ---
    Protocol: int = 0
    Flow_Duration: float = 0.0
    Total_Fwd_Packets: int = 0
    Total_Backward_Packets: int = 0
    Fwd_Packet_Length_Max: float = 0.0
    Bwd_Packet_Length_Max: float = 0.0

    # --- v3 扩展 9 维 ---
    Fwd_Packet_Length_Mean: float = 0.0
    Bwd_Packet_Length_Mean: float = 0.0
    Flow_Bytes_Per_Sec: float = 0.0
    Flow_Packets_Per_Sec: float = 0.0
    Fwd_IAT_Mean: float = 0.0
    Bwd_IAT_Mean: float = 0.0
    SYN_Flag_Count: int = 0
    FIN_Flag_Count: int = 0
    RST_Flag_Count: int = 0

    # --- 元信息（不进入模型）---
    flow_id: str = ""
    start_time: str = ""
    last_seen: str = ""

    def to_feature_list(self) -> List[Any]:
        """按 config.py MODEL_FEATURE_COLUMNS 顺序返回 15 个特征值的列表。"""
        return [
            self.Protocol,
            self.Flow_Duration,
            self.Total_Fwd_Packets,
            self.Total_Backward_Packets,
            self.Fwd_Packet_Length_Max,
            self.Bwd_Packet_Length_Max,
            self.Fwd_Packet_Length_Mean,
            self.Bwd_Packet_Length_Mean,
            self.Flow_Bytes_Per_Sec,
            self.Flow_Packets_Per_Sec,
            self.Fwd_IAT_Mean,
            self.Bwd_IAT_Mean,
            self.SYN_Flag_Count,
            self.FIN_Flag_Count,
            self.RST_Flag_Count,
        ]

    def to_dict(self) -> Dict[str, Any]:
        """转为字典，键名使用 DB 列名。"""
        return {
            "Protocol": self.Protocol,
            "Flow Duration": self.Flow_Duration,
            "Total Fwd Packets": self.Total_Fwd_Packets,
            "Total Backward Packets": self.Total_Backward_Packets,
            "Fwd Packet Length Max": self.Fwd_Packet_Length_Max,
            "Bwd Packet Length Max": self.Bwd_Packet_Length_Max,
            "Fwd Packet Length Mean": self.Fwd_Packet_Length_Mean,
            "Bwd Packet Length Mean": self.Bwd_Packet_Length_Mean,
            "Flow Bytes/s": self.Flow_Bytes_Per_Sec,
            "Flow Packets/s": self.Flow_Packets_Per_Sec,
            "Fwd IAT Mean": self.Fwd_IAT_Mean,
            "Bwd IAT Mean": self.Bwd_IAT_Mean,
            "SYN Flag Count": self.SYN_Flag_Count,
            "FIN Flag Count": self.FIN_Flag_Count,
            "RST Flag Count": self.RST_Flag_Count,
            "flow_id": self.flow_id,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ---------------------------------------------------------------------------
# FlowManager
# ---------------------------------------------------------------------------

class FlowManager:
    """Flow 管理器 — 核心引擎 (v3)。

    职责:
        - 接收 ParsedPacket，自动创建 / 更新 Flow
        - 超时回收已完成 Flow
        - TCP FIN/RST 触发 Flow 关闭
        - 导出 15 维特征 CSV 供 AI 推理
    """

    def __init__(self, timeout: float = FLOW_TIMEOUT) -> None:
        self._timeout = timeout
        self._flows: Dict[FlowKey, _FlowRecord] = {}
        self._lock = threading.Lock()
        self._flow_counter: int = 0

        # 统计
        self._total_created: int = 0
        self._total_closed: int = 0
        self._total_closed_timeout: int = 0
        self._total_closed_fin: int = 0

    # ---- 主入口 ----------------------------------------------------------

    def process_packet(self, parsed: Any) -> Optional[str]:
        """处理一个 ParsedPacket，更新对应 Flow。

        Returns:
            如果该包导致 Flow 关闭（FIN/RST），返回 flow_id；否则返回 None。
        """
        src_ip = parsed.src_ip
        dst_ip = parsed.dst_ip
        if not src_ip or not dst_ip:
            return None

        proto_num = parsed.protocol_number
        if proto_num is None:
            return None

        src_port = _port_or_zero(parsed.src_port)
        dst_port = _port_or_zero(parsed.dst_port)

        pkt_ts = _parse_timestamp(parsed.timestamp)
        if pkt_ts is None:
            pkt_ts = time.time()

        pkt_len = float(parsed.packet_length or 0)

        key = make_flow_key(src_ip, dst_ip, src_port, dst_port, proto_num)

        with self._lock:
            record = self._flows.get(key)
            if record is None:
                if len(self._flows) >= MAX_ACTIVE_FLOWS:
                    self._evict_oldest_closed()

                record = _FlowRecord(
                    key=key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_num,
                    start_time=pkt_ts,
                    last_seen=pkt_ts,
                    flow_id=self._gen_flow_id(),
                )
                self._flows[key] = record
                self._total_created += 1
                _logger.debug("Flow 创建 | id=%s | key=%s", record.flow_id, key)

            if record.is_closed:
                return None

            record.update(parsed, pkt_ts, pkt_len)

            # TCP FIN / RST 检测
            tcp_flags = getattr(parsed, "tcp_flags", None) or ""
            if proto_num == PROTO_TCP and tcp_flags:
                if "FIN" in tcp_flags and "ACK" not in tcp_flags:
                    record.is_closed = True
                    record.close_reason = "fin"
                    self._total_closed += 1
                    self._total_closed_fin += 1
                    _logger.info("Flow 关闭(FIN) | id=%s | packets fwd=%d bwd=%d",
                                 record.flow_id, record.fwd_packets, record.bwd_packets)
                    return record.flow_id
                if "RST" in tcp_flags:
                    record.is_closed = True
                    record.close_reason = "rst"
                    self._total_closed += 1
                    _logger.info("Flow 关闭(RST) | id=%s", record.flow_id)
                    return record.flow_id

        return None

    # ---- 超时回收 --------------------------------------------------------

    def cleanup_expired_flows(self, now: Optional[float] = None) -> List[FlowFeature]:
        """回收所有超时的 Flow，返回其特征列表。"""
        if now is None:
            now = time.time()

        expired_ids: List[str] = []
        features: List[FlowFeature] = []

        with self._lock:
            for key, record in list(self._flows.items()):
                if record.is_closed:
                    continue
                if (now - record.last_seen) >= self._timeout:
                    record.is_closed = True
                    record.close_reason = "timeout"
                    expired_ids.append(record.flow_id)
                    self._total_closed += 1
                    self._total_closed_timeout += 1
                    features.append(record.to_feature())

        for flow_id in expired_ids:
            _logger.info("Flow 超时回收 | id=%s", flow_id)

        return features

    # ---- 获取已完成 Flow -------------------------------------------------

    def get_completed_flows(self) -> List[FlowFeature]:
        """返回所有已关闭 Flow 的特征列表。"""
        results: List[FlowFeature] = []
        with self._lock:
            for record in self._flows.values():
                if record.is_closed:
                    results.append(record.to_feature())
        return results

    def get_all_flows(self) -> List[FlowFeature]:
        """返回所有 Flow（含活跃）的特征列表。"""
        results: List[FlowFeature] = []
        with self._lock:
            for record in self._flows.values():
                results.append(record.to_feature())
        return results

    # ---- 导出 CSV (v3: 15 列) -------------------------------------------

    def export_csv(self, path: Optional[str] = None, completed_only: bool = True) -> str:
        """将 Flow 特征导出为 15 维 CSV。

        CSV 列名与 config.py DB_FEATURE_COLUMNS 一致。
        """
        target = path or CSV_PATH
        flows = self.get_completed_flows() if completed_only else self.get_all_flows()

        _logger.info("导出特征 CSV (v3) | path=%s | flows=%d", target, len(flows))

        csv_columns = list(_FLOW_CSV_COLUMNS)

        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target, mode="w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(csv_columns)
                for feat in flows:
                    writer.writerow([
                        feat.Protocol,
                        feat.Flow_Duration,
                        feat.Total_Fwd_Packets,
                        feat.Total_Backward_Packets,
                        feat.Fwd_Packet_Length_Max,
                        feat.Bwd_Packet_Length_Max,
                        feat.Fwd_Packet_Length_Mean,
                        feat.Bwd_Packet_Length_Mean,
                        feat.Flow_Bytes_Per_Sec,
                        feat.Flow_Packets_Per_Sec,
                        feat.Fwd_IAT_Mean,
                        feat.Bwd_IAT_Mean,
                        feat.SYN_Flag_Count,
                        feat.FIN_Flag_Count,
                        feat.RST_Flag_Count,
                    ])
            _logger.info("特征 CSV 导出完成 → %s", os.path.abspath(target))
        except IOError:
            _logger.exception("CSV 写入失败: %s", target)
            raise

        return os.path.abspath(target)

    # ---- 统计 ------------------------------------------------------------

    @property
    def statistics(self) -> Dict[str, Any]:
        with self._lock:
            active = sum(1 for r in self._flows.values() if not r.is_closed)
            closed = sum(1 for r in self._flows.values() if r.is_closed)
        return {
            "total_flows": len(self._flows),
            "active_flows": active,
            "closed_flows": closed,
            "total_created": self._total_created,
            "total_closed": self._total_closed,
            "closed_by_timeout": self._total_closed_timeout,
            "closed_by_fin_rst": self._total_closed_fin,
        }

    # ---- 内部方法 --------------------------------------------------------

    def _gen_flow_id(self) -> str:
        self._flow_counter += 1
        return f"flow-{self._flow_counter:06d}"

    def _evict_oldest_closed(self) -> None:
        """容量超限时，移除最旧的已完成 Flow。"""
        closed = [(k, r) for k, r in self._flows.items() if r.is_closed]
        if closed:
            closed.sort(key=lambda x: x[1].last_seen)
            oldest_key = closed[0][0]
            del self._flows[oldest_key]
            _logger.debug("容量驱逐 | removed=%s", oldest_key)
        else:
            all_flows = sorted(self._flows.items(), key=lambda x: x[1].last_seen)
            if all_flows:
                oldest_key, oldest_rec = all_flows[0]
                oldest_rec.is_closed = True
                oldest_rec.close_reason = "evicted"
                del self._flows[oldest_key]
                _logger.debug("容量强制驱逐 | removed=%s", oldest_key)

    def reset(self) -> None:
        """重置所有状态（测试用）。"""
        with self._lock:
            self._flows.clear()
            self._flow_counter = 0
            self._total_created = 0
            self._total_closed = 0
            self._total_closed_timeout = 0
            self._total_closed_fin = 0


# ---------------------------------------------------------------------------
# AI 推理接口 (v3: 15 维)
# ---------------------------------------------------------------------------

def prepare_for_ai(flow: FlowFeature) -> List[Any]:
    """将一条 FlowFeature 转换为 AI 模型可直接推理的 15 维特征列表。

    Returns:
        按 config.py MODEL_FEATURE_COLUMNS 顺序的 15 元素列表。
    """
    return flow.to_feature_list()


# ---------------------------------------------------------------------------
# main — 自测 (v3)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from unittest.mock import Mock

    print("=" * 62)
    print("  feature_extractor.py (v3) 流特征提取 — 自测")
    print("=" * 62)

    def _mock_parsed(src_ip, dst_ip, src_port, dst_port, proto_num, ts, pkt_len, tcp_flags=""):
        m = Mock()
        m.src_ip = src_ip
        m.dst_ip = dst_ip
        m.src_port = src_port
        m.dst_port = dst_port
        m.protocol_number = proto_num
        m.timestamp = ts
        m.packet_length = pkt_len
        m.tcp_flags = tcp_flags
        return m

    mgr = FlowManager(timeout=60.0)
    base_ts = time.time()

    print("\n--- 场景: A → B 双向 TCP 流量 (SYN → SYN/ACK → ACK → DATA → FIN) ---\n")

    # SYN (前向)
    mgr.process_packet(_mock_parsed(
        "192.168.1.10", "8.8.8.8", 12345, 80, PROTO_TCP,
        base_ts + 0.0, 60, "SYN",
    ))
    # SYN/ACK (后向)
    mgr.process_packet(_mock_parsed(
        "8.8.8.8", "192.168.1.10", 80, 12345, PROTO_TCP,
        base_ts + 0.05, 60, "SYN/ACK",
    ))
    # ACK (前向)
    mgr.process_packet(_mock_parsed(
        "192.168.1.10", "8.8.8.8", 12345, 80, PROTO_TCP,
        base_ts + 0.1, 54, "ACK",
    ))
    # 数据包 1 (前向, 1500B)
    mgr.process_packet(_mock_parsed(
        "192.168.1.10", "8.8.8.8", 12345, 80, PROTO_TCP,
        base_ts + 1.0, 1500, "PSH/ACK",
    ))
    # 数据包 2 (前向, 800B)
    mgr.process_packet(_mock_parsed(
        "192.168.1.10", "8.8.8.8", 12345, 80, PROTO_TCP,
        base_ts + 1.5, 800, "ACK",
    ))
    # 后向 ACK
    mgr.process_packet(_mock_parsed(
        "8.8.8.8", "192.168.1.10", 80, 12345, PROTO_TCP,
        base_ts + 1.6, 54, "ACK",
    ))
    # 后向数据 (1200B)
    mgr.process_packet(_mock_parsed(
        "8.8.8.8", "192.168.1.10", 80, 12345, PROTO_TCP,
        base_ts + 2.0, 1200, "PSH/ACK",
    ))
    # FIN (前向)
    mgr.process_packet(_mock_parsed(
        "192.168.1.10", "8.8.8.8", 12345, 80, PROTO_TCP,
        base_ts + 4.0, 54, "FIN",
    ))

    features = mgr.get_all_flows()
    print(f"活跃/已关闭 Flow: {len(features)}")
    assert len(features) >= 1, "至少应有一个 Flow"

    feat = features[0]

    print(f"\n--- Flow 特征 (v3: 15 维) ---")
    print(f"  [基础 6]")
    print(f"    Protocol               : {feat.Protocol}  (expected 6)")
    print(f"    Flow Duration          : {feat.Flow_Duration}  (expected ~4.0)")
    print(f"    Total Fwd Packets      : {feat.Total_Fwd_Packets}  (expected 5: SYN+ACK+DATA1+DATA2+FIN)")
    print(f"    Total Backward Packets : {feat.Total_Backward_Packets}  (expected 2: SYN/ACK+DATA)")
    print(f"    Fwd Packet Length Max  : {feat.Fwd_Packet_Length_Max}  (expected 1500)")
    print(f"    Bwd Packet Length Max  : {feat.Bwd_Packet_Length_Max}  (expected 1200)")
    print(f"  [扩展 9]")
    print(f"    Fwd Packet Length Mean : {feat.Fwd_Packet_Length_Mean}")
    print(f"    Bwd Packet Length Mean : {feat.Bwd_Packet_Length_Mean}")
    print(f"    Flow Bytes/s           : {feat.Flow_Bytes_Per_Sec}")
    print(f"    Flow Packets/s         : {feat.Flow_Packets_Per_Sec}")
    print(f"    Fwd IAT Mean           : {feat.Fwd_IAT_Mean}")
    print(f"    Bwd IAT Mean           : {feat.Bwd_IAT_Mean}")
    print(f"    SYN Flag Count         : {feat.SYN_Flag_Count}  (expected 2: SYN + SYN/ACK)")
    print(f"    FIN Flag Count         : {feat.FIN_Flag_Count}  (expected 1)")
    print(f"    RST Flag Count         : {feat.RST_Flag_Count}  (expected 0)")

    # 验证基础特征
    assert feat.Protocol == PROTO_TCP, f"Protocol={feat.Protocol}"
    assert 3.9 <= feat.Flow_Duration <= 4.1, f"Duration={feat.Flow_Duration}"
    assert feat.Fwd_Packet_Length_Max == 1500.0, f"FwdMax={feat.Fwd_Packet_Length_Max}"
    assert feat.Bwd_Packet_Length_Max == 1200.0, f"BwdMax={feat.Bwd_Packet_Length_Max}"

    # 验证扩展特征
    assert feat.SYN_Flag_Count == 2, f"SYN={feat.SYN_Flag_Count}"
    assert feat.FIN_Flag_Count == 1, f"FIN={feat.FIN_Flag_Count}"
    assert feat.RST_Flag_Count == 0, f"RST={feat.RST_Flag_Count}"
    assert feat.Fwd_Packet_Length_Mean > 0, f"FwdMean={feat.Fwd_Packet_Length_Mean}"
    assert feat.Flow_Bytes_Per_Sec > 0, f"Bps={feat.Flow_Bytes_Per_Sec}"

    print("\n[PASS] 15 维 Flow 特征验证通过")

    # --- 测试场景 2: 双向归一化 ---
    print("\n--- 场景: 验证双向归一化 ---\n")
    mgr2 = FlowManager(timeout=60.0)
    base2 = time.time()
    mgr2.process_packet(_mock_parsed(
        "10.0.0.1", "10.0.0.2", 8080, 443, PROTO_TCP, base2, 100, "SYN",
    ))
    mgr2.process_packet(_mock_parsed(
        "10.0.0.2", "10.0.0.1", 443, 8080, PROTO_TCP, base2 + 1, 200, "SYN/ACK",
    ))
    assert mgr2.statistics["total_flows"] == 1, "双向归一化失败"
    print("[PASS] 双向归一化验证通过")

    # --- JSON / CSV 导出 ---
    print("\n--- 导出测试 ---")
    json_str = feat.to_json()
    print(f"JSON (截断): {json_str[:200]}...")

    csv_path = mgr.export_csv(completed_only=False)
    with open(csv_path, encoding="utf-8") as fh:
        print(f"\nCSV 表头 ({csv_path}):")
        print(fh.readline().strip())

    # --- AI 接口测试 ---
    print("\n--- AI 推理接口 (v3) ---")
    ai_vector = prepare_for_ai(feat)
    print(f"prepare_for_ai() → {len(ai_vector)} 维向量")
    assert len(ai_vector) == 15, f"期望 15 维，实际 {len(ai_vector)}"
    print(f"  [{ai_vector[0]}, {ai_vector[1]:.4f}, {ai_vector[2]}, {ai_vector[3]}, "
          f"{ai_vector[4]}, {ai_vector[5]}, {ai_vector[6]:.2f}, {ai_vector[7]:.2f}, "
          f"{ai_vector[8]:.2f}, {ai_vector[9]:.2f}, ...]")
    print("[PASS] AI 接口验证通过 (15 维)")

    # --- 统计 ---
    print("\n--- 统计 ---")
    for k, v in mgr.statistics.items():
        print(f"  {k}: {v}")

    print(f"\n日志: {LOG_PATH}")
    print(f"CSV:  {csv_path}")
    print("\n" + "=" * 62)
    print("  全部自测通过 [PASS — v3]")
    print("=" * 62)
