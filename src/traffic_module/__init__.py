"""
流量采集与解析模块

子模块：
    capture.py          — 实时抓包引擎（当前模块）
    parser.py           — 深度协议解析（待开发）
    feature_extractor.py — 特征提取，对接 AI 引擎（待开发）
"""

from .capture import (
    PacketInfo,
    PacketCache,
    start_capture,
    stop_capture,
    get_packet_count,
    get_recent_packets,
    get_recent_raw_packets,
    get_packets_for_feature_extraction,
    get_packets_as_dicts,
    export_csv,
    is_running,
    get_statistics,
    parse_packet,
    DEFAULT_INTERFACE,
    DEFAULT_FILTER,
    MAX_PACKET_CACHE,
    CSV_PATH,
    LOG_PATH,
)

__all__ = [
    "PacketInfo",
    "PacketCache",
    "start_capture",
    "stop_capture",
    "get_packet_count",
    "get_recent_packets",
    "get_recent_raw_packets",
    "get_packets_for_feature_extraction",
    "get_packets_as_dicts",
    "export_csv",
    "is_running",
    "get_statistics",
    "parse_packet",
    "DEFAULT_INTERFACE",
    "DEFAULT_FILTER",
    "MAX_PACKET_CACHE",
    "CSV_PATH",
    "LOG_PATH",
]
