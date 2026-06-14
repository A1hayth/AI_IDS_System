"""
流量采集、解析与特征提取模块

子模块：
    capture.py           — 实时抓包引擎（基于 Scapy）
    parser.py            — 深度协议解析（HTTP / TLS / ICMP）
    feature_extractor.py — 流特征提取，对接 AI 引擎

数据流：
    capture.py ──raw packets──▶ parser.py ──ParsedPacket──▶ feature_extractor.py ──FlowFeature──▶ AI 引擎

使用示例：
    from traffic_module import (
        start_capture, stop_capture,
        get_recent_raw_packets, PacketParser,
        FlowManager,
    )

    start_capture(timeout=30)
    # ... 等待数据积累 ...
    raw = get_recent_raw_packets(200)
    parsed = PacketParser().parse_packets(raw)

    mgr = FlowManager()
    for p in parsed:
        mgr.process_packet(p)
    features = mgr.get_completed_flows()
"""

# ============================================================================
# capture.py — 实时抓包引擎
# ============================================================================

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
    set_target_domains,
    get_domain_filter_stats,
    DEFAULT_INTERFACE,
    DEFAULT_FILTER,
    TARGET_DOMAINS,
    MAX_PACKET_CACHE,
    CSV_PATH,
    LOG_PATH,
)

# ============================================================================
# parser.py — 深度协议解析
# ============================================================================

from .parser import (
    ParsedPacket,
    PacketParser,
    extract_features,
    extract_sql_fields,
    MAX_PAYLOAD_LENGTH,
)

# 避免与 capture.LOG_PATH 冲突，加前缀
from .parser import LOG_PATH as PARSER_LOG_PATH

# ============================================================================
# feature_extractor.py — 流特征提取
# ============================================================================

from .feature_extractor import (
    FlowFeature,
    FlowManager,
    make_flow_key,
    is_forward,
    prepare_for_ai,
    FLOW_TIMEOUT,
    MAX_ACTIVE_FLOWS,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
)

# 避免与 capture 的 CSV_PATH / LOG_PATH 冲突
from .feature_extractor import CSV_PATH as FE_CSV_PATH
from .feature_extractor import LOG_PATH as FE_LOG_PATH

# ============================================================================
# __all__
# ============================================================================

__all__ = [
    # -- capture --
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
    "set_target_domains",
    "get_domain_filter_stats",
    "DEFAULT_INTERFACE",
    "DEFAULT_FILTER",
    "TARGET_DOMAINS",
    "MAX_PACKET_CACHE",
    "CSV_PATH",
    "LOG_PATH",
    # -- parser --
    "ParsedPacket",
    "PacketParser",
    "extract_features",
    "extract_sql_fields",
    "MAX_PAYLOAD_LENGTH",
    "PARSER_LOG_PATH",
    # -- feature_extractor --
    "FlowFeature",
    "FlowManager",
    "make_flow_key",
    "is_forward",
    "prepare_for_ai",
    "FLOW_TIMEOUT",
    "MAX_ACTIVE_FLOWS",
    "PROTO_TCP",
    "PROTO_UDP",
    "PROTO_ICMP",
    "FE_CSV_PATH",
    "FE_LOG_PATH",
]
