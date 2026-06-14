"""
AI-IDS 主运行脚本 — 串联 capture → parser → feature_extractor 全流程。

数据流:
    capture.py ──raw packets──▶ parser.py ──ParsedPacket──▶ feature_extractor.py ──特征CSV

用法:
    python run.py -t 60                       # 抓包 60 秒，输出到默认 CSV
    python run.py -t 120 -o results.csv       # 指定输出路径
    python run.py -t 30 --no-capture          # 不抓包（使用模拟数据演示）
    python run.py -t 60 --interval 1.5        # 每 1.5 秒轮询一次（默认 2 秒）
    python run.py -t 300 --csv completed      # 仅导出已关闭的 Flow
    python run.py -t 300 --csv all            # 导出全部 Flow（含活跃）
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import textwrap
from datetime import datetime, timezone
from typing import List, Optional

# 确保 src 在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from traffic_module import (               # noqa: E402
    # capture
    start_capture,
    stop_capture,
    get_recent_raw_packets,
    get_packet_count,
    get_statistics,
    is_running,
    set_target_domains,
    get_domain_filter_stats,
    # parser
    PacketParser,
    # feature_extractor
    FlowManager,
    FE_CSV_PATH,
    FE_LOG_PATH,
)

# ---------------------------------------------------------------------------
# 默认参数
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 60
DEFAULT_POLL_INTERVAL: float = 2.0
DEFAULT_OUTPUT: str = FE_CSV_PATH

# ---------------------------------------------------------------------------
# 模拟数据（--no-capture 时使用）
# ---------------------------------------------------------------------------

_MOCK_PACKETS = None  # 惰性构造


def _get_mock_packets():
    """构造模拟 Scapy 数据包用于演示。"""
    global _MOCK_PACKETS
    if _MOCK_PACKETS is not None:
        return _MOCK_PACKETS

    from scapy.all import IP, TCP, Raw

    now = time.time()
    _MOCK_PACKETS = [
        IP(src="192.168.1.100", dst="93.184.216.34", ttl=64)
        / TCP(sport=54321, dport=80, flags="PA")
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n\r\n"),
        IP(src="93.184.216.34", dst="192.168.1.100", ttl=52)
        / TCP(sport=80, dport=54321, flags="PA")
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n<html>"),
        IP(src="192.168.1.100", dst="93.184.216.34", ttl=64)
        / TCP(sport=54321, dport=80, flags="PA")
        / Raw(load=b"GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        IP(src="10.0.0.1", dst="10.0.0.2", ttl=128)
        / TCP(sport=443, dport=54322, flags="SA"),
        IP(src="192.168.1.1", dst="8.8.8.8", ttl=64)
        / TCP(sport=12345, dport=443, flags="S"),
        IP(src="10.0.0.3", dst="10.0.0.4", ttl=64)
        / TCP(sport=80, dport=49152, flags="A")
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
        IP(src="172.16.0.1", dst="172.16.0.2", ttl=62)
        / TCP(sport=9999, dport=8080, flags="PA")
        / Raw(load=b"POST /login HTTP/1.1\r\nHost: test.com\r\n"
                b"User-Agent: curl/7.88\r\n\r\nuser=admin&pass=123"),
        IP(src="192.168.1.100", dst="93.184.216.34", ttl=64)
        / TCP(sport=54321, dport=80, flags="FA"),
    ]
    return _MOCK_PACKETS


def _feed_all_mock_packets(pparser: PacketParser, flow_mgr: FlowManager) -> int:
    """一次性喂入全部模拟包，返回喂入的包数。"""
    pkts = _get_mock_packets()
    if not pkts:
        print("  [!] 模拟数据为空")
        return 0

    from copy import deepcopy
    now = time.time()
    fed = 0
    for pkt in pkts:
        clone = deepcopy(pkt)
        # 给每个包一个相对时间戳（模拟渐进的流量）
        clone.time = now - len(pkts) + fed
        parsed = pparser.parse_packet(clone)
        if parsed.src_ip or parsed.protocol or parsed.packet_length:
            flow_mgr.process_packet(parsed)
            fed += 1
    flow_mgr.cleanup_expired_flows()
    return fed


# ---------------------------------------------------------------------------
# 核心编排逻辑
# ---------------------------------------------------------------------------

def run_pipeline(
    timeout: float = DEFAULT_TIMEOUT,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    output_path: str = DEFAULT_OUTPUT,
    completed_only: bool = True,
    use_mock: bool = False,
    target_domains: Optional[List[str]] = None,
) -> str:
    """运行完整流量采集→解析→特征提取流水线。

    Args:
        timeout: 总运行时长（秒）。
        poll_interval: 轮询间隔（秒）。
        output_path: 最终 CSV 输出路径。
        completed_only: True=仅导出已关闭 Flow，False=导出全部。
        use_mock: True=使用模拟数据（无需管理员权限）。

    Returns:
        写入的 CSV 文件绝对路径。
    """
    pparser = PacketParser()
    flow_mgr = FlowManager()

    # ---- 阶段 1: 启动采集 ----
    print("=" * 62)
    print("  AI-IDS 流量检测系统")
    print("=" * 62)
    print(f"  启动时间 : {datetime.now(timezone.utc).isoformat()}")
    print(f"  运行时长 : {timeout} 秒")
    print(f"  轮询间隔 : {poll_interval} 秒")
    print(f"  输出路径 : {output_path}")
    print(f"  数据源   : {'模拟数据' if use_mock else '实时抓包'}")
    print("-" * 62)

    if not use_mock:
        # 设置域名过滤（在启动抓包之前）
        if target_domains:
            print(f"  [domain] 目标域名: {target_domains}")
            set_target_domains(target_domains)
            stats = get_domain_filter_stats()
            if stats:
                print(f"  [domain] 已解析 {stats['total_ips']} 个 IP（{len(stats['domains'])} 个域名）")

        try:
            start_capture(timeout=None)
            print("  [capture] 后台抓包已启动")
        except RuntimeError as e:
            print(f"  [!] 抓包启动失败: {e}")
            print("      切换到模拟数据模式...")
            use_mock = True
        except PermissionError:
            print("  [!] 权限不足（需管理员权限抓包），切换到模拟数据模式...")
            use_mock = True
    else:
        print("  [capture] 使用模拟数据（跳过抓包）")

    # ---- 阶段 2: 主循环 ----
    start_time = time.time()
    processed_count = 0
    last_status = start_time

    # 模拟模式一次性喂入所有包
    if use_mock:
        fed = _feed_all_mock_packets(pparser, flow_mgr)
        print(f"  [mock] 已喂入 {fed} 个模拟数据包")
        print(f"  等待 {timeout:.0f} 秒模拟实时采集...")

    try:
        while (elapsed := time.time() - start_time) < timeout:
            if use_mock:
                # 模拟模式：仅周期性回收超时 Flow
                flow_mgr.cleanup_expired_flows()
            else:
                # 实时模式：从 _raw_cache 增量取包
                all_raw = get_recent_raw_packets(None)
                if all_raw and len(all_raw) > processed_count:
                    new_pkts = all_raw[processed_count:]
                    processed_count = len(all_raw)

                    parsed = pparser.parse_packets(new_pkts)
                    for p in parsed:
                        flow_mgr.process_packet(p)

                # 定期回收超时 Flow
                flow_mgr.cleanup_expired_flows()

            # 定期打印状态
            if time.time() - last_status >= 5.0:
                _print_status(pparser, flow_mgr, elapsed, timeout, use_mock)
                last_status = time.time()

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n  [!] 用户中断 (Ctrl+C)")

    # ---- 阶段 3: 停止采集 ----
    remaining = max(0.0, timeout - (time.time() - start_time))
    if remaining > 0:
        print(f"\n  等待剩余 {remaining:.0f} 秒（让流量充分到达）...")
        if use_mock:
            flow_mgr.cleanup_expired_flows()
            time.sleep(min(remaining, 2.0))
        else:
            # 等待期间继续处理新增包
            deadline = time.time() + remaining
            while time.time() < deadline:
                all_raw = get_recent_raw_packets(None)
                if all_raw and len(all_raw) > processed_count:
                    new_pkts = all_raw[processed_count:]
                    processed_count = len(all_raw)
                    parsed = pparser.parse_packets(new_pkts)
                    for p in parsed:
                        flow_mgr.process_packet(p)
                flow_mgr.cleanup_expired_flows()
                time.sleep(min(1.0, deadline - time.time()))

    if not use_mock:
        stop_capture()

    # ---- 阶段 4: 最终回收 ----
    # 将所有剩余 Flow 强制超时（now=极大值）
    flow_mgr.cleanup_expired_flows(now=float("inf"))

    # ---- 阶段 5: 导出 ----
    print()
    output = flow_mgr.export_csv(output_path, completed_only=completed_only)

    # ---- 阶段 6: 汇总 ----
    _print_summary(pparser, flow_mgr, output, time.time() - start_time)

    return output



# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def _print_status(pparser, flow_mgr, elapsed, timeout, use_mock):
    """打印运行中状态。"""
    ps = pparser.statistics
    fs = flow_mgr.statistics
    pkt_count = get_packet_count() if not use_mock else ps["total_parsed"]
    line = (
        f"  [{elapsed:5.0f}s] "
        f"抓包={pkt_count:>6} | "
        f"解析={ps['total_parsed']:>6} | "
        f"TCP={ps['tcp']:>5} UDP={ps['udp']:>4} ICMP={ps['icmp']:>3} "
        f"HTTP={ps['http']:>3} HTTPS={ps['https']:>3} | "
        f"Flow: 活跃={fs['active_flows']:>4} 已关闭={fs['closed_flows']:>4} "
        f"总量={fs['total_flows']:>5}"
    )
    # 域名过滤统计
    ds = get_domain_filter_stats()
    if ds:
        cc = ds.get("connection_cache", {})
        line += f" | 域名过滤: IPs={ds['total_ips']} 连接缓存={cc.get('active', 0)}"
    print(line)


def _print_summary(pparser, flow_mgr, output_path, total_time):
    """打印最终汇总。"""
    ps = pparser.statistics
    fs = flow_mgr.statistics

    print()
    print("=" * 62)
    print("  运行完毕")
    print("=" * 62)
    print(f"  总耗时            : {total_time:.1f} 秒")
    print()
    print(f"  --- capture ---")
    print(f"  捕获数据包        : {ps['total_parsed']}")
    print()
    print(f"  --- parser ---")
    print(f"  TCP / UDP / ICMP  : {ps['tcp']} / {ps['udp']} / {ps['icmp']}")
    print(f"  HTTP / HTTPS      : {ps['http']} / {ps['https']}")
    print(f"  解析错误          : {ps['parse_errors']}")
    print()
    print(f"  --- feature_extractor ---")
    print(f"  创建 Flow 总数    : {fs['total_created']}")
    print(f"  已关闭 Flow       : {fs['total_closed']}")
    print(f"    └─ 超时回收     : {fs['closed_by_timeout']}")
    print(f"    └─ FIN/RST      : {fs['closed_by_fin_rst']}")
    print(f"  活跃 Flow         : {fs['active_flows']}")
    print()
    print(f"  CSV 输出          : {output_path}")
    print(f"  日志目录          : {os.path.dirname(FE_LOG_PATH)}")

    # 域名过滤汇总
    ds = get_domain_filter_stats()
    if ds:
        cc = ds.get("connection_cache", {})
        print()
        print(f"  --- 域名过滤 ---")
        print(f"  目标域名          : {ds['total_domains']}")
        print(f"  已解析 IP         : {ds['total_ips']}")
        print(f"  连接缓存(已批准)  : {cc.get('active', 0)}")
        for d, info in ds.get("domains", {}).items():
            err = f" ({info['error']})" if info['error'] else ""
            print(f"    {d}: {info['ip_count']} IPs{err}")

    print("=" * 62)


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AI-IDS 流量检测系统 — 完整流水线",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            示例:
              python run.py -t 60                         # 抓包 60 秒
              python run.py -t 120 -o my_features.csv     # 指定输出
              python run.py -t 30 --no-capture            # 模拟数据演示
              python run.py -t 300 --csv all              # 导出全部 Flow
              python run.py -t 60 -d example.com          # 仅捕获指定网站
              python run.py -t 60 -d example.com baidu.com # 多个网站
        """),
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"运行时长（秒），默认 {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "-o", "--output", default=DEFAULT_OUTPUT,
        help=f"特征 CSV 输出路径，默认 {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_POLL_INTERVAL,
        help=f"轮询间隔（秒），默认 {DEFAULT_POLL_INTERVAL}",
    )
    parser.add_argument(
        "--csv", choices=["completed", "all"], default="completed",
        help="导出模式: completed=仅已关闭Flow, all=含活跃Flow（默认 completed）",
    )
    parser.add_argument(
        "--no-capture", action="store_true",
        help="不抓包，使用模拟 Scapy 数据包（无需管理员权限）",
    )
    parser.add_argument(
        "-d", "--domains", nargs="+", default=None,
        help="目标域名列表，只捕获相关流量（空格分隔），例如: -d example.com test.org",
    )
    args = parser.parse_args()

    run_pipeline(
        timeout=args.timeout,
        poll_interval=args.interval,
        output_path=args.output,
        completed_only=(args.csv == "completed"),
        use_mock=args.no_capture,
        target_domains=args.domains,
    )


if __name__ == "__main__":
    main()
