# -*- coding: utf-8 -*-
"""
AI-IDS 测试流量生成器 — 生成能被 AI 模型识别为攻击的测试流量。

═══════════════════════════════════════════════════════════════════════════════
  为什么旧版（HTTP请求）无法被识别？
═══════════════════════════════════════════════════════════════════════════════
  AI 模型 (XGBoost v3) 基于 **15 维流统计特征** 判定攻击，而非 HTTP 载荷内容:
      protocol, flow_duration, total_fwd_packets, total_backward_packets,
      fwd_packet_length_max, bwd_packet_length_max, fwd_packet_length_mean,
      bwd_packet_length_mean, flow_bytes_per_sec, flow_packets_per_sec,
      fwd_iat_mean, bwd_iat_mean, syn_flag_count, fin_flag_count, rst_flag_count

  发送带 SQLi/XSS 字符串的 HTTP 请求，从流统计角度看与正常浏览无异，
  因此 100% 被判定为 Normal。必须生成与攻击类型匹配的流级别统计模式。

═══════════════════════════════════════════════════════════════════════════════
  三种模式
═══════════════════════════════════════════════════════════════════════════════

  【DB 注入模式】(默认，推荐)  — 直接向 flow_features 写入攻击特征行
    100% 可靠，无需管理员权限，无需抓包。
    用法: python generate_test_traffic.py

  【混合模式】                   — DB注入 + Scapy发包 同时进行
    适用于测试完整链路 (capture → parser → feature_extractor → AI)
    用法: python generate_test_traffic.py --mixed --target 127.0.0.1

  【Scapy 发包模式】             — 仅发送真实数据包（不注入DB）
    需要管理员权限 + traffic_monitor 运行中。
    用法: python generate_test_traffic.py --scapy-only --target 10.20.101.246

═══════════════════════════════════════════════════════════════════════════════
  可模拟的 12 种攻击类型
═══════════════════════════════════════════════════════════════════════════════
  CRITICAL: DDoS, DoS Hulk, DoS slowloris, DoS GoldenEye, DoS Slowhttptest
  HIGH:     Web Attack - Brute Force, Web Attack - XSS
  MEDIUM:   PortScan, Bot, SSH-Patator, FTP-Patator

用法:
    python generate_test_traffic.py                             # DB注入全部攻击+正常流量
    python generate_test_traffic.py --count 10                  # 每种攻击10条
    python generate_test_traffic.py --types DDoS,PortScan,Bot   # 仅指定类型
    python generate_test_traffic.py --benign 20                 # 混入20条正常流量
    python generate_test_traffic.py --all                       # 清空flow_features后注入
    python generate_test_traffic.py --list                      # 列出所有攻击类型
    python generate_test_traffic.py --mixed --target 10.20.101.246  # DB注入+发包
    python generate_test_traffic.py --scapy-only --target 10.20.101.246  # 仅发包
    python generate_test_traffic.py --loop 60                   # 每60秒循环一轮

完整测试链路:
    # 终端1: 启动监控
    python main.py --no-capture

    # 终端2: 注入攻击数据
    python generate_test_traffic.py --all

    # AI 检测
    python main.py --once
"""

from __future__ import annotations

import argparse
import datetime
import os
import random
import sys
import textwrap
import time
from typing import Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC_DIR = os.path.join(_PROJECT_DIR, "src")

# ============================================================================
# 攻击特征指纹库 (v3: 15 维 — 全部经过 XGBoost 模型验证)
# 格式: [protocol, flow_duration, total_fwd, total_bwd, fwd_max, bwd_max,
#         fwd_mean, bwd_mean, bytes_ps, pkts_ps, fwd_iat, bwd_iat,
#         syn_cnt, fin_cnt, rst_cnt]
# ============================================================================
ATTACK_FINGERPRINTS: Dict[str, Dict] = {
    "DDoS": {
        "label": "DDoS", "risk": "CRITICAL",
        "desc": "分布式拒绝服务 — 高后向包长(4380B)，高前向IAT",
        "vectors": [
            [6, 1935397, 4, 4, 20, 4380, 7.0, 1934.5, 156.3, 2.47, 508236, 18978, 0, 0, 0],
            [6, 1500000, 5, 3, 15, 4000, 6.0, 1800.0, 200.0, 3.0, 400000, 15000, 0, 0, 0],
            [6, 2500000, 3, 5, 25, 4500, 8.0, 2000.0, 120.0, 2.0, 600000, 20000, 0, 0, 0],
            [6, 1800000, 4, 4, 18, 4200, 7.5, 1900.0, 180.0, 2.8, 500000, 18000, 0, 0, 0],
            [6, 2200000, 6, 3, 22, 4400, 6.5, 1950.0, 140.0, 2.2, 550000, 19000, 0, 0, 0],
        ],
    },
    "DoS_Hulk": {
        "label": "DoS Hulk", "risk": "CRITICAL",
        "desc": "HTTP高并发拒绝服务 — 极大流量时长(86M μs)，极低PPS(0.15)",
        "vectors": [
            [6, 86589878, 6, 6, 345, 5792, 54.5, 1932.5, 124.5, 0.15, 14200000, 29926, 0, 0, 0],
            [6, 80000000, 7, 5, 300, 5500, 50.0, 1800.0, 130.0, 0.16, 13000000, 28000, 0, 0, 0],
            [6, 90000000, 5, 7, 380, 6000, 58.0, 2000.0, 120.0, 0.14, 15000000, 32000, 0, 0, 0],
            [6, 85000000, 6, 6, 350, 5800, 55.0, 1950.0, 125.0, 0.15, 14000000, 30000, 0, 0, 0],
            [6, 95000000, 8, 4, 330, 5600, 52.0, 1850.0, 128.0, 0.13, 14500000, 29000, 0, 0, 0],
        ],
    },
    "DoS_slowloris": {
        "label": "DoS slowloris", "risk": "CRITICAL",
        "desc": "Slowloris慢速攻击 — 极长时延(100M μs)，极低速率(0.16 B/s)",
        "vectors": [
            [6, 99999401, 3, 2, 8, 0, 8.0, 0.0, 0.16, 0.18, 7048861, 51300000, 0, 0, 0],
            [6, 95000000, 2, 2, 5, 0, 5.0, 0.0, 0.12, 0.15, 6500000, 50000000, 0, 0, 0],
            [6, 105000000, 4, 2, 10, 0, 10.0, 0.0, 0.20, 0.20, 7500000, 53000000, 0, 0, 0],
            [6, 98000000, 3, 1, 7, 0, 7.0, 0.0, 0.14, 0.16, 7000000, 51000000, 0, 0, 0],
            [6, 102000000, 3, 3, 9, 0, 9.0, 0.0, 0.18, 0.19, 7200000, 52000000, 0, 0, 0],
        ],
    },
    "DoS_GoldenEye": {
        "label": "DoS GoldenEye", "risk": "CRITICAL",
        "desc": "GoldenEye DoS — 长时HTTP连接耗尽，高后向包长",
        "vectors": [
            [6, 11601932, 7, 5, 372, 4344, 52.8, 1454.0, 654.0, 0.98, 1151716, 2296316, 0, 0, 0],
            [6, 10000000, 8, 4, 350, 4000, 50.0, 1400.0, 600.0, 1.0, 1000000, 2000000, 0, 0, 0],
            [6, 13000000, 6, 6, 400, 4500, 55.0, 1500.0, 700.0, 0.9, 1300000, 2500000, 0, 0, 0],
            [6, 11000000, 7, 5, 360, 4200, 53.0, 1450.0, 650.0, 1.0, 1150000, 2300000, 0, 0, 0],
            [6, 12500000, 9, 4, 380, 4400, 52.0, 1480.0, 620.0, 0.95, 1200000, 2400000, 0, 0, 0],
        ],
    },
    "DoS_Slowhttptest": {
        "label": "DoS Slowhttptest", "risk": "CRITICAL",
        "desc": "Slowhttptest — 极低速率，无后向包，零包长",
        "vectors": [
            [6, 63120632, 7, 0, 0, 0, 0.0, 0.0, 0.0, 0.11, 10500000, 0, 0, 0, 0],
            [6, 60000000, 6, 0, 0, 0, 0.0, 0.0, 0.0, 0.10, 10000000, 0, 0, 0, 0],
            [6, 65000000, 8, 0, 0, 0, 0.0, 0.0, 0.0, 0.12, 11000000, 0, 0, 0, 0],
            [6, 58000000, 5, 0, 0, 0, 0.0, 0.0, 0.0, 0.09, 9500000, 0, 0, 0, 0],
            [6, 68000000, 9, 0, 0, 0, 0.0, 0.0, 0.0, 0.13, 11500000, 0, 0, 0, 0],
        ],
    },
    "PortScan": {
        "label": "PortScan", "risk": "MEDIUM",
        "desc": "端口扫描 — 极短流(674μs)，高PPS(5050)，零前向包长",
        "vectors": [
            [6, 674, 2, 1, 0, 2, 0.0, 2.0, 12987.2, 5050.5, 490, 0, 0, 0, 0],
            [6, 500, 2, 1, 0, 2, 0.0, 2.0, 15000.0, 6000.0, 400, 0, 0, 0, 0],
            [6, 800, 3, 1, 0, 3, 0.0, 3.0, 12000.0, 5000.0, 500, 0, 0, 0, 0],
            [6, 300, 1, 1, 0, 1, 0.0, 1.0, 20000.0, 8000.0, 300, 0, 0, 0, 0],
            [6, 1000, 2, 2, 0, 2, 0.0, 2.0, 10000.0, 4000.0, 600, 0, 0, 0, 0],
        ],
    },
    "Bot": {
        "label": "Bot", "risk": "MEDIUM",
        "desc": "僵尸网络心跳 — 中等时长(88K μs)，双向IAT均高",
        "vectors": [
            [6, 88782, 4, 3, 194, 128, 42.6, 8.3, 4141.4, 83.8, 27734, 40798, 0, 0, 0],
            [6, 80000, 5, 3, 180, 120, 40.0, 8.0, 4200.0, 85.0, 25000, 40000, 0, 0, 0],
            [6, 95000, 3, 4, 200, 140, 45.0, 9.0, 4000.0, 80.0, 30000, 42000, 0, 0, 0],
            [6, 70000, 4, 2, 190, 110, 42.0, 7.5, 4300.0, 90.0, 26000, 38000, 0, 0, 0],
            [6, 100000, 5, 3, 210, 130, 44.0, 8.5, 4100.0, 82.0, 29000, 41000, 0, 0, 0],
        ],
    },
    "SSH_Patator": {
        "label": "SSH-Patator", "risk": "MEDIUM",
        "desc": "SSH暴力破解 — 多包(21/32对)，大包长(640/976B)",
        "vectors": [
            [6, 12029788, 21, 32, 640, 976, 95.6, 85.8, 389.4, 4.41, 503476, 388508, 0, 0, 0],
            [6, 11000000, 20, 30, 600, 900, 90.0, 80.0, 380.0, 4.5, 500000, 380000, 0, 0, 0],
            [6, 13000000, 22, 35, 680, 1000, 100.0, 90.0, 400.0, 4.3, 510000, 400000, 0, 0, 0],
            [6, 11500000, 18, 28, 620, 950, 92.0, 82.0, 390.0, 4.0, 490000, 370000, 0, 0, 0],
            [6, 12500000, 25, 33, 660, 990, 98.0, 88.0, 395.0, 4.6, 520000, 395000, 0, 0, 0],
        ],
    },
    "FTP_Patator": {
        "label": "FTP-Patator", "risk": "MEDIUM",
        "desc": "FTP暴力破解 — 中等时长(8.7M μs)，双向均衡小包",
        "vectors": [
            [6, 8695582, 9, 15, 22, 34, 11.3, 12.5, 33.9, 2.76, 715498, 621420, 0, 0, 0],
            [6, 8000000, 8, 14, 20, 30, 10.0, 12.0, 35.0, 2.8, 700000, 600000, 0, 0, 0],
            [6, 9000000, 10, 16, 25, 35, 12.0, 13.0, 32.0, 2.7, 730000, 640000, 0, 0, 0],
            [6, 8500000, 7, 13, 18, 28, 10.5, 11.5, 34.0, 2.5, 710000, 610000, 0, 0, 0],
            [6, 9500000, 11, 17, 24, 36, 11.8, 13.5, 33.5, 2.9, 720000, 630000, 0, 0, 0],
        ],
    },
    "Web_Attack_Brute_Force": {
        "label": "Web Attack - Brute Force", "risk": "HIGH",
        "desc": "Web暴力破解 — 长时(5.6M μs)，零包长，高前向IAT(2.7M)",
        "vectors": [
            [6, 5567835, 3, 1, 0, 0, 0.0, 0.0, 0.0, 0.74, 2714256, 0, 0, 0, 0],
            [6, 5000000, 2, 1, 0, 0, 0.0, 0.0, 0.0, 0.60, 2500000, 0, 0, 0, 0],
            [6, 6000000, 4, 1, 0, 0, 0.0, 0.0, 0.0, 0.83, 2900000, 0, 0, 0, 0],
            [6, 4500000, 3, 2, 0, 0, 0.0, 0.0, 0.0, 1.11, 2400000, 0, 0, 0, 0],
            [6, 6500000, 2, 1, 0, 0, 0.0, 0.0, 0.0, 0.46, 3000000, 0, 0, 0, 0],
        ],
    },
    "Web_Attack_XSS": {
        "label": "Web Attack - XSS", "risk": "HIGH",
        "desc": "跨站脚本攻击 — 长时(5.4M μs)，零包长，高前向IAT(2.7M)",
        "vectors": [
            [6, 5398910, 3, 1, 0, 0, 0.0, 0.0, 0.0, 0.75, 2683926, 0, 0, 0, 0],
            [6, 5000000, 2, 1, 0, 0, 0.0, 0.0, 0.0, 0.60, 2500000, 0, 0, 0, 0],
            [6, 5800000, 4, 1, 0, 0, 0.0, 0.0, 0.0, 0.86, 2800000, 0, 0, 0, 0],
            [6, 4800000, 3, 2, 0, 0, 0.0, 0.0, 0.0, 1.04, 2600000, 0, 0, 0, 0],
            [6, 6200000, 2, 1, 0, 0, 0.0, 0.0, 0.0, 0.48, 2900000, 0, 0, 0, 0],
        ],
    },
}

# 正常流量模板 (v3: 15 维 — 从 CIC-IDS-2017 Benign 中位数提取)
BENIGN_TEMPLATES: List[List] = [
    [6, 49008, 2, 2, 43, 98, 39.8, 90.0, 4179.2, 74.2, 41, 4, 0, 0, 0],
    [6, 25000000, 10, 12, 500, 1200, 250.0, 600.0, 2000.0, 10.0, 1500000, 1200000, 0, 0, 0],
    [6, 15000000, 8, 9, 300, 800, 150.0, 400.0, 1500.0, 12.0, 1000000, 800000, 0, 0, 0],
    [6, 30000000, 15, 14, 800, 1500, 400.0, 750.0, 2500.0, 8.0, 2000000, 1500000, 0, 0, 0],
    [17, 5000000, 5, 6, 200, 300, 100.0, 150.0, 1000.0, 20.0, 500000, 400000, 0, 0, 0],
    [6, 10000000, 3, 4, 100, 500, 50.0, 250.0, 800.0, 5.0, 2000000, 1500000, 0, 0, 0],
    [6, 20000000, 12, 10, 600, 1000, 300.0, 500.0, 1800.0, 9.0, 1200000, 1000000, 0, 0, 0],
    [6, 28000000, 9, 11, 450, 1100, 225.0, 550.0, 1600.0, 7.0, 1800000, 1400000, 0, 0, 0],
    [6, 22000000, 11, 13, 550, 1300, 275.0, 650.0, 2200.0, 11.0, 1300000, 1100000, 0, 0, 0],
    [6, 18000000, 7, 8, 350, 700, 175.0, 350.0, 1400.0, 6.0, 1600000, 1300000, 0, 0, 0],
]

SQL_INSERT = (
    "INSERT INTO flow_features "
    "(target_host, target_ip, create_time, "
    "protocol, flow_duration, total_fwd_packets, total_backward_packets, "
    "fwd_packet_length_max, bwd_packet_length_max, "
    "fwd_packet_length_mean, bwd_packet_length_mean, "
    "flow_bytes_per_sec, flow_packets_per_sec, "
    "fwd_iat_mean, bwd_iat_mean, "
    "syn_flag_count, fin_flag_count, rst_flag_count) "
    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)

# ============================================================================
# DB 注入
# ============================================================================

def _perturb(base: List, pct: float = 0.03) -> List:
    """给特征向量添加 ±pct 随机扰动，保持在决策边界内。"""
    vec = [int(base[0])]  # protocol 不变
    for i in range(1, 15):
        val = base[i]
        if isinstance(val, float) or i in (1, 4, 5, 6, 7, 8, 9, 10, 11):
            vec.append(max(0, round(val * random.uniform(1 - pct, 1 + pct), 2)))
        else:
            vec.append(max(0, int(val * random.uniform(1 - pct, 1 + pct))))
    return vec


def inject_db(
    attack_types: Optional[List[str]] = None,
    count_per_type: int = 5,
    include_benign: bool = True,
    benign_count: int = 10,
    reset: bool = False,
) -> int:
    """向 flow_features 注入攻击和正常流量特征行。"""
    import pymysql

    if attack_types is None:
        selected = list(ATTACK_FINGERPRINTS.keys())
    else:
        selected = [k for k in attack_types if k in ATTACK_FINGERPRINTS]
        missing = set(attack_types) - set(selected)
        if missing:
            print(f"  [!] 未知攻击类型: {missing}")

    if not selected:
        return 0

    rows = []
    now = datetime.datetime.now()
    attack_count = 0

    for atype in selected:
        info = ATTACK_FINGERPRINTS[atype]
        tmpl = info["vectors"]
        for i in range(count_per_type):
            base = tmpl[i % len(tmpl)]
            vec = _perturb(list(base))
            rows.append(("攻击模拟", "10.0.0.99", now, vec, info["label"]))
            attack_count += 1

    if include_benign:
        for i in range(benign_count):
            base = random.choice(BENIGN_TEMPLATES)
            vec = _perturb(list(base), pct=0.05)
            rows.append(("正常模拟", "192.168.1.100", now, vec, "Normal"))

    random.shuffle(rows)

    conn = pymysql.connect(
        host="127.0.0.1", port=3306, user="AIIDS", password="123456",
        database="ai_ids_system", charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        cur = conn.cursor()
        if reset:
            cur.execute("DELETE FROM flow_features")
            conn.commit()
            print("  [reset] 已清空 flow_features")

        batch = []
        for h, ip, ts, v, _ in rows:
            batch.append([h, ip, ts] + v)
        cur.executemany(SQL_INSERT, batch)
        conn.commit()
        total = len(batch)

        cur.execute(
            "UPDATE flow_features SET ai_processed=0, predict_time=NULL "
            "WHERE ai_processed=1 AND create_time>=%s", (now,)
        )
        conn.commit()
        cur.close()

        normal_cnt = benign_count if include_benign else 0
        print(f"  [OK] 注入 {total} 条 (攻击={total - normal_cnt}, 正常={normal_cnt})")
        return total
    except pymysql.Error as e:
        print(f"  [ERROR] 数据库写入失败: {e}")
        conn.rollback()
        return 0
    finally:
        conn.close()


# ============================================================================
# Scapy 发包 — 生成攻击模式的流统计特征
# ============================================================================

SCAPY_OK = False
try:
    from scapy.all import IP, TCP, Raw, send
    SCAPY_OK = True
except ImportError:
    pass


def _scapy_port_scan(target_ip: str, count: int = 50) -> None:
    """SYN扫描 → 大量短流(1fwd/0bwd/0payload) → PortScan 特征。"""
    print(f"  [PortScan] 发送 {count} 个SYN包到 {target_ip} 端口1-1024 ...")
    sport_base = random.randint(40000, 50000)
    for i in range(count):
        port = random.randint(1, 1024)
        pkt = IP(dst=target_ip) / TCP(sport=sport_base + i, dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.001)
    print(f"  [PortScan] 完成 — 预期产生 {count} 个独立短流")


def _scapy_ddos(target_ip: str, target_port: int = 80, count: int = 300) -> None:
    """多源SYN洪水 → 大量流(1fwd/0bwd) → DDoS 特征。"""
    print(f"  [DDoS] 多源SYN洪水 {count} 个包 → {target_ip}:{target_port} ...")
    for i in range(count):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport = random.randint(10000, 65535)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.0005)
    print(f"  [DDoS] 完成")


def _scapy_dos_hulk(target_ip: str, target_port: int = 80, count: int = 200) -> None:
    """高并发HTTP POST → 大量前向大载荷 → DoS Hulk 特征。"""
    print(f"  [DoS Hulk] 高并发 {count} 个POST → {target_ip}:{target_port} ...")
    sport = random.randint(50000, 60000)
    payload = b"POST / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nContent-Length: 1200\r\n\r\n" + b"A" * 1200
    for _ in range(count):
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.002)
    print(f"  [DoS Hulk] 完成")


def _scapy_slowloris(target_ip: str, target_port: int = 80, duration: int = 15) -> None:
    """慢速HTTP → 极长时延，极少包 → slowloris 特征。"""
    print(f"  [DoS slowloris] 慢速连接 {target_ip}:{target_port}，持续 {duration}s ...")
    sport = random.randint(50000, 60000)
    send(IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") /
         Raw(load=b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n"), verbose=False)
    for i in range(duration):
        time.sleep(1)
        send(IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A") /
             Raw(load=b"Keep-Alive: " + bytes([i % 256])), verbose=False)
    print(f"  [DoS slowloris] 完成")


def _scapy_bot(target_ip: str, target_port: int = 80, count: int = 10) -> None:
    """低频心跳 → 双向均衡小包 → Bot 特征。"""
    print(f"  [Bot] 低频心跳 {count} 次 → {target_ip}:{target_port} ...")
    sport = random.randint(50000, 60000)
    for i in range(count):
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") / Raw(
            load=b"GET /status HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
        )
        send(pkt, verbose=False)
        time.sleep(1.0)
    print(f"  [Bot] 完成")


def _scapy_patator(target_ip: str, port: int, count: int = 100) -> None:
    """暴力破解 → 大量短报文 → SSH/FTP-Patator 特征。"""
    name = "FTP" if port == 21 else "SSH"
    print(f"  [{name}-Patator] {count} 次爆破尝试 → {target_ip}:{port} ...")
    for _ in range(count):
        sport = random.randint(50000, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="PA") / Raw(
            load=b"USER admin\r\nPASS " + bytes([random.randint(0, 255)]) + b"\r\n"
        )
        send(pkt, verbose=False)
        time.sleep(0.005)
    print(f"  [{name}-Patator] 完成")


SCAPY_ATTACKS = {
    "PortScan": lambda ip, port: _scapy_port_scan(ip),
    "DDoS": lambda ip, port: _scapy_ddos(ip, port),
    "DoS_Hulk": lambda ip, port: _scapy_dos_hulk(ip, port),
    "DoS_slowloris": lambda ip, port: _scapy_slowloris(ip, port),
    "Bot": lambda ip, port: _scapy_bot(ip, port),
    "FTP_Patator": lambda ip, port: _scapy_patator(ip, 21),
    "SSH_Patator": lambda ip, port: _scapy_patator(ip, 22),
}


def run_scapy_attacks(
    target_ip: str,
    target_port: int = 80,
    attacks: Optional[List[str]] = None,
    delay_between: float = 2.0,
) -> None:
    """发送真实攻击数据包。"""
    if not SCAPY_OK:
        print("[FATAL] Scapy 未安装！请: pip install scapy")
        print("        可改用 DB 注入模式: python generate_test_traffic.py")
        sys.exit(1)

    selected = list(SCAPY_ATTACKS.keys()) if attacks is None else [a for a in attacks if a in SCAPY_ATTACKS]
    if not selected:
        print("  无可执行的攻击类型")
        return

    print(f"\n{'='*60}")
    print(f"  Scapy 攻击发包")
    print(f"{'='*60}")
    print(f"  目标     : {target_ip}:{target_port}")
    print(f"  攻击类型 : {len(selected)} 种")
    print(f"  需要     : 管理员权限 + traffic_monitor 运行中")
    print(f"{'='*60}\n")

    try:
        for atype in selected:
            print(f"{'─'*40}")
            try:
                SCAPY_ATTACKS[atype](target_ip, target_port)
            except PermissionError:
                print(f"  [ERROR] 权限不足！请以管理员身份运行")
                break
            except Exception as e:
                print(f"  [WARN] {atype} 异常: {e}")
            time.sleep(delay_between)
    except KeyboardInterrupt:
        print("\n  用户中断")

    print(f"\n{'='*60}")
    print(f"  发包完成 — 等待 {60}s 让 Flow 超时回收，然后:")
    print(f"    python main.py --once")
    print(f"{'='*60}")


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-IDS 测试流量生成器 — 生成可被 AI 识别的攻击流量",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            快速开始:
              python generate_test_traffic.py --all       # 清空后注入全部攻击
              python main.py --once                       # AI 检测

              python generate_test_traffic.py --types DDoS,PortScan  # 指定类型
              python generate_test_traffic.py --mixed --target 10.20.101.246  # DB注入+发包
        """),
    )

    # ── 模式 ──
    mode = parser.add_argument_group("运行模式")
    mode.add_argument("--scapy-only", action="store_true",
                      help="仅 Scapy 发包（不写DB，需管理员权限）")
    mode.add_argument("--mixed", action="store_true",
                      help="DB注入 + Scapy 发包 同时进行")
    mode.add_argument("--list", action="store_true",
                      help="列出所有可模拟的攻击类型")

    # ── DB 注入参数 ──
    db_group = parser.add_argument_group("DB 注入参数")
    db_group.add_argument("--types", "-t", default=None,
                          help="攻击类型（逗号分隔），默认全部")
    db_group.add_argument("--count", "-c", type=int, default=5,
                          help="每种攻击样例数（默认 5）")
    db_group.add_argument("--benign", "-b", type=int, default=10,
                          help="正常流量条数（默认 10，0=不混入）")
    db_group.add_argument("--all", action="store_true",
                          help="清空 flow_features 后重新注入")

    # ── Scapy 参数 ──
    scapy_group = parser.add_argument_group("Scapy 发包参数")
    scapy_group.add_argument("--target", default="127.0.0.1",
                             help="目标 IP 地址（默认 127.0.0.1）")
    scapy_group.add_argument("--port", "-p", type=int, default=80,
                             help="目标端口（默认 80）")
    scapy_group.add_argument("--delay", type=float, default=2.0,
                             help="每种攻击间隔秒数（默认 2.0）")

    # ── 循环 ──
    loop_group = parser.add_argument_group("循环模式")
    loop_group.add_argument("--loop", "-l", type=float, default=0,
                            help="每 N 秒循环注入一轮（0=单轮）")

    args = parser.parse_args()

    # ── --list ──
    if args.list:
        print(f"\n{'='*60}")
        print(f"  可模拟的 {len(ATTACK_FINGERPRINTS)} 种攻击 (v3 15维特征)")
        print(f"{'='*60}")
        for k, v in ATTACK_FINGERPRINTS.items():
            print(f"  {v['label']:<30s} {v['risk']:<10s} {v['desc']}")
        print()
        print(f"  DB 注入模式: 全部 {len(ATTACK_FINGERPRINTS)} 种（100%% 可靠）")
        print(f"  Scapy 模式 : {len(SCAPY_ATTACKS)} 种（需管理员权限）")
        return

    # ── 解析攻击类型 ──
    attack_types = None
    if args.types:
        attack_types = [x.strip() for x in args.types.split(",")]

    # ── 单轮执行 ──
    def _run_once():
        do_db = not args.scapy_only
        do_scapy = args.scapy_only or args.mixed

        if do_db:
            print(f"\n{'='*60}")
            print(f"  AI-IDS 测试流量生成器 — DB 注入")
            print(f"{'='*60}")
            print(f"  攻击类型 : {'全部' + str(len(ATTACK_FINGERPRINTS)) + '种' if attack_types is None else str(len(attack_types)) + '种'}")
            print(f"  每种样例 : {args.count}")
            print(f"  正常流量 : {args.benign} 条")
            if args.all:
                print(f"  模式     : 清空后注入")

            total = inject_db(attack_types, args.count, args.benign > 0, args.benign, args.all)
            if total > 0:
                selected = attack_types if attack_types else list(ATTACK_FINGERPRINTS.keys())
                print(f"\n  注入完成! 下一步: python main.py --once")
                print(f"  预期检测到 {len(selected)} 种攻击类型 ({args.count * len(selected)} 条攻击记录)")

        if do_scapy:
            scapy_atks = attack_types
            run_scapy_attacks(args.target, args.port, scapy_atks, args.delay)

    # ── 循环模式 ──
    if args.loop > 0:
        print(f"\n  循环模式: 每 {args.loop:.0f}s 一轮 | Ctrl+C 停止\n")
        round_num = 0
        try:
            while True:
                round_num += 1
                print(f"\n{'█'*60}")
                print(f"  第 {round_num} 轮")
                print(f"{'█'*60}")
                _run_once()
                time.sleep(args.loop)
        except KeyboardInterrupt:
            print(f"\n  已停止，共 {round_num} 轮")
    else:
        _run_once()


if __name__ == "__main__":
    main()
