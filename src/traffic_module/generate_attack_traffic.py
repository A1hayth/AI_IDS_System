# -*- coding: utf-8 -*-
"""
AI-IDS 攻击流量模拟器 (v3) — 生成 15 维攻击特征流量测试 AI 检测引擎。

v3 更新:
    - 攻击指纹从 6 维扩展到 15 维（与 v3 模型一致）
    - 指纹数据从 CIC-IDS-2017 真实数据中位数提取，已通过模型验证
    - DB INSERT 适配 15+ 特征列

用法:
    python generate_attack_traffic.py                     # DB注入全部12种攻击
    python generate_attack_traffic.py --count 10          # 每种攻击10条
    python generate_attack_traffic.py --types DDoS,PortScan  # 仅指定类型
    python generate_attack_traffic.py --all               # 清空flow_features后注入
    python generate_attack_traffic.py --scapy             # Scapy真实发包模式
    python generate_attack_traffic.py --list              # 列出所有攻击类型
"""

import argparse
import datetime
import os
import random
import sys
import time
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC_DIR = os.path.join(_PROJECT_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# ============================================================================
# 攻击特征指纹库 (v3: 15 维 — 从 CIC-IDS-2017 中位数提取，已通过模型验证)
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
        "desc": "僵尸网络心跳 — 中等时长，双向IAT均高(27K/40K μs)",
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


# ============================================================================
# DB 注入 (v3: 15 特征列)
# ============================================================================

def inject_db(
    attack_types: Optional[List[str]] = None,
    count_per_type: int = 5,
    include_benign: bool = True,
    benign_count: int = 10,
    reset: bool = False,
) -> int:
    import pymysql

    if attack_types is None:
        selected = list(ATTACK_FINGERPRINTS.keys())
    else:
        selected = [k for k in attack_types if k in ATTACK_FINGERPRINTS]
        missing = set(attack_types) - set(selected)
        if missing:
            print(f"  [!] 未知类型: {missing}")

    if not selected:
        return 0

    rows: List[Tuple] = []
    now = datetime.datetime.now()

    for atype in selected:
        info = ATTACK_FINGERPRINTS[atype]
        tmpl = info["vectors"]
        for i in range(count_per_type):
            base = list(tmpl[i % len(tmpl)])
            # 添加小幅随机扰动（±3% 以保持在决策边界内）
            vec = [
                int(base[0]),                                    # protocol
                max(0, int(base[1] * random.uniform(0.97, 1.03))),  # flow_duration
                max(0, int(base[2] * random.uniform(0.97, 1.03))),  # total_fwd
                max(0, int(base[3] * random.uniform(0.97, 1.03))),  # total_bwd
                max(0, int(base[4] * random.uniform(0.97, 1.03))),  # fwd_max
                max(0, int(base[5] * random.uniform(0.97, 1.03))),  # bwd_max
                max(0, round(base[6] * random.uniform(0.97, 1.03), 2)),  # fwd_mean
                max(0, round(base[7] * random.uniform(0.97, 1.03), 2)),  # bwd_mean
                max(0, round(base[8] * random.uniform(0.97, 1.03), 2)),  # bytes_ps
                max(0, round(base[9] * random.uniform(0.97, 1.03), 2)),  # pkts_ps
                max(0, round(base[10] * random.uniform(0.97, 1.03), 2)), # fwd_iat
                max(0, round(base[11] * random.uniform(0.97, 1.03), 2)), # bwd_iat
                int(base[12]),                                    # syn_cnt
                int(base[13]),                                    # fin_cnt
                int(base[14]),                                    # rst_cnt
            ]
            rows.append(("攻击模拟", "10.0.0.99", now, vec, f"{info['label']}_#{i+1}"))

    if include_benign:
        for i in range(benign_count):
            base = list(random.choice(BENIGN_TEMPLATES))
            vec = [
                int(base[0]),
                max(0, int(base[1] * random.uniform(0.97, 1.03))),
                max(0, int(base[2] * random.uniform(0.97, 1.03))),
                max(0, int(base[3] * random.uniform(0.97, 1.03))),
                max(0, int(base[4] * random.uniform(0.97, 1.03))),
                max(0, int(base[5] * random.uniform(0.97, 1.03))),
                max(0, round(base[6] * random.uniform(0.97, 1.03), 2)),
                max(0, round(base[7] * random.uniform(0.97, 1.03), 2)),
                max(0, round(base[8] * random.uniform(0.97, 1.03), 2)),
                max(0, round(base[9] * random.uniform(0.97, 1.03), 2)),
                max(0, round(base[10] * random.uniform(0.97, 1.03), 2)),
                max(0, round(base[11] * random.uniform(0.97, 1.03), 2)),
                int(base[12]),
                int(base[13]),
                int(base[14]),
            ]
            rows.append(("正常模拟", "192.168.1.100", now, vec, f"Benign_#{i+1}"))

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

        # v3: 完整 15 特征列 INSERT
        sql = (
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
        batch = [[h, ip, ts] + v for h, ip, ts, v, _lbl in rows]
        cur.executemany(sql, batch)
        conn.commit()
        total = len(batch)

        # 标记新增行为待检测
        cur.execute(
            "UPDATE flow_features SET ai_processed=0, predict_time=NULL "
            "WHERE ai_processed=1 AND create_time>=%s", (now,)
        )
        conn.commit()
        cur.close()
        print(f"  [OK] 注入成功: {total} 条 (攻击={total - (benign_count if include_benign else 0)}, 正常={benign_count if include_benign else 0})")
        return total
    except pymysql.Error as e:
        print(f"  [ERROR] {e}")
        conn.rollback()
        return 0
    finally:
        conn.close()


# ============================================================================
# Scapy 发包 (需要管理员权限)
# ============================================================================

SCAPY_OK = False
try:
    from scapy.all import IP, TCP, Raw, send
    SCAPY_OK = True
except ImportError:
    pass


def _scapy_port_scan(ip, port=80):
    print(f"  [PortScan] 30个SYN -> {ip}")
    for _ in range(30):
        p = IP(dst=ip)/TCP(sport=random.randint(50000, 60000), dport=random.randint(1, 1024), flags="S")
        send(p, verbose=False)
        time.sleep(0.001)

def _scapy_dos_hulk(ip, port=80):
    print(f"  [DoS Hulk] 200个POST -> {ip}:{port}")
    sp = random.randint(60000, 65000)
    pl = b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\n" + b"A"*1000
    for _ in range(200):
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=pl), verbose=False)
        time.sleep(0.002)

def _scapy_ddos(ip, port=80):
    print(f"  [DDoS] 500个SYN flood -> {ip}:{port}")
    for _ in range(500):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        send(IP(src=src, dst=ip)/TCP(sport=random.randint(10000, 65535), dport=port, flags="S"), verbose=False)
        time.sleep(0.0005)

def _scapy_slowloris(ip, port=80):
    print(f"  [slowloris] 慢速15s -> {ip}:{port}")
    sp = random.randint(60000, 65000)
    send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\nHost: t\r\n"), verbose=False)
    for i in range(15):
        time.sleep(1)
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="A")/Raw(load=b"X-Forwarded: 127.0.0."+bytes([i])), verbose=False)

def _scapy_bot(ip, port=80):
    print(f"  [Bot] 心跳 -> {ip}:{port}")
    sp = random.randint(50000, 60000)
    for _ in range(10):
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"), verbose=False)
        time.sleep(1)

def _scapy_web_attack(ip, port=80):
    print(f"  [Web Attack] 50个恶意载荷 -> {ip}:{port}")
    sp = random.randint(60000, 65000)
    payloads = [b"GET /?id=1'OR'1'='1\r\n", b"POST /login\r\n\r\nuser=admin'--", b"GET /?q=<script>alert(1)</script>\r\n"]
    for _ in range(50):
        pl = random.choice(payloads) + b"X"*random.randint(400, 600)
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=pl), verbose=False)
        time.sleep(0.01)

def _scapy_patator(ip, port=21):
    name = "FTP" if port == 21 else "SSH"
    print(f"  [{name} Patator] 100次爆破 -> {ip}:{port}")
    for _ in range(100):
        send(IP(dst=ip)/TCP(sport=random.randint(50000, 65535), dport=port, flags="PA")/Raw(load=b"USER a\r\nPASS "+bytes([random.randint(0, 255)])), verbose=False)
        time.sleep(0.005)

SCAPY_ATTACKS = {
    "PortScan": _scapy_port_scan, "DDoS": _scapy_ddos, "DoS_Hulk": _scapy_dos_hulk,
    "DoS_slowloris": _scapy_slowloris, "Bot": _scapy_bot, "Web_Attack": _scapy_web_attack,
    "FTP_Patator": lambda ip: _scapy_patator(ip, 21),
    "SSH_Patator": lambda ip: _scapy_patator(ip, 22),
}


def run_scapy_mode(target_ip, target_port=80, attacks=None, delay_between=2.0):
    if not SCAPY_OK:
        print("[FATAL] Scapy未安装! pip install scapy"), sys.exit(1)
    selected = list(SCAPY_ATTACKS.keys()) if attacks is None else [a for a in attacks if a in SCAPY_ATTACKS]
    print(f"\n{'='*60}\n  Scapy攻击模拟\n{'='*60}\n  目标:{target_ip}:{target_port}  类型:{len(selected)}种\n  按Enter开始...")
    input()
    try:
        for atype in selected:
            print(f"\n{'─'*40}")
            try:
                SCAPY_ATTACKS[atype](target_ip, target_port) if atype not in ("FTP_Patator", "SSH_Patator") else SCAPY_ATTACKS[atype](target_ip)
            except Exception as e:
                print(f"  [WARN] {e}")
            time.sleep(delay_between)
    except KeyboardInterrupt:
        print("\n  中断")
    print(f"\n{'='*60}\n  完成 -> python main.py --once\n{'='*60}")


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="AI-IDS攻击流量模拟器 (v3: 15维特征)")
    p.add_argument("--scapy", action="store_true", help="Scapy真实发包")
    p.add_argument("--list", action="store_true", help="列出攻击类型")
    p.add_argument("--types", "-t", default=None, help="攻击类型(逗号分隔)")
    p.add_argument("--count", "-c", type=int, default=5, help="每种类型样例数(默认5)")
    p.add_argument("--benign", "-b", type=int, default=10, help="正常流量条数(默认10)")
    p.add_argument("--all", action="store_true", help="清空flow_features后注入")
    p.add_argument("--target", default="127.0.0.1", help="Scapy目标IP")
    p.add_argument("--target-port", type=int, default=80, help="Scapy目标端口")
    p.add_argument("--delay", type=float, default=2.0, help="Scapy攻击间延迟")
    args = p.parse_args()

    if args.list:
        print(f"\n{'='*60}\n  v3 可模拟的 {len(ATTACK_FINGERPRINTS)} 种攻击 (15维特征)\n{'='*60}")
        for k, v in ATTACK_FINGERPRINTS.items():
            print(f"  {v['label']:<30s} {v['risk']:<10s} {v['desc']}")
        return

    if args.scapy:
        scapy_atks = None
        if args.types:
            scapy_atks = [x.strip() for x in args.types.split(",")]
        run_scapy_mode(args.target, args.target_port, scapy_atks, args.delay)
        return

    # DB注入
    atk_types = None
    if args.types:
        atk_types = [x.strip() for x in args.types.split(",")]

    print(f"\n{'='*60}\n  AI-IDS攻击流量模拟器 v3 — DB注入 (15维特征)\n{'='*60}")
    if atk_types:
        print(f"  类型: {len(atk_types)}种")
    else:
        print(f"  类型: 全部{len(ATTACK_FINGERPRINTS)}种")
    print(f"  每种: {args.count}条  正常: {args.benign}条")
    if args.all:
        print(f"  模式: 清空后注入")

    total = inject_db(atk_types, args.count, args.benign > 0, args.benign, args.all)

    if total > 0:
        print(f"\n{'='*60}\n  注入完成: {total}条\n{'='*60}")
        selected = atk_types if atk_types else list(ATTACK_FINGERPRINTS.keys())
        for k in selected:
            v = ATTACK_FINGERPRINTS[k]
            print(f"  {v['label']:<30s} {v['risk']:<10s} {v['desc']}")
        print(f"{'='*60}\n\n  -> python main.py --once    # AI检测\n")


if __name__ == "__main__":
    main()
