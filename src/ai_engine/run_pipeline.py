# -*- coding: utf-8 -*-
"""
AI-IDS 单次检测管线 —— 从 flow_features 读取特征 → AI 推理 → 写入 traffic_logs

与 db_bridge_pipeline.py 的区别:
  - 一次性执行，非守护进程轮询
  - 使用 pymysql (与 Flask 后端一致，无需 mysql.connector)
  - 支持增量处理 (已处理过的 flow_features 行不会重复写入)

用法:
    cd src/ai_engine
    python run_pipeline.py              # 处理所有未写入 traffic_logs 的新行
    python run_pipeline.py --all        # 清空 traffic_logs 后重新全量处理
    python run_pipeline.py --dry-run    # 仅预测并打印，不写入数据库
"""

import os
import sys
import argparse
import datetime
import pymysql

# ── Windows GBK 编码兼容 ──────────────────────────────────────
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ── 路径 & 导入 ────────────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.ai_engine.predictor import Detector

# ── 数据库配置 (与 web/backend/config.py 保持一致) ──────────────
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'AIIDS',
    'password': '123456',
    'database': 'ai_ids_system',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,
    'autocommit': False,
}

# ── 6 个模型特征 (必须与 preprocess.py SELECTED_FEATURES 严格对齐) ──
FEATURE_COLUMNS = [
    'protocol',
    'flow_duration',
    'total_fwd_packets',
    'total_backward_packets',
    'fwd_packet_length_max',
    'bwd_packet_length_max',
]


def get_connection():
    """建立 MySQL 数据库连接"""
    try:
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except pymysql.Error as e:
        print(f"[ERROR] 数据库连接失败: {e}")
        sys.exit(1)


def calculate_severity(attack_type: str) -> str:
    """根据攻击类型映射威胁等级"""
    high = {"DoS Hulk", "DoS slowloris", "DDoS", "Infiltration"}
    medium = {"PortScan", "Bot", "Web Attack", "Web Attack - Brute Force",
              "Web Attack - XSS", "Web Attack - Sql Injection"}
    if attack_type in ("Benign", "Normal"):
        return "Low"
    if attack_type in high:
        return "High"
    if attack_type in medium:
        return "Medium"
    # 未知攻击类型默认 Medium
    return "Medium"


def generate_ai_reason(features: list, attack_type: str) -> str:
    """
    根据特征值生成中文 AI 判定理由
    features: [protocol, flow_duration, total_fwd, total_bwd, fwd_max, bwd_max]
    """
    proto_map = {6: "TCP", 17: "UDP"}
    proto = proto_map.get(features[0], f"Protocol({features[0]})")
    duration = features[1]
    fwd_pkts = int(features[2])
    bwd_pkts = int(features[3])
    fwd_len_max = int(features[4])
    total_pkts = fwd_pkts + bwd_pkts

    if attack_type in ("Benign", "Normal"):
        return (f"流量特征均衡，协议 {proto}，前向/反向报文比 {fwd_pkts}/{bwd_pkts}，"
                f"流持续时间 {duration:.2f}μs，判定为常规无害会话。")
    elif attack_type == "DoS Hulk":
        return (f"检测到瞬时高并发前向载荷。前向报文最大长度 {fwd_len_max}B，"
                f"前向总报文数 ({fwd_pkts}) 异常偏高，与 HTTP Hulk DoS 特征强吻合。")
    elif attack_type == "DoS slowloris":
        return (f"流持续时间极长 ({duration:.1f}μs)，而报文总数极低 (仅 {total_pkts} 个包)，"
                f"涉嫌利用 Slowloris 耗尽服务器线程池。")
    elif attack_type == "DDoS":
        return (f"检测到高密度不对称流量突发。前/反向报文比例严重失衡，"
                f"前向包数 {fwd_pkts}，判定为协同分布式拒绝服务攻击。")
    elif attack_type == "PortScan":
        return (f"流生存期极短 ({duration:.2f}μs) 且前向最大报文无应用负载 (Fwd Max=0)，"
                f"识别为快速 SYN 静默扫描探测。")
    elif attack_type == "Bot":
        return (f"通信模式展现僵尸网络(Botnet)控端与受控主机的低频心跳特征，"
                f"已标记为可疑僵尸会话。")
    elif "Web Attack" in attack_type:
        return (f"检测到 Web 应用层攻击特征，协议 {proto}，前向报文最大长度 {fwd_len_max}B，"
                f"分类为 [{attack_type}]。")
    else:
        return (f"异常流量命中特征偏移，协议 {proto}，前/反向发包比 {fwd_pkts}/{bwd_pkts}，"
                f"判定攻击分类为 [{attack_type}]。")


def get_processed_flow_ids(conn) -> set:
    """
    返回 traffic_logs 中已处理过的 flow_features.id 集合。
    flow_id 作为唯一键，保证每个 flow_features 行只生成一条 traffic_logs 记录。
    """
    cur = conn.cursor()
    cur.execute("SELECT flow_id FROM traffic_logs WHERE flow_id IS NOT NULL")
    existing = set(row['flow_id'] for row in cur.fetchall())
    cur.close()
    return existing


def run_pipeline(dry_run: bool = False, reset_all: bool = False):
    """核心管线：读取 flow_features → AI 预测 → 写入 traffic_logs"""
    conn = get_connection()

    print("=" * 60)
    print("  AI-IDS 智能检测管线")
    print("  flow_features → XGBoost Detector → traffic_logs")
    print("=" * 60)

    # ── 初始化 AI 检测器 ──────────────────────────────────────
    print("\n[1/4] 加载 AI 检测模型...")
    try:
        detector = Detector()
    except Exception as e:
        print(f"[ERROR] 无法初始化检测器: {e}")
        conn.close()
        sys.exit(1)

    # ── 读取流量特征 ──────────────────────────────────────────
    print("[2/4] 从 flow_features 读取流量特征...")
    cur = conn.cursor()

    if reset_all:
        cur.execute("DELETE FROM traffic_logs")
        conn.commit()
        print("      已清空 traffic_logs 表，将全量重新处理。")

    cur.execute("SELECT * FROM flow_features ORDER BY id ASC")
    all_rows = cur.fetchall()
    cur.close()

    if not all_rows:
        print("      flow_features 表中暂无数据，退出。")
        conn.close()
        return

    print(f"      共读取 {len(all_rows)} 条流量特征记录")

    # ── 获取已处理 flow_id 用于去重 ──────────────────────
    processed_ids = set() if reset_all else get_processed_flow_ids(conn)
    if processed_ids:
        print(f"      已存在 {len(processed_ids)} 条 traffic_logs 记录，将跳过已处理行")

    # ── AI 推理 ──────────────────────────────────────────────
    print("[3/4] 执行 AI 推理判定...")
    insert_rows = []
    skipped = 0

    for idx, row in enumerate(all_rows):
        # 1. 提取 6 维特征向量 (与训练时顺序严格一致)
        feature_vector = [row[col] for col in FEATURE_COLUMNS]

        # 2. AI 预测
        attack_type = detector.predict(feature_vector)

        # 3. 清洗标签
        if str(attack_type).upper() in ('BENIGN', 'NORMAL'):
            is_attack = 0
            clean_type = "Normal"
        else:
            is_attack = 1
            clean_type = str(attack_type)

        # 4. 去重检查：以 flow_id (即 flow_features.id) 为唯一键
        flow_id = row['id']
        if flow_id in processed_ids:
            skipped += 1
            continue
        # 立即加入已处理集合，防止同批次内重复
        processed_ids.add(flow_id)

        # 5. 映射流量日志字段
        timestamp = row['create_time'] or datetime.datetime.now()
        client_ip = row['target_ip'] or '0.0.0.0'
        severity = calculate_severity(clean_type)
        ai_reason = generate_ai_reason(feature_vector, clean_type)

        insert_rows.append((timestamp, client_ip, is_attack, clean_type, severity, ai_reason, flow_id))

        if (idx + 1) % 20 == 0:
            print(f"      已处理 {idx + 1}/{len(all_rows)} ...")

    print(f"      推理完成: 新增 {len(insert_rows)} 条, 跳过 {skipped} 条重复")

    # ── 写入结果 ──────────────────────────────────────────────
    print("[4/4] 写入流量与拦截日志表 (traffic_logs)...")
    if not insert_rows:
        print("      无新数据需要写入。")
        conn.close()
        return

    if dry_run:
        print(f"\n      [DRY-RUN 模式] 以下为前 10 条预测结果 (不写入数据库):\n")
        print(f"      {'flow_id':<8} {'时间':<22} {'来源IP':<18} {'攻击?':<6} {'攻击类型':<22} {'等级':<8} {'AI理由':<50}")
        print(f"      {'─'*8} {'─'*22} {'─'*18} {'─'*6} {'─'*22} {'─'*8} {'─'*50}")
        for fid, ts, ip, is_att, atype, sev, reason in insert_rows[:10]:
            ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if hasattr(ts, 'strftime') else str(ts)
            print(f"      {fid:<8} {ts_str:<22} {ip:<18} {'Yes' if is_att else 'No':<6} {atype:<22} {sev:<8} {reason[:48]:<50}")
        if len(insert_rows) > 10:
            print(f"      ... 共 {len(insert_rows)} 条")
    else:
        cur = conn.cursor()
        insert_sql = """
            INSERT INTO traffic_logs
                (timestamp, client_ip, is_attack, attack_type, severity, ai_reason, flow_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cur.executemany(insert_sql, insert_rows)
        conn.commit()
        cur.close()
        print(f"      成功写入 {len(insert_rows)} 条检测日志到 traffic_logs 表！")

    conn.close()
    print("\n  管线执行完成。\n")


def main():
    parser = argparse.ArgumentParser(description='AI-IDS 单次检测管线')
    parser.add_argument('--dry-run', action='store_true',
                        help='仅预测并打印，不写入数据库')
    parser.add_argument('--all', action='store_true',
                        help='清空 traffic_logs 后全量重新处理')
    args = parser.parse_args()
    run_pipeline(dry_run=args.dry_run, reset_all=args.all)


if __name__ == '__main__':
    main()
