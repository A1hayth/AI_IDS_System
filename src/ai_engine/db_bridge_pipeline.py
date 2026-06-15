# -*- coding: utf-8 -*-
"""
@File    : db_bridge_pipeline.py
@Comment : 连接 flow_features 原始特征表与 traffic_logs 安全审计表的 AI 数据中继集成管线
"""

import os
import sys
import time
import datetime
import mysql.connector
from mysql.connector import Error
import numpy as np

# 确保核心路径能正常加载根目录下的 config 或模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# 导入您的 AI 检测模型声明（取决于您的 predictor.py 路径）
from predictor import Detector


class DatabaseConfig:
    """MySQL 数据库连接配置参数。"""

    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "AIIDS"
    password: str = "123456"
    database: str = "ai_ids_system"

    # 连接池/重连参数
    connect_timeout: int = 10
    read_timeout: int = 30
    write_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 2.0
    charset: str = "utf8mb4"


def get_db_connection():
    """带重试机制的安全数据库连接生成器。"""
    for attempt in range(1, DatabaseConfig.max_retries + 1):
        try:
            conn = mysql.connector.connect(
                host=DatabaseConfig.host,
                port=DatabaseConfig.port,
                user=DatabaseConfig.user,
                password=DatabaseConfig.password,
                database=DatabaseConfig.database,
                charset=DatabaseConfig.charset,
                connect_timeout=DatabaseConfig.connect_timeout
            )
            if conn.is_connected():
                return conn
        except Error as e:
            print(f"⚠️ [Attempt {attempt}] 数据库连接失败: {e}")
            if attempt < DatabaseConfig.max_retries:
                time.sleep(DatabaseConfig.retry_delay)
            else:
                raise e
    return None


def calculate_severity(attack_type: str) -> str:
    """根据 XGBoost 分类决策结果，映射威胁评级 (severity)。"""
    high_threats = ["DoS Hulk", "DoS slowloris", "DDoS", "Infiltration"]
    medium_threats = ["PortScan", "Bot", "Web Attack"]
    
    if attack_type == "Benign" or attack_type == "Normal":
        return "Low"
    elif attack_type in high_threats:
        return "High"
    elif attack_type in medium_threats:
        return "Medium"
    else:
        return "Medium"


def generate_ai_reason(features: list, attack_type: str) -> str:
    """
    根据物理指标度量，自适应拼装一条极具信度的中文 AI 分析判定理由
    features 格式: [Protocol, Flow Duration, Total Fwd, Total Bwd, Fwd Max, Bwd Max]
    """
    proto = "TCP" if features[0] == 6 else "UDP" if features[0] == 17 else f"Protocol({features[0]})"
    duration = features[1]
    fwd_pkts = features[2]
    bwd_pkts = features[3]
    fwd_len_max = features[4]
    
    if attack_type == "Benign":
        return f"会话流传输特征均衡，底层协议为 {proto}，前向与反向数据包比对正常，判定为常规无害会话。"
    
    elif attack_type == "DoS Hulk":
        return f"检测到瞬时高并发前向载荷。前向数据包最高长度达到 {fwd_len_max}B，前向总报文数 ({fwd_pkts}) 极其畸高。流量模型与 HTTP Hulk 拒绝服务特征强吻合。"
    
    elif attack_type == "DoS slowloris":
        return f"流持续时间极长 (持续 {duration:.1f} 微秒)，而交互交互的报文总数极低 (仅 {fwd_pkts + bwd_pkts} 个包)。该低频连接涉嫌利用 Slowloris 精确榨干服务器工作线程池。"
    
    elif attack_type == "DDoS":
        return f"检测到高密度不对称流量突发。前向与后向重定向报文比例严重失衡，前向包数过载 ({fwd_pkts})，判定触发了协同分布式拒绝服务攻击的联动拦截。"
    
    elif attack_type == "PortScan":
        return f"事件流交互生存期极短 ({duration} 微秒) 且前向最大数据分组无应用负载内容 (Fwd Max = 0)。高频微秒侦查动作已被识别为快速 SYN 静默扫描探测。"
    
    elif attack_type == "Bot":
        return f"通信极好地展现了僵尸网络(Botnet)控端与受控主机的低频心跳规律特征，已被自动列为可疑僵尸会话。"
        
    else:
        return f"异常流量检测中命中特征偏移，协议 {proto}，前/后向发包比: {fwd_pkts}/{bwd_pkts}，判定该攻击分类为 [{attack_type}]。"


def run_pipeline_step(detector, processed_ids):
    """
    单步预测执行。
    1. 从 flow_features 提取未进行判定及最新的未审计数据。
    2. 基于 XGBoost 推理得出 attack_type。
    3. 自适应对准并安全落库到 traffic_logs 日志表。
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return

        cursor = conn.cursor(dictionary=True)

        # A. 拉取 flow_features 中还未被处理的新特征行（可以使用记录 ID 过滤）
        # 这里为了避免重复查询，我们在内存处理，或者通过 processed_ids 集合追溯
        if processed_ids:
            query = f"SELECT * FROM flow_features WHERE id NOT IN ({','.join(map(str, processed_ids))}) ORDER BY id ASC LIMIT 50"
        else:
            query = "SELECT * FROM flow_features ORDER BY id DESC LIMIT 50"

        cursor.execute(query)
        rows = cursor.fetchall()

        if not rows:
            return  # 暂无未处理的新流量

        print(f"🎮 捕获到 {len(rows)} 条未预测的流量特征行，开始通过 XGBoost 引擎转换决策...")

        # 准备插入到 traffic_logs 表
        insert_sql = """
            INSERT INTO traffic_logs (
                timestamp, client_ip, is_attack, attack_type, severity, ai_reason
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """

        log_insert_samples = []
        newly_processed = []

        for row in rows:
            record_id = row['id']
            newly_processed.append(record_id)

            # 1. 严格按照您的 preprocess.py SELECTED_FEATURES 物理对齐特征顺序 (6 个特征)
            # SELECTED_FEATURES: ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Max', 'Bwd Packet Length Max']
            feature_vector = [
                row['protocol'],
                row['flow_duration'],
                row['total_fwd_packets'],
                row['total_backward_packets'],
                row['fwd_packet_length_max'],
                row['bwd_packet_length_max']
            ]

            # 2. 调用您的模型进行预测
            # predictor.py 会底层自动调用 np.array(feature_values).reshape(1, -1) -> scaler -> model -> LabelEncoder 反转
            attack_type = detector.predict(feature_vector)

            # 自适应标签清洗修正
            if attack_type == "BENIGN" or attack_type == "Benign":
                is_attack = 0
                cleansed_attack_type = "Normal"
            else:
                is_attack = 1
                cleansed_attack_type = attack_type

            # 3. 关联映射字段
            timestamp = row['create_time'] or datetime.datetime.now()
            client_ip = row['target_ip'] if row['target_ip'] else "127.0.0.1" # 异常发起 IP
            severity = calculate_severity(cleansed_attack_type)
            ai_reason = generate_ai_reason(feature_vector, cleansed_attack_type)

            log_insert_samples.append((
                timestamp,
                client_ip,
                is_attack,
                cleansed_attack_type,
                severity,
                ai_reason
            ))

        # B. 批量写入到 traffic_logs
        if log_insert_samples:
            cursor.executemany(insert_sql, log_insert_samples)
            conn.commit()
            print(f"💾 转换完成，已成功将 {len(log_insert_samples)} 条判定特征流批量追加写入『traffic_logs』安全判定表中！")

        # 将这些已处理的 ID 更新进集合，防止下次循环重复预测
        processed_ids.update(newly_processed)

    except Error as e:
        print(f"❌ 流程遇到数据库异常: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def main():
    print("====================================================")
    print("🚀 AI-IDS 自适应动态数据库安全映射主程及集成桥接器启动！")
    print("====================================================")
    
    # 实例化并初始化您的 Detector AI预测引擎
    print("⏳ 正在载入 XGBoost 网络入侵分类算法权重结构...")
    try:
        detector = Detector()
    except Exception as e:
        print(f"❌ 初始化 AI 检测引擎或加载 persistent scaler/model/encoder 被迫中断：{e}")
        return

    # 本地已处理特征行缓存避开重复计算
    processed_ids = set()

    print("🔎 安全守护进程已完成对 flow_features 纸面指标表的定时监听侦测...")
    
    # 每 3 秒自动轮询未落库的流量记录，并快速完成机器学习预测落地到 traffic_logs 表
    while True:
        run_pipeline_step(detector, processed_ids)
        time.sleep(3.0)


if __name__ == "__main__":
    main()