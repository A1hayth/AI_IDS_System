# -*- coding: utf-8 -*-
"""
AI-IDS 统一配置中心 —— 全局路径、特征定义、模型超参数

v3 更新:
    - 特征从 6 维扩展到 15 维（精选 CIC-IDS-2017 高区分度特征）
    - 新增 SMOTE 过采样参数
    - XGBoost 超参数优化（正则化、更深树、更多迭代）
    - 所有模块必须从此文件导入配置，保证全链路一致性。
"""
import os
import numpy as np

# ============================================================================
# 路径管理
# ============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_RAW_DIR = os.path.join(BASE_DIR, "archive")
MODELS_DIR = os.path.join(BASE_DIR, "models")

# ============================================================================
# 核心特征定义（v3: 6 → 15 维，全链路统一使用此定义）
# ============================================================================

# 数据库列名（MySQL 实际存储的列名，Mixed_Case — 与 feature_extractor.py 输出一致）
DB_FEATURE_COLUMNS = [
    # --- 6 个基础特征 ---
    "Protocol",
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Fwd_Packet_Length_Max",
    "Bwd_Packet_Length_Max",
    # --- 9 个新增特征 ---
    "Fwd_Packet_Length_Mean",       # 前向平均包长
    "Bwd_Packet_Length_Mean",       # 后向平均包长
    "Flow_Bytes_Per_Sec",           # 流字节速率
    "Flow_Packets_Per_Sec",         # 流包速率
    "Fwd_IAT_Mean",                 # 前向包到达间隔均值
    "Bwd_IAT_Mean",                 # 后向包到达间隔均值
    "SYN_Flag_Count",               # SYN 标志计数
    "FIN_Flag_Count",               # FIN 标志计数
    "RST_Flag_Count",               # RST 标志计数
]

# 模型内部使用的标准化列名（lowercase，train.py / predictor.py 内部统一）
MODEL_FEATURE_COLUMNS = [
    # --- 6 个基础特征 ---
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "fwd_packet_length_max",
    "bwd_packet_length_max",
    # --- 9 个新增特征 ---
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
]

# DB列名 → 模型列名 映射
DB_TO_MODEL_COLUMN_MAP = dict(zip(DB_FEATURE_COLUMNS, MODEL_FEATURE_COLUMNS))

# 模型列名 → DB列名 映射
MODEL_TO_DB_COLUMN_MAP = dict(zip(MODEL_FEATURE_COLUMNS, DB_FEATURE_COLUMNS))

# CIC-IDS-2017 原始列名 → 模型列名（用于训练数据加载）
CIC_TO_MODEL_COLUMN_MAP = {
    # 基础
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_backward_packets",
    "Fwd Packet Length Max": "fwd_packet_length_max",
    "Bwd Packet Length Max": "bwd_packet_length_max",
    # 新增
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "SYN Flag Count": "syn_flag_count",
    "FIN Flag Count": "fin_flag_count",
    "RST Flag Count": "rst_flag_count",
}

# 兼容旧代码的 SELECTED_FEATURES（Mixed_Case）
SELECTED_FEATURES = list(DB_FEATURE_COLUMNS)

# 特征数量（方便引用）
N_FEATURES = len(MODEL_FEATURE_COLUMNS)  # 15

# ============================================================================
# 模型文件路径
# ============================================================================
MODEL_PATH = os.path.join(MODELS_DIR, "xgboost_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# joblib 格式（推荐，跨版本兼容性更好）
XGB_MODEL_FILE = os.path.join(MODELS_DIR, "xgboost_model.joblib")
SCALER_FILE = os.path.join(MODELS_DIR, "scaler.joblib")
LABEL_ENCODER_FILE = os.path.join(MODELS_DIR, "label_encoder.joblib")

# ============================================================================
# XGBoost 训练超参数（v3 优化：更深树 + 正则化 + 更多迭代）
# ============================================================================
XGB_PARAMS = {
    "n_estimators": 300,              # 200 → 300，充分学习
    "max_depth": 10,                  # 8 → 10，增强表达能力
    "learning_rate": 0.03,            # 0.05 → 0.03，更精细
    "subsample": 0.8,                 # 行采样，防过拟合
    "colsample_bytree": 0.8,          # 列采样，防过拟合
    "colsample_bylevel": 0.8,         # 每层列采样
    "reg_alpha": 0.1,                 # L1 正则化
    "reg_lambda": 1.0,                # L2 正则化
    "min_child_weight": 3,            # 叶节点最小权重和
    "objective": "multi:softprob",    # 多分类概率输出
    "eval_metric": "mlogloss",
    "random_state": 42,
    "n_jobs": -1,
    "verbosity": 0,
}

# ============================================================================
# SMOTE 过采样参数
# ============================================================================
SMOTE_PARAMS = {
    "k_neighbors": 5,                 # SMOTE 近邻数
    "sampling_strategy": "auto",      # 自动平衡（除多数类外全部过采样）
    "random_state": 42,
}

# 每类最少样本数（低于此值的类别将被剔除）
MIN_SAMPLES_PER_CLASS = 50

# 训练时每类最大样本数（降采样控制训练规模，限制 SMOTE 目标上限）
MAX_SAMPLES_PER_CLASS = 15000

# ============================================================================
# 推理阈值配置
# ============================================================================
MIN_CONFIDENCE_THRESHOLD = 0.60    # 低于此置信度的预测标记为 "Uncertain"
LOW_CONFIDENCE_WARNING = 0.75     # 低于此置信度的预测在日志中 warn

# ============================================================================
# 协议号映射（保留作为参考）
# ============================================================================
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}

# ============================================================================
# 攻击标签映射
# ============================================================================
BENIGN_LABELS = {"BENIGN", "Benign", "BENIGN", "Normal", "normal"}

# 威胁等级 → 攻击类型映射
CRITICAL_THREATS = {
    "DDoS", "DoS Hulk", "DoS slowloris", "DoS GoldenEye",
    "DoS Slowhttptest", "Heartbleed", "Infiltration",
}
HIGH_THREATS = {
    "Web Attack", "Web Attack - Brute Force", "Web Attack - XSS",
    "Web Attack - Sql Injection", "SQL Injection", "Brute Force",
}
MEDIUM_THREATS = {"PortScan", "Bot", "FTP-Patator", "SSH-Patator"}
