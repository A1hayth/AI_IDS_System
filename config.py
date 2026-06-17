# -*- coding: utf-8 -*-
"""
AI-IDS 统一配置中心 —— 全局路径、特征定义、模型超参数

所有模块必须从此文件导入配置，保证全链路一致性。
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
# 核心特征定义（全链路统一使用此定义）
# ============================================================================
# 数据库列名（MySQL 实际存储的列名，Mixed_Case）
DB_FEATURE_COLUMNS = [
    "Protocol",
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Fwd_Packet_Length_Max",
    "Bwd_Packet_Length_Max",
]

# 模型内部使用的标准化列名（lowercase，train.py / predictor.py 内部统一）
MODEL_FEATURE_COLUMNS = [
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "fwd_packet_length_max",
    "bwd_packet_length_max",
]

# DB列名 → 模型列名 映射
DB_TO_MODEL_COLUMN_MAP = dict(zip(DB_FEATURE_COLUMNS, MODEL_FEATURE_COLUMNS))

# 模型列名 → DB列名 映射
MODEL_TO_DB_COLUMN_MAP = dict(zip(MODEL_FEATURE_COLUMNS, DB_FEATURE_COLUMNS))

# 兼容旧代码的 SELECTED_FEATURES（Mixed_Case，供 config.py 老引用者使用）
SELECTED_FEATURES = list(DB_FEATURE_COLUMNS)

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
# XGBoost 训练超参数（优化后）
# ============================================================================
XGB_PARAMS = {
    "n_estimators": 200,           # 从 100 提升到 200
    "max_depth": 8,                # 从 6 提升到 8，增强表达能力
    "learning_rate": 0.05,         # 从 0.1 降低到 0.05，更精细
    "subsample": 0.8,              # 新增：防止过拟合
    "colsample_bytree": 0.8,       # 新增：特征采样
    "objective": "multi:softprob", # 多分类概率输出
    "eval_metric": "mlogloss",
    "random_state": 42,
    "n_jobs": -1,
    "verbosity": 0,
}

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
