"""
项目配置文件 - 统一管理所有路径和参数
"""
import os

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# 数据路径
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

# 模型路径
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

# 日志和笔记本路径
NOTEBOOKS_DIR = os.path.join(PROJECT_ROOT, "notebooks")

# 模型文件名
XGB_MODEL_FILE = os.path.join(MODELS_DIR, "xgb_model.pkl")
RF_MODEL_FILE = os.path.join(MODELS_DIR, "rf_model.pkl")
SCALER_FILE = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_FILE = os.path.join(MODELS_DIR, "label_encoder.pkl")
PROTOCOL_ENCODER_FILE = os.path.join(MODELS_DIR, "protocol_encoder.pkl")

# 数据文件
TRAIN_DATA_FILE = os.path.join(PROCESSED_DATA_DIR, "train_data.csv")
TEST_DATA_FILE = os.path.join(PROCESSED_DATA_DIR, "test_data.csv")
RAW_DATASET_FILE = os.path.join(RAW_DATA_DIR, "dataset.csv")

# 模型参数
RANDOM_FOREST_PARAMS = {
    'n_estimators': 100,
    'random_state': 42,
    'n_jobs': -1
}

XGBOOST_PARAMS = {
    'use_label_encoder': False,
    'eval_metric': 'mlogloss',
    'random_state': 42
}

TRAIN_TEST_SPLIT_RATIO = 0.2

# 特征列名
FEATURE_COLUMNS = ['src_port', 'dst_port', 'protocol', 'pkt_len', 'duration']

# 协议映射
PROTOCOL_MAP = {
    'TCP': 6,
    'UDP': 17,
    'ICMP': 1
}
