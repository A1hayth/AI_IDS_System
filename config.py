"""
项目配置文件 - 统一管理所有路径和参数
"""
import os

# 1. 项目根目录设置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. 数据路径
DATA_DIR = os.path.join(BASE_DIR, "data")
# 指向存放 .parquet 文件的文件夹
DATA_RAW_DIR = os.path.join(BASE_DIR, "data", "raw", "archive")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

# 3. 模型路径
MODELS_DIR = os.path.join(BASE_DIR, "models")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgb_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# 4. 模型参数
XGBOOST_PARAMS = {
    'use_label_encoder': False,
    'eval_metric': 'mlogloss',
    'random_state': 42,
    'n_jobs': -1  # 使用所有 CPU 核心
}

TRAIN_TEST_SPLIT_RATIO = 0.2

# 5. 核心特征列名 (必须与 CIC-IDS-2017 Parquet 文件中的列名完全一致)
SELECTED_FEATURES = [
    'Destination Port', 
    'Protocol', 
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Backward Packets',
    'Fwd Packet Length Max', 
    'Bwd Packet Length Max'
]

# 6. 协议映射 (用于实时检测时将字符串转换为数字)
PROTOCOL_MAP = {
    'TCP': 6,
    'UDP': 17,
    'ICMP': 1
}