import os

# 路径管理
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_RAW_DIR = os.path.join(BASE_DIR, "archive") # 根据你数据集的实际位置
MODELS_DIR = os.path.join(BASE_DIR, "models")

# 核心特征 (必须与数据集列名完全一致)
# 已根据 archive 数据文件实际列名调整，移除不存在的 'Destination Port'
SELECTED_FEATURES = [
    'Protocol', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Max', 'Bwd Packet Length Max'
]

# 模型文件路径
MODEL_PATH = os.path.join(MODELS_DIR, "xgb_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")