import joblib
import os

# 获取当前脚本所在目录: IDS_Project/src/ai_engine
base_path = os.path.dirname(os.path.abspath(__file__))

# 向上跳两级到根目录，再进入 models 文件夹
scaler_path = os.path.abspath(os.path.join(base_path, "../../models/scaler.pkl"))

if not os.path.exists(scaler_path):
    print(f"❌ 依然找不到文件，请确认此路径是否存在: {scaler_path}")
else:
    scaler = joblib.load(scaler_path)
    print(f"📊 你的模型训练时使用的特征数量是: {scaler.n_features_in_}")
    
    # 顺便帮你看看是哪几个特征（如果 scaler 记录了的话）
    if hasattr(scaler, "feature_names_in_"):
        print(f"特征名称分别是: {scaler.feature_names_in_.tolist()}")