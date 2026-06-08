import joblib
import os
import numpy as np
import pandas as pd

class Detector:
    def __init__(self):
        # 获取模型路径（建议使用绝对路径防止报错）
        base_path = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.join(base_path, "../../models/")
        
        try:
            self.model = joblib.load(os.path.join(model_dir, "xgb_model.pkl"))
            self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
            self.encoder = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))
            # 定义你在训练时选用的那几个核心特征列名（必须顺序一致）
            self.feature_names = [
                'Destination Port', 'Protocol', 'Flow Duration', 
                'Total Fwd Packets', 'Total Backward Packets',
                'Fwd Packet Length Max', 'Bwd Packet Length Max'
            ]
            print("✅ AI 推理引擎已加载最新模型")
        except Exception as e:
            print(f"❌ 加载失败: {e}")

    def predict(self, feature_values):
        """
        feature_values: 成员1传过来的列表，例如 [80, 6, 5000, 2, 1, 100, 50]
        """
        # 1. 转换为 DataFrame 并指定列名（确保与训练时特征对齐）
        features_df = pd.DataFrame([feature_values], columns=self.feature_names)
        
        # 2. 使用训练时的 scaler 进行标准化
        features_scaled = self.scaler.transform(features_df)
        
        # 3. 预测并转换标签
        pred_idx = self.model.predict(features_scaled)
        result = self.encoder.inverse_transform(pred_idx)[0]
        return result