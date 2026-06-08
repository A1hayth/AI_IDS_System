import joblib
import numpy as np
import os
import sys

# 导入配置
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import MODEL_PATH, SCALER_PATH, ENCODER_PATH

class Detector:
    def __init__(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.encoder = joblib.load(ENCODER_PATH)
            print("✅ AI 异常检测引擎已启动")
        except Exception as e:
            print(f"❌ 加载模型失败: {e}")

    def predict(self, feature_values):
        """
        输入: 7个特征的数值列表
        输出: 攻击类型字符串
        """
        try:
            # 1. 强制转换为 numpy 数组，并重塑为 2D 结构 (1, 7)
            # 这一步通过不指定列名，绕过了 XGBoost 的特征名检查
            data = np.array(feature_values).reshape(1, -1)
            
            # 2. 标准化
            data_scaled = self.scaler.transform(data)
            
            # 3. 推理
            pred_idx = self.model.predict(data_scaled)
            
            # 4. 解码标签
            attack_type = self.encoder.inverse_transform(pred_idx)[0]
            return attack_type
        except Exception as e:
            return f"Error: {str(e)}"