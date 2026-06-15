import joblib
import numpy as np
import os
import sys

# 导入配置
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import MODEL_PATH, SCALER_PATH, ENCODER_PATH

# 修复 Windows GBK 编码下 emoji/中文输出问题
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass


class Detector:
    def __init__(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.encoder = joblib.load(ENCODER_PATH)
            # 兼容 run_detector.py 中引用的 label_encoder 别名
            self.label_encoder = self.encoder
            print("[AI Engine] Model loaded successfully, ready for prediction")
        except Exception as e:
            print(f"[AI Engine] Failed to load model: {e}")
            raise

    def predict(self, feature_values):
        """
        输入: 6 个特征数值的列表 (Protocol, Flow Duration, Total Fwd Packets,
              Total Backward Packets, Fwd Packet Length Max, Bwd Packet Length Max)
        输出: 攻击类型字符串 (如 'Benign', 'DoS Hulk', 'PortScan' 等)
        """
        try:
            data = np.array(feature_values, dtype=np.float64).reshape(1, -1)
            data_scaled = self.scaler.transform(data)
            pred_idx = self.model.predict(data_scaled)
            attack_type = self.encoder.inverse_transform(pred_idx)[0]
            return attack_type
        except Exception as e:
            return f"Error: {str(e)}"

    def predict_proba(self, feature_values):
        """
        输入: 与 predict() 相同
        输出: (attack_type, confidence) 元组
              - attack_type: 预测的攻击类型字符串
              - confidence: 置信度 0.0~1.0
        """
        try:
            data = np.array(feature_values, dtype=np.float64).reshape(1, -1)
            data_scaled = self.scaler.transform(data)

            # 获取概率分布
            proba = self.model.predict_proba(data_scaled)[0]
            pred_idx = int(np.argmax(proba))
            confidence = float(proba[pred_idx])

            attack_type = self.encoder.inverse_transform([pred_idx])[0]
            return attack_type, confidence
        except Exception as e:
            return f"Error: {str(e)}", 0.0