import joblib
import os
import sys
import numpy as np

# 导入配置
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    XGB_MODEL_FILE, SCALER_FILE, LABEL_ENCODER_FILE, 
    PROTOCOL_ENCODER_FILE, MODELS_DIR
)

class Detector:
    def __init__(self, model_dir=None):
        """
        初始化检测器，加载模型和预处理工具
        :param model_dir: 模型目录，不提供时使用配置文件中的路径
        """
        # 使用配置的目录
        if model_dir is None:
            model_dir = MODELS_DIR

        try:
            self.model = joblib.load(XGB_MODEL_FILE)
            self.scaler = joblib.load(SCALER_FILE)
            self.label_encoder = joblib.load(LABEL_ENCODER_FILE)
            self.protocol_encoder = joblib.load(PROTOCOL_ENCODER_FILE)
            print("✅ AI 推理模型加载成功！")
            print(f"   - XGBoost模型: {XGB_MODEL_FILE}")
            print(f"   - 特征标准化器: {SCALER_FILE}")
            print(f"   - 标签编码器: {LABEL_ENCODER_FILE}")
            print(f"   - 协议编码器: {PROTOCOL_ENCODER_FILE}")
        except Exception as e:
            print(f"❌ 模型加载失败，请检查 models 文件夹。错误: {e}")
            raise

    def predict(self, feature_list):
        """
        供其他模块调用
        :param feature_list: 成员1提取的特征列表，如 [80, 6, 1024, ...]
        :return: 预测的攻击类型字符串 (如 'Normal', 'DDoS', 'SQL Injection')
        """
        try:
            # 1. 转换为 numpy 数组并重塑为 2D 结构
            features = np.array(feature_list).reshape(1, -1)
            
            # 2. 特征标准化
            features_scaled = self.scaler.transform(features)
            
            # 3. 模型预测
            prediction_idx = self.model.predict(features_scaled)
            
            # 4. 标签逆转（数字 -> 字符串）
            result = self.label_encoder.inverse_transform(prediction_idx)[0]
            return result
        except Exception as e:
            return f"Error during prediction: {str(e)}"

# --- 供测试使用 ---
if __name__ == "__main__":
    detector = Detector()
    # 模拟一条来自成员1的特征数据 (假设模型需要 5 个特征)
    sample_traffic = [80, 6, 500, 1, 0] 
    result = detector.predict(sample_traffic)
    print(f"流量检测结果: {result}")