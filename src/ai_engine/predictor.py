import joblib
import os
import numpy as np

class Detector:
    def __init__(self, model_dir=None):
        """
        初始化检测器，加载模型和预处理工具
        """
        # 默认路径指向项目根目录下的 models 文件夹
        if model_dir is None:
            # 获取当前文件所在目录的上一级的上一级，即项目根目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(current_dir, "../../models")

        try:
            self.model = joblib.load(os.path.join(model_dir, "xgb_model.pkl"))
            self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
            self.encoder = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))
            print("✅ AI 推理模型加载成功！")
        except Exception as e:
            print(f"❌ 模型加载失败，请检查 models 文件夹。错误: {e}")

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
            result = self.encoder.inverse_transform(prediction_idx)[0]
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