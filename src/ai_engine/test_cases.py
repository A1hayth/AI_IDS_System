import os
import sys
# 确保能导入 config 和 predictor
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.ai_engine.predictor import Detector

def run_test():
    # 1. 初始化检测器
    detector = Detector()
    
    # 2. 定义测试用例 (特征顺序必须与你 SELECTED_FEATURES 一致):
    # [Destination Port, Protocol, Flow Duration, Total Fwd Packets, Total Backward Packets, Fwd Packet Length Max, Bwd Packet Length Max]
    
    test_samples = {
        "正常 HTTPS 流量": [443, 6, 50000, 10, 12, 500, 1200],
        "疑似 DDoS 攻击": [80, 6, 1000, 5000, 0, 64, 0],
        "疑似 端口扫描": [21, 6, 50, 1, 0, 0, 0],
        "疑似 暴力破解 (SSH)": [22, 6, 200000, 40, 35, 100, 100],
        "疑似 SQL 注入 (Web Attack)": [80, 6, 30000, 5, 4, 800, 1500]
    }

    print("\n" + "="*50)
    print("🚀 AI 异常检测模块 - 实时推理测试")
    print("="*50)

    for name, features in test_samples.items():
        try:
            # 调用你的推理接口
            result = detector.predict(features)
            print(f"【测试用例】: {name}")
            print(f"【输入特征】: {features}")
            print(f"【检测结果】: ⚠️ {result}" if result != 'BENIGN' and result != 'Benign' else f"【检测结果】: ✅ {result}")
            print("-" * 30)
        except Exception as e:
            print(f"❌ 测试 '{name}' 出错: {e}")

if __name__ == "__main__":
    run_test()