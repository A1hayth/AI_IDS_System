import os
import sys

# 确保路径正确
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.ai_engine.predictor import Detector

def run_test():
    detector = Detector()
    
    # 【核心修正】: 严格按照你截图中的 6 个特征顺序填充数据
    # 顺序: [Protocol, Flow Duration, Total Fwd Pkts, Total Bwd Pkts, Fwd Len Max, Bwd Len Max]
    
    test_samples = {
        "正常 HTTPS 流量": [6, 50000, 10, 12, 500, 1200],
        "疑似 DDoS 攻击": [6, 1000, 5000, 0, 64, 0],
        "疑似 端口扫描": [6, 50, 1, 0, 0, 0],
        "疑似 暴力破解 (SSH)": [6, 200000, 40, 35, 100, 100],
        "疑似 Web 攻击 (SQLi)": [6, 30000, 5, 4, 1200, 1500]
    }

    print("\n" + "="*50)
    print("🚀 AI 异常检测模块 - 特征对齐修正测试")
    print("="*50)

    for name, features in test_samples.items():
        try:
            result = detector.predict(features)
            print(f"【测试项目】: {name}")
            # 统一转为大写判断，防止数据集标签大小写不一
            res_up = str(result).upper()
            if 'BENIGN' in res_up:
                print(f"【检测结果】: ✅ {result}")
            else:
                print(f"【检测结果】: ⚠️ {result}")
            print("-" * 30)
        except Exception as e:
            print(f"❌ 推理失败: {e}")

if __name__ == "__main__":
    run_test()