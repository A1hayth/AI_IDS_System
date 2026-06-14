import pandas as pd
import glob
import os
import joblib
import numpy as np
import sys

# 导入配置路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.ai_engine.predictor import Detector

def verify():
    # 1. 初始化
    detector = Detector()
    base_path = os.path.dirname(os.path.abspath(__file__))
    # 路径指向你的 archive 文件夹
    data_path = os.path.join(base_path, "../../archive/*.parquet")
    
    print("🔍 正在从原始数据集中搜寻真实的攻击样本...")
    files = glob.glob(data_path)
    
    # 找到包含攻击的文件（例如 Friday-PortScan 或 Friday-DDoS）
    # 我们直接找 Label 不是 Benign 的行
    for f in files:
        df = pd.read_parquet(f)
        df.columns = df.columns.str.strip()
        
        # 筛选出非正常的样本
        attacks = df[df['Label'] != 'Benign']
        
        if not attacks.empty:
            print(f"💥 在文件 {os.path.basename(f)} 中发现真实攻击类型: {attacks['Label'].unique()}")
            
            # 随机取 3 条真实攻击数据
            sample_rows = attacks.sample(min(3, len(attacks)))
            
            # 提取那 6 个特征 (严格按照你之前的顺序)
            features_list = [
                'Protocol', 'Flow Duration', 'Total Fwd Packets', 
                'Total Backward Packets', 'Fwd Packet Length Max', 'Bwd Packet Length Max'
            ]
            
            for _, row in sample_rows.iterrows():
                real_label = row['Label']
                # 提取特征数值
                input_data = [row[feat] for feat in features_list]
                
                # 预测
                prediction = detector.predict(input_data)
                
                print(f"\n--- 真实样本盲测 ---")
                print(f"【数据集原始标签】: {real_label}")
                print(f"【AI 模型预测结果】: {prediction}")
                print(f"【结果】: {'✅ 成功捕捉攻击' if prediction == real_label else '❌ 未能准确分类'}")
            
            break # 测完一个文件就停止

if __name__ == "__main__":
    verify()