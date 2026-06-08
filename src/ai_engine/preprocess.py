import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

class DataPreprocessor:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        # 定义任务书要求的特征（示例，需根据成员1提供的特征调整）
        self.feature_columns = ['src_port', 'dst_port', 'protocol', 'pkt_len', 'duration']

    def clean_data(self, df):
        """处理缺失值和异常值"""
        df = df.dropna()
        # 将协议等类别特征转换为数字
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].map({'TCP': 6, 'UDP': 17, 'ICMP': 1})
        return df

    def process_for_training(self, csv_path):
        """读取原始CSV并保存为训练用的npy文件或清洗后的CSV"""
        if not os.path.exists(csv_path):
            print(f"❌ 未找到原始数据: {csv_path}")
            return None

        df = pd.read_csv(csv_path)
        df = self.clean_data(df)

        # 分离特征和标签
        X = df[self.feature_columns]
        y = df['label'] # 假设标签列名为 'label'

        # 编码标签 (Normal: 0, DDoS: 1, SQLi: 2, etc.)
        y_encoded = self.label_encoder.fit_transform(y)
        
        # 特征标准化
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled, y_encoded

    def save_tools(self, save_path="../../models/"):
        """保存预处理工具供推理时使用"""
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        joblib.dump(self.scaler, os.path.join(save_path, "scaler.pkl"))
        joblib.dump(self.label_encoder, os.path.join(save_path, "label_encoder.pkl"))
        print("✅ 预处理工具（Scaler/Encoder）已保存")

if __name__ == "__main__":
    preprocessor = DataPreprocessor()
    # 示例用法
    # X, y = preprocessor.process_for_training("../../data/raw/dataset.csv")
    # preprocessor.save_tools()