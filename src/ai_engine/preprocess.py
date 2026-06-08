import pandas as pd
import numpy as np
import os
import sys
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

# 导入配置
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    FEATURE_COLUMNS, SCALER_FILE, LABEL_ENCODER_FILE, 
    PROTOCOL_ENCODER_FILE, MODELS_DIR, PROTOCOL_MAP
)

class DataPreprocessor:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.protocol_encoder = LabelEncoder()  # 分离的protocol编码器
        self.scaler = StandardScaler()
        self.feature_columns = FEATURE_COLUMNS
        self.protocol_fitted = False

    def clean_data(self, df):
        """处理缺失值和异常值"""
        df = df.dropna()
        # 将协议等类别特征转换为数字（使用独立的protocol_encoder）
        if 'protocol' in df.columns:
            if not self.protocol_fitted:
                df['protocol'] = self.protocol_encoder.fit_transform(df['protocol'])
                self.protocol_fitted = True
            else:
                df['protocol'] = self.protocol_encoder.transform(df['protocol'])
        return df

    def process_for_training(self, csv_path, fit=True):
        """
        读取原始CSV并返回处理后的特征和标签
        :param csv_path: 原始数据路径
        :param fit: 是否拟合编码器和标准化器
        :return: (X_scaled, y_encoded) 元组
        """
        if not os.path.exists(csv_path):
            print(f"❌ 未找到原始数据: {csv_path}")
            return None

        df = pd.read_csv(csv_path)
        df = self.clean_data(df)

        # 分离特征和标签
        X = df[self.feature_columns]
        y = df['label']

        # 编码标签 (Normal: 0, DDoS: 1, SQLi: 2, etc.)
        if fit:
            y_encoded = self.label_encoder.fit_transform(y)
            X_scaled = self.scaler.fit_transform(X)
        else:
            y_encoded = self.label_encoder.transform(y)
            X_scaled = self.scaler.transform(X)

        return X_scaled, y_encoded

    def save_tools(self):
        """保存预处理工具供推理时使用"""
        if not os.path.exists(MODELS_DIR):
            os.makedirs(MODELS_DIR)
        joblib.dump(self.scaler, SCALER_FILE)
        joblib.dump(self.label_encoder, LABEL_ENCODER_FILE)
        joblib.dump(self.protocol_encoder, PROTOCOL_ENCODER_FILE)
        print("✅ 预处理工具（Scaler/Encoder）已保存")
        print(f"   - Scaler: {SCALER_FILE}")
        print(f"   - Label Encoder: {LABEL_ENCODER_FILE}")
        print(f"   - Protocol Encoder: {PROTOCOL_ENCODER_FILE}")

if __name__ == "__main__":
    preprocessor = DataPreprocessor()
    # 示例用法
    # from config import RAW_DATASET_FILE
    # X, y = preprocessor.process_for_training(RAW_DATASET_FILE, fit=True)
    # preprocessor.save_tools()
    pass