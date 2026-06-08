import pandas as pd
import numpy as np
import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# 导入配置
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    MODELS_DIR, XGB_MODEL_FILE, RF_MODEL_FILE, SCALER_FILE,
    LABEL_ENCODER_FILE, PROTOCOL_ENCODER_FILE,
    RANDOM_FOREST_PARAMS, XGBOOST_PARAMS, TRAIN_TEST_SPLIT_RATIO
)

class AnomalyDetectionModel:
    def __init__(self):
        self.rf_model = RandomForestClassifier(**RANDOM_FOREST_PARAMS)
        self.xgb_model = XGBClassifier(**XGBOOST_PARAMS)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()  # 标签编码器
        self.protocol_encoder = LabelEncoder()  # 协议编码器（分离）
        self.protocol_fitted = False  # 标记protocol_encoder是否已拟合

    def preprocess_data(self, df, fit=True):
        """
        数据预处理：处理缺失值、编码、标准化
        :param df: 包含特征和 'label' 列的 DataFrame
        :param fit: 是否拟合编码器和标准化器（训练集为True，测试集为False）
        """
        df = df.copy()  # 避免修改原始数据
        
        # 1. 处理类别型特征 (protocol: TCP, UDP, ICMP)
        if 'protocol' in df.columns:
            if fit and not self.protocol_fitted:
                # 首次处理时拟合protocol编码器
                df['protocol'] = self.protocol_encoder.fit_transform(df['protocol'])
                self.protocol_fitted = True
            else:
                # 后续使用已拟合的编码器
                df['protocol'] = self.protocol_encoder.transform(df['protocol'])
        
        # 2. 分离特征和标签
        X = df.drop('label', axis=1)
        y = df['label']
        
        # 3. 标签编码 (Normal:0, DDoS:1, SQLi:2, BruteForce:3, Scan:4)
        if fit:
            # 只在训练时拟合标签编码器
            y = self.label_encoder.fit_transform(y)
            X_scaled = self.scaler.fit_transform(X)
        else:
            # 测试/验证时使用已拟合的编码器
            y = self.label_encoder.transform(y)
            X_scaled = self.scaler.transform(X)
        
        return X_scaled, y

    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TRAIN_TEST_SPLIT_RATIO, random_state=42
        )
        
        print("正在训练随机森林模型...")
        self.rf_model.fit(X_train, y_train)
        rf_pred = self.rf_model.predict(X_test)
        print("\n随机森林评估报告:")
        print(classification_report(y_test, rf_pred))
        
        print("\n正在训练 XGBoost 模型...")
        self.xgb_model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = self.xgb_model.predict(X_test)
        print("\nXGBoost 评估报告:")
        print(classification_report(y_test, y_pred))
        
    def save_model(self):
        """保存所有模型和预处理工具到配置指定的目录"""
        if not os.path.exists(MODELS_DIR):
            os.makedirs(MODELS_DIR)
        
        joblib.dump(self.rf_model, RF_MODEL_FILE)
        joblib.dump(self.xgb_model, XGB_MODEL_FILE)
        joblib.dump(self.scaler, SCALER_FILE)
        joblib.dump(self.label_encoder, LABEL_ENCODER_FILE)
        joblib.dump(self.protocol_encoder, PROTOCOL_ENCODER_FILE)
        
        print(f"✅ 模型及预处理组件已保存至 {MODELS_DIR}")
        print(f"   - RF模型: {RF_MODEL_FILE}")
        print(f"   - XGBoost模型: {XGB_MODEL_FILE}")
        print(f"   - 特征标准化器: {SCALER_FILE}")
        print(f"   - 标签编码器: {LABEL_ENCODER_FILE}")
        print(f"   - 协议编码器: {PROTOCOL_ENCODER_FILE}")

# 使用示例
if __name__ == "__main__":
    # df = pd.read_csv(RAW_DATASET_FILE)
    # model_module = AnomalyDetectionModel()
    # X, y = model_module.preprocess_data(df, fit=True)
    # model_module.train(X, y)
    # model_module.save_model()
    pass