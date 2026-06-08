import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

class AnomalyDetectionModel:
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.xgb_model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def preprocess_data(self, df):
        """
        数据预处理：处理缺失值、编码、标准化
        假设 df 包含特征和 'label' 列
        """
        # 1. 处理类别型特征 (例如 protocol: TCP, UDP, ICMP)
        if 'protocol' in df.columns:
            df['protocol'] = self.label_encoder.fit_transform(df['protocol'])
        
        # 2. 分离特征和标签
        X = df.drop('label', axis=1)
        y = df['label']
        
        # 3. 标签编码 (Normal:0, DDoS:1, SQLi:2, BruteForce:3, Scan:4)
        y = self.label_encoder.fit_transform(y)
        
        # 4. 数据标准化
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y

    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        print("正在训练随机森林模型...")
        self.rf_model.fit(X_train, y_train)
        
        print("正在训练 XGBoost 模型...")
        self.xgb_model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = self.xgb_model.predict(X_test)
        print("\nXGBoost 评估报告:")
        print(classification_report(y_test, y_pred))
        
    def save_model(self, path="model_assets/"):
        import os
        if not os.path.exists(path): os.makedirs(path)
        joblib.dump(self.rf_model, f"{path}rf_model.pkl")
        joblib.dump(self.xgb_model, f"{path}xgb_model.pkl")
        joblib.dump(self.scaler, f"{path}scaler.pkl")
        joblib.dump(self.label_encoder, f"{path}encoder.pkl")
        print(f"模型及预处理组件已保存至 {path}")

# 使用示例 (假设你有一个特征提取后的 csv)
# df = pd.read_csv("network_traffic_data.csv")
# model_module = AnomalyDetectionModel()
# X, y = model_module.preprocess_data(df)
# model_module.train(X, y)
# model_module.save_model()