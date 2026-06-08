import os
import joblib
from preprocess import prepare_ids_data
from xgboost import XGBClassifier

def train_system():
    # 数据集所在的 archive 文件夹路径
    dataset_path = "E:/桌面/IDS_Project/archive" 
    
    # 1. 加载并处理数据
    (X_train, X_test, y_train, y_test), scaler, le = prepare_ids_data(dataset_path)
    
    # 2. 初始化并训练模型
    print("开始训练 XGBoost 模型 (这可能需要几分钟)...")
    model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1)
    model.fit(X_train, y_train)
    
    # 3. 保存
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models")
    if not os.path.exists(model_dir): os.makedirs(model_dir)
    
    joblib.dump(model, os.path.join(model_dir, "xgb_model.pkl"))
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    joblib.dump(le, os.path.join(model_dir, "label_encoder.pkl"))
    
    print("✅ 所有模型文件已存入 models/ 文件夹！")

if __name__ == "__main__":
    train_system()