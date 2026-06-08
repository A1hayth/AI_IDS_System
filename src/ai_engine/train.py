import os
import joblib
import sys
from xgboost import XGBClassifier
from preprocess import prepare_ids_data

# 导入配置
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import DATA_RAW_DIR, MODEL_PATH, SCALER_PATH, ENCODER_PATH, MODELS_DIR

def train_system():
    if not os.path.exists(MODELS_DIR): os.makedirs(MODELS_DIR)
    
    print("📂 正在加载并预处理数据...")
    (X_train, X_test, y_train, y_test), scaler, le = prepare_ids_data(DATA_RAW_DIR)
    
    print(f"🚀 正在训练模型，样本量: {len(X_train)}...")
    # tree_method='hist' 可以大幅加快大型数据集的训练速度
    model = XGBClassifier(n_estimators=100, max_depth=6, n_jobs=-1, tree_method='hist')
    model.fit(X_train, y_train)
    
    # 保存产物
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, ENCODER_PATH)
    
    print(f"✅ 训练完成！模型已存入 {MODELS_DIR}")
    print(f"识别类别: {list(le.classes_)}")

if __name__ == "__main__":
    train_system()