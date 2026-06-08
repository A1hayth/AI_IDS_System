import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score

# 导入配置
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    XGB_MODEL_FILE, LABEL_ENCODER_FILE, TEST_DATA_FILE, NOTEBOOKS_DIR
)

def evaluate_model(model_name="xgb_model.pkl"):
    """
    加载模型和测试集，生成评估图表
    :param model_name: 模型文件名（xgb_model.pkl 或 rf_model.pkl）
    """
    # 根据模型文件名选择模型路径
    if model_name == "xgb_model.pkl":
        model_path = XGB_MODEL_FILE
    elif model_name == "rf_model.pkl":
        from config import RF_MODEL_FILE
        model_path = RF_MODEL_FILE
    else:
        print(f"❌ 不支持的模型文件: {model_name}")
        return
    
    if not os.path.exists(model_path):
        print(f"❌ 模型文件不存在: {model_path}")
        print(f"   请先运行 train.py 生成模型文件")
        return

    # 1. 加载模型和工具
    try:
        model = joblib.load(model_path)
        label_encoder = joblib.load(LABEL_ENCODER_FILE)
        print(f"✅ 模型加载成功: {model_path}")
    except Exception as e:
        print(f"❌ 模型加载失败: {e}")
        return
    
    # 2. 加载测试数据
    if os.path.exists(TEST_DATA_FILE):
        try:
            df_test = pd.read_csv(TEST_DATA_FILE)
            X_test = df_test.drop('label', axis=1)
            y_true = df_test['label']
            
            # 3. 进行预测
            y_pred_encoded = model.predict(X_test)
            
            # 4. 转换预测结果回字符串标签
            y_pred = label_encoder.inverse_transform(y_pred_encoded)
            
            print(f"\n--- 模型 {model_name} 评估结果 ---")
            print(f"准确率: {accuracy_score(y_true, y_pred):.4f}")
            print("\n分类报告:")
            print(classification_report(y_true, y_pred))
            
            # 5. 生成混淆矩阵 (Confusion Matrix) 可视化
            cm = confusion_matrix(y_true, y_pred)
            plt.figure(figsize=(10, 7))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=label_encoder.classes_, 
                        yticklabels=label_encoder.classes_)
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.title(f'Confusion Matrix - {model_name}')
            
            if not os.path.exists(NOTEBOOKS_DIR):
                os.makedirs(NOTEBOOKS_DIR)
            
            save_path = os.path.join(NOTEBOOKS_DIR, f'confusion_matrix_{model_name.replace(".pkl", "")}.png')
            plt.savefig(save_path)
            print(f"\n✅ 混淆矩阵已保存到: {save_path}")
            plt.close()
            
        except Exception as e:
            print(f"❌ 评估过程出错: {e}")
    else:
        print(f"❌ 测试数据不存在: {TEST_DATA_FILE}")
        print(f"   请先准备测试数据文件")

if __name__ == "__main__":
    # 评估 XGBoost 模型
    evaluate_model("xgb_model.pkl")
    
    # 如需评估随机森林模型，取消下行注释
    # evaluate_model("rf_model.pkl")