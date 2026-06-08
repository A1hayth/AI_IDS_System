import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import os

def evaluate_model(model_name="xgb_model.pkl", test_data_path="../../data/processed/test_data.csv"):
    """
    加载模型和测试集，生成评估图表
    """
    model_path = f"../../models/{model_name}"
    encoder_path = "../../models/label_encoder.pkl"
    
    if not os.path.exists(model_path):
        print("❌ 模型文件不存在，请先运行 train.py")
        return

    # 1. 加载模型和工具
    model = joblib.load(model_path)
    encoder = joblib.load(encoder_path)
    
    # 2. 加载测试数据 (假设你已经准备好了测试集)
    # 这里为了演示，假设 df_test 已经存在
    # df_test = pd.read_csv(test_data_path)
    # X_test = df_test.drop('label', axis=1)
    # y_true = df_test['label']
    
    # 3. 模拟评估过程（实际使用时请替换为真实测试数据）
    print(f"--- 模型 {model_name} 评估结果 ---")
    # y_pred = model.predict(X_test)
    
    # 4. 生成混淆矩阵 (Confusion Matrix) 可视化
    # 提示：这部分代码在你有数据后可以生成精美的热力图
    """
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 7))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=encoder.classes_, yticklabels=encoder.classes_)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig('../../notebooks/confusion_matrix.png') # 保存图片用于报告
    plt.show()
    """
    
    print("报告：请查阅 notebooks 文件夹下的评估图片。")

if __name__ == "__main__":
    evaluate_model()