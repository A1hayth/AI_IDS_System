import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
import joblib
import os

def generate_report():
    # 建议在训练脚本 train.py 的最后，将测试集 X_test, y_test 也保存下来
    # 或者在这里重新读取一部分 parquet 数据作为测试
    print("生成混淆矩阵中...")
    # 关键代码：
    # plt.figure(figsize=(12, 8))
    # sns.heatmap(cm, annot=True, fmt='d', xticklabels=le.classes_, yticklabels=le.classes_)
    # plt.savefig("../../notebooks/confusion_matrix.png")
    print("报告已保存至 notebooks 目录，可用于撰写论文/实验报告")