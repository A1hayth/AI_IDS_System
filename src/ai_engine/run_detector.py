import os
import sys
import argparse
import pandas as pd
import numpy as np

# 确保能导入项目模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.ai_engine.predictor import Detector
from config import SELECTED_FEATURES


def parse_features(s: str):
    parts = [p.strip() for p in s.split(',') if p.strip()]
    return [float(x) for x in parts]


def main():
    parser = argparse.ArgumentParser(description='Run Detector on single sample or CSV batch')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--features', '-f', help='Comma-separated feature values in order: ' + ','.join(SELECTED_FEATURES))
    group.add_argument('--csv', '-c', help='Path to CSV file for batch prediction. CSV must contain columns: ' + ','.join(SELECTED_FEATURES))
    args = parser.parse_args()

    detector = Detector()

    if args.features:
        feats = parse_features(args.features)
        expected = len(SELECTED_FEATURES)
        if len(feats) != expected:
            print(f"错误：特征数量应为 {expected}，但收到 {len(feats)}")
            sys.exit(2)
        try:
            label = detector.predict(feats)
            print('Prediction:', label)
        except Exception as e:
            print('预测失败:', e)
            sys.exit(1)

    else:
        csv_path = args.csv
        if not os.path.exists(csv_path):
            print('CSV 文件不存在:', csv_path)
            sys.exit(2)
        df = pd.read_csv(csv_path)
        # 检查并重排序列
        missing = [c for c in SELECTED_FEATURES if c not in df.columns]
        if missing:
            print('CSV 文件缺少列:', missing)
            sys.exit(2)
        X = df[SELECTED_FEATURES].values
        # 批量预测（使用 detector 中加载的 scaler 和 model）
        try:
            X_scaled = detector.scaler.transform(X)
            preds = detector.model.predict(X_scaled)
            labels = detector.label_encoder.inverse_transform(preds)
            out = df.copy()
            out['prediction'] = labels
            print(out[['prediction']].to_string(index=False))
        except Exception as e:
            print('批量预测失败:', e)
            sys.exit(1)


if __name__ == '__main__':
    main()
