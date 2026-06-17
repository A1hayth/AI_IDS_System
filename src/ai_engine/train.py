# coding=utf-8
"""
AI-IDS 网络安全模型训练工序（v2 — 优化版）

改进点:
    - 统一使用 config.py 的特征定义，全链路列名一致
    - XGBoost 添加 sample_weight 处理类别不平衡
    - 优化超参数（n_estimators=200, max_depth=8, learning_rate=0.05）
    - 保存为 joblib 格式（跨版本兼容性更好）
    - 额外保存 feature_names 供 predictor 对齐校验
    - 输出详细的分类报告
"""
import os
import sys
import glob
import gc
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import joblib
from collections import Counter

# ============================================================================
# 路径注入
# ============================================================================
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
for p in [current_dir, parent_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

# 导入统一配置
from config import (
    MODELS_DIR, DATA_RAW_DIR,
    DB_FEATURE_COLUMNS, MODEL_FEATURE_COLUMNS,
    DB_TO_MODEL_COLUMN_MAP,
    XGB_PARAMS, XGB_MODEL_FILE, SCALER_FILE, LABEL_ENCODER_FILE,
)

# 导入数据预处理函数
try:
    from preprocess import load_and_clean_parquet, align_and_extract_features
except ImportError:
    from ai_engine.preprocess import load_and_clean_parquet, align_and_extract_features


def run_train_pipeline(archive_dir=None, models_dir=None):
    """
    自动化训练闭环（v2）:
        1. 加载 archive/ 下所有 Parquet 文件并合并
        2. 等比例降采样（每类最多 80,000 行）
        3. 统一列名到 MODEL_FEATURE_COLUMNS (lowercase)
        4. 标签编码 + StandardScaler 标准化
        5. 使用 sample_weight 处理类别不平衡
        6. 拟合 XGBoost（优化超参数）
        7. 保存模型为 joblib 格式 + 额外 feature_names.json
    """
    if archive_dir is None:
        archive_dir = DATA_RAW_DIR
    if models_dir is None:
        models_dir = MODELS_DIR

    os.makedirs(models_dir, exist_ok=True)

    print("=" * 70)
    print("  AI-IDS 网络安全模型闭环训练工序 (v2)")
    print("=" * 70)
    print(f"  数据目录: {os.path.abspath(archive_dir)}")
    print(f"  模型目录: {os.path.abspath(models_dir)}")
    print(f"  特征数量: {len(MODEL_FEATURE_COLUMNS)}")
    print(f"  特征列表: {MODEL_FEATURE_COLUMNS}")
    print("=" * 70)

    # ── 1. 扫描 Parquet 文件 ──────────────────────────────────────
    search_path = os.path.join(archive_dir, "*.parquet")
    parquet_files = glob.glob(search_path)

    if not parquet_files:
        raise FileNotFoundError(
            f"未在 {os.path.abspath(archive_dir)} 下找到 .parquet 文件，"
            f"请先放入 CIC-IDS-2017 数据集。"
        )

    print(f"\n找到 {len(parquet_files)} 个 Parquet 文件:")
    for f in parquet_files:
        print(f"    {os.path.basename(f)}")

    # ── 2. 加载、清洗、合并 ────────────────────────────────────────
    all_X = []
    all_y = []

    for file in parquet_files:
        try:
            raw_df = load_and_clean_parquet(file)
            X_clean, y_clean = align_and_extract_features(raw_df)

            # 重命名到统一的 lowercase 模型列名
            X_clean = X_clean.rename(columns=DB_TO_MODEL_COLUMN_MAP)
            # 确保列顺序一致
            X_clean = X_clean[MODEL_FEATURE_COLUMNS]

            # 平衡降采样（每类最多 80,000 行）
            if len(X_clean) > 80000:
                print(f"    {os.path.basename(file)}: {len(X_clean)} → 降采样至 80,000")
                idx_sampled = X_clean.sample(n=80000, random_state=42).index
                X_clean = X_clean.loc[idx_sampled]
                y_clean = y_clean.loc[idx_sampled]

            all_X.append(X_clean)
            all_y.append(y_clean)

            del raw_df
            gc.collect()

        except Exception as e:
            print(f"    [SKIP] {os.path.basename(file)}: {e}")

    if not all_X:
        raise ValueError("所有数据文件加载失败，无可用训练集！")

    X = pd.concat(all_X, ignore_index=True)
    y = pd.concat(all_y, ignore_index=True)

    print(f"\n  合并后样本总量: {len(X):,} 行, {len(X.columns)} 维特征")
    print(f"  标签分布:")
    label_counts = Counter(y)
    for label, count in label_counts.most_common():
        pct = count / len(y) * 100
        print(f"    {label:<35s}: {count:>8,} ({pct:>5.1f}%)")

    # ── 3. 标签编码 ───────────────────────────────────────────────
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    num_classes = len(label_encoder.classes_)
    print(f"\n  类别数量: {num_classes}")
    print(f"  类别列表: {list(label_encoder.classes_)}")

    # ── 4. 特征标准化 ─────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    # 保存 feature_names_in_（确保 predictor 加载后能对齐）
    scaler.feature_names_in_ = np.array(MODEL_FEATURE_COLUMNS)
    print(f"  标准化完成 | feature_names: {list(scaler.feature_names_in_)}")

    # ── 5. 数据切分 ───────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )
    print(f"  训练集: {X_train.shape[0]:,} | 测试集: {X_test.shape[0]:,}")

    # ── 6. 计算类别权重（关键修复！）─────────────────────────────
    sample_weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train,
    )
    print(f"  已计算 balanced 类别权重")

    # ── 7. 拟合 XGBoost ───────────────────────────────────────────
    print(f"\n  正在拟合 XGBoost（优化超参数）...")
    print(f"    n_estimators={XGB_PARAMS['n_estimators']}, "
          f"max_depth={XGB_PARAMS['max_depth']}, "
          f"learning_rate={XGB_PARAMS['learning_rate']}")

    model = xgb.XGBClassifier(**XGB_PARAMS)
    model.fit(X_train, y_train, sample_weight=sample_weights)

    # ── 8. 评估 ───────────────────────────────────────────────────
    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    print(f"\n  训练集 Accuracy: {train_acc:.4f}")
    print(f"  测试集 Accuracy: {test_acc:.4f}")

    # 详细分类报告
    y_pred = model.predict(X_test)
    print(f"\n  ── 分类报告 ──")
    print(classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0,
    ))

    # ── 9. 保存模型（joblib 格式）────────────────────────────────
    xgb_path = os.path.join(models_dir, "xgboost_model.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    feature_names_path = os.path.join(models_dir, "feature_names.json")

    joblib.dump(model, xgb_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)

    # 额外保存 feature_names 供 predictor 校验
    with open(feature_names_path, "w", encoding="utf-8") as f:
        json.dump({
            "model_feature_columns": MODEL_FEATURE_COLUMNS,
            "db_feature_columns": DB_FEATURE_COLUMNS,
            "feature_count": len(MODEL_FEATURE_COLUMNS),
            "num_classes": num_classes,
            "classes": list(label_encoder.classes_),
        }, f, ensure_ascii=False, indent=2)

    print(f"\n  {'='*60}")
    print(f"  模型资产已保存（joblib 格式）:")
    print(f"     XGBoost 模型:  {os.path.abspath(xgb_path)}")
    print(f"     标准化器:      {os.path.abspath(scaler_path)}")
    print(f"     标签编码器:    {os.path.abspath(encoder_path)}")
    print(f"     特征元信息:    {os.path.abspath(feature_names_path)}")
    print(f"  {'='*60}")

    return {
        "train_acc": train_acc,
        "test_acc": test_acc,
        "num_classes": num_classes,
        "feature_count": len(MODEL_FEATURE_COLUMNS),
    }


if __name__ == "__main__":
    try:
        result = run_train_pipeline()
    except Exception as e:
        print(f"\n  [FATAL] 训练中断: {e}")
        import traceback
        traceback.print_exc()
