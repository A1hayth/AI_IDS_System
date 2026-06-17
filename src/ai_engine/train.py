# coding=utf-8
"""
AI-IDS 网络安全模型训练工序 (v3 — 全面优化版)

改进点:
    - 特征从 6 维扩展到 15 维精选特征（更高区分度）
    - SMOTE 过采样处理极端类别不平衡
    - StratifiedKFold 5折交叉验证，输出每折指标
    - CalibratedClassifierCV 概率校准（置信度更可靠）
    - 特征重要性排名输出
    - 标签清洗 + 稀有类自动剔除
    - 超参数全面调优（正则化、更深树、更多迭代）
    - 保存为 joblib 格式 + feature_names.json 元信息
"""
import os
import sys
import glob
import gc
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.calibration import CalibratedClassifierCV
from collections import Counter
import xgboost as xgb
import joblib

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
    DB_FEATURE_COLUMNS, MODEL_FEATURE_COLUMNS, N_FEATURES,
    DB_TO_MODEL_COLUMN_MAP, CIC_TO_MODEL_COLUMN_MAP,
    XGB_PARAMS, SMOTE_PARAMS,
    MIN_SAMPLES_PER_CLASS, MAX_SAMPLES_PER_CLASS,
    XGB_MODEL_FILE, SCALER_FILE, LABEL_ENCODER_FILE,
)

# 导入数据预处理函数
try:
    from preprocess import (
        load_and_clean_parquet, align_and_extract_features,
        clean_labels, filter_rare_classes,
    )
except ImportError:
    from ai_engine.preprocess import (
        load_and_clean_parquet, align_and_extract_features,
        clean_labels, filter_rare_classes,
    )


def run_train_pipeline(archive_dir=None, models_dir=None):
    """
    自动化训练闭环 (v3):
        1. 加载 archive/ 下所有 Parquet 文件并合并
        2. 标签清洗 + 稀有类剔除
        3. 等比例降采样（每类最多 MAX_SAMPLES_PER_CLASS 行）
        4. 统一列名到 MODEL_FEATURE_COLUMNS (15维, lowercase)
        5. 标签编码 + StandardScaler 标准化
        6. SMOTE 过采样平衡类别
        7. StratifiedKFold 5折交叉验证
        8. 拟合 XGBoost（优化超参数）
        9. CalibratedClassifierCV 概率校准
        10. 保存模型 + 特征重要性报告
    """
    if archive_dir is None:
        archive_dir = DATA_RAW_DIR
    if models_dir is None:
        models_dir = MODELS_DIR

    os.makedirs(models_dir, exist_ok=True)

    print("=" * 70)
    print("  AI-IDS 网络安全模型闭环训练工序 (v3)")
    print("=" * 70)
    print(f"  数据目录: {os.path.abspath(archive_dir)}")
    print(f"  模型目录: {os.path.abspath(models_dir)}")
    print(f"  特征数量: {N_FEATURES}")
    print(f"  特征列表: {MODEL_FEATURE_COLUMNS}")
    print(f"  SMOTE   : k_neighbors={SMOTE_PARAMS['k_neighbors']}")
    print(f"  XGBoost : n_estimators={XGB_PARAMS['n_estimators']}, "
          f"max_depth={XGB_PARAMS['max_depth']}, "
          f"lr={XGB_PARAMS['learning_rate']}")
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
            print(f"\n── 处理: {os.path.basename(file)} ──")
            raw_df = load_and_clean_parquet(file)
            X_clean, y_clean = align_and_extract_features(raw_df)

            # 检查是否有有效攻击标签
            attack_count = sum(1 for v in y_clean if str(v).strip().lower() != 'benign')
            print(f"    攻击样本: {attack_count:,} / {len(y_clean):,}")

            # 降采样（每类最多 MAX_SAMPLES_PER_CLASS 行）
            if len(X_clean) > MAX_SAMPLES_PER_CLASS:
                # 按类分层降采样
                indices = []
                for label in y_clean.unique():
                    label_idx = y_clean[y_clean == label].index
                    if len(label_idx) > MAX_SAMPLES_PER_CLASS:
                        sampled_idx = np.random.RandomState(42).choice(
                            label_idx, MAX_SAMPLES_PER_CLASS, replace=False
                        )
                        indices.extend(sampled_idx)
                    else:
                        indices.extend(label_idx)
                X_clean = X_clean.loc[indices]
                y_clean = y_clean.loc[indices]
                print(f"    降采样后: {len(X_clean):,} 行")

            all_X.append(X_clean)
            all_y.append(y_clean)

            del raw_df
            gc.collect()

        except Exception as e:
            print(f"    [SKIP] {os.path.basename(file)}: {e}")
            import traceback
            traceback.print_exc()

    if not all_X:
        raise ValueError("所有数据文件加载失败，无可用训练集！")

    X = pd.concat(all_X, ignore_index=True)
    y = pd.concat(all_y, ignore_index=True)

    print(f"\n{'='*60}")
    print(f"  合并后样本总量: {len(X):,} 行, {len(X.columns)} 维特征")
    print(f"  标签分布（清洗前）:")
    label_counts = Counter(y)
    for label, count in label_counts.most_common():
        pct = count / len(y) * 100
        print(f"    {label:<38s}: {count:>10,} ({pct:>5.1f}%)")

    # ── 2.5 稀有类剔除 ──────────────────────────────────────────
    X, y, removed = filter_rare_classes(X, y)
    if removed:
        print(f"\n  剔除后样本量: {len(X):,} 行")
        remaining = Counter(y)
        for label, count in remaining.most_common():
            pct = count / len(y) * 100
            print(f"    {label:<38s}: {count:>10,} ({pct:>5.1f}%)")

    # ── 3. 标签编码 ───────────────────────────────────────────────
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    num_classes = len(label_encoder.classes_)
    print(f"\n  类别数量: {num_classes}")
    print(f"  类别列表: {list(label_encoder.classes_)}")

    # ── 4. 特征标准化 ─────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    # 保存 feature_names_in_
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

    # ── 6. SMOTE 过采样 ─────────────────────────────────────────
    print(f"\n  ── SMOTE 过采样 ──")
    print(f"  过采样前训练集分布:")
    pre_counts = Counter(y_train)
    for cls_id, count in sorted(pre_counts.items()):
        cls_name = label_encoder.classes_[cls_id]
        print(f"    {cls_name:<38s}: {count:>10,}")

    try:
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(**SMOTE_PARAMS)
        X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
        print(f"\n  过采样后训练集分布:")
        post_counts = Counter(y_train_resampled)
        for cls_id, count in sorted(post_counts.items()):
            cls_name = label_encoder.classes_[cls_id]
            print(f"    {cls_name:<38s}: {count:>10,}")
        print(f"  过采样后总样本: {len(X_train_resampled):,}")
    except ImportError:
        print("  [WARN] imbalanced-learn 未安装，跳过 SMOTE。")
        print("         请运行: pip install imbalanced-learn")
        X_train_resampled, y_train_resampled = X_train, y_train

    # ── 7. 交叉验证 ──────────────────────────────────────────────
    print(f"\n  ── StratifiedKFold 5折交叉验证 ──")
    try:
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        # 使用较小的 n_estimators 做快速 CV（正式训练用完整参数）
        cv_model = xgb.XGBClassifier(**{**XGB_PARAMS, "n_estimators": 100})
        cv_scores = cross_val_score(
            cv_model, X_train_resampled, y_train_resampled,
            cv=skf, scoring='f1_macro', n_jobs=-1,
        )
        print(f"  各折 macro-F1: {[f'{s:.4f}' for s in cv_scores]}")
        print(f"  平均 macro-F1: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    except Exception as e:
        print(f"  交叉验证跳过: {e}")
        cv_scores = None

    # ── 8. 拟合 XGBoost ───────────────────────────────────────────
    print(f"\n  正在拟合 XGBoost（优化超参数）...")
    print(f"    n_estimators={XGB_PARAMS['n_estimators']}, "
          f"max_depth={XGB_PARAMS['max_depth']}, "
          f"learning_rate={XGB_PARAMS['learning_rate']}, "
          f"reg_alpha={XGB_PARAMS.get('reg_alpha', 0)}, "
          f"reg_lambda={XGB_PARAMS.get('reg_lambda', 0)}")

    model = xgb.XGBClassifier(**XGB_PARAMS)
    model.fit(X_train_resampled, y_train_resampled)

    # ── 9. 概率校准 ──────────────────────────────────────────────
    print(f"\n  ── 概率校准 (CalibratedClassifierCV) ──")
    try:
        calibrated_model = CalibratedClassifierCV(
            estimator=model,
            method='isotonic',       # isotonic 校准精度更高
            cv='prefit',              # 使用已拟合模型
        )
        # Isotonic 需要至少包含每类的样本，使用测试集的子集
        # 但 prefit 模式要求 cv 不是 'prefit' 时重新训练
        # 这里使用 sigmoid 方法更简单可靠
        calibrated_model = CalibratedClassifierCV(
            estimator=xgb.XGBClassifier(**XGB_PARAMS),
            method='sigmoid',
            cv=3,
        )
        calibrated_model.fit(X_train_resampled, y_train_resampled)
        # 用校准后的模型做最终评估
        final_model = calibrated_model
        print(f"  校准方法: sigmoid (3-fold)")
    except Exception as e:
        print(f"  校准失败（将使用原始模型）: {e}")
        final_model = model

    # ── 10. 评估 ─────────────────────────────────────────────────
    train_pred = final_model.predict(X_train_resampled)
    test_pred = final_model.predict(X_test)

    train_acc = final_model.score(X_train_resampled, y_train_resampled)
    test_acc = final_model.score(X_test, y_test)
    train_f1 = f1_score(y_train_resampled, train_pred, average='macro')
    test_f1 = f1_score(y_test, test_pred, average='macro')

    print(f"\n  {'='*60}")
    print(f"  训练集 Accuracy:   {train_acc:.4f}  |  macro-F1: {train_f1:.4f}")
    print(f"  测试集 Accuracy:   {test_acc:.4f}  |  macro-F1: {test_f1:.4f}")
    print(f"  {'='*60}")

    # ── 详细分类报告 ─────────────────────────────────────────────
    print(f"\n  ── 测试集分类报告 ──")
    print(classification_report(
        y_test, test_pred,
        target_names=label_encoder.classes_,
        zero_division=0,
    ))

    # ── 混淆矩阵概要 ─────────────────────────────────────────────
    cm = confusion_matrix(y_test, test_pred)
    print(f"\n  ── 混淆矩阵 (行=真实, 列=预测) ──")
    class_names = label_encoder.classes_
    # 只展示缩写版（每类检出/误报）
    for i, name in enumerate(class_names):
        tp = cm[i, i]
        total_real = cm[i, :].sum()
        fp = cm[:, i].sum() - tp
        recall = tp / total_real * 100 if total_real > 0 else 0
        print(f"  {name:<38s} 检出={tp:>6}/{total_real:>6} ({recall:>5.1f}%)  |  误报={fp:>6}")

    # ── 11. 特征重要性 ──────────────────────────────────────────
    print(f"\n  ── 特征重要性 Top-15 ──")
    # 获取原始 XGBoost 模型的重要性（校准模型包装了一层）
    if hasattr(final_model, 'calibrated_classifiers_'):
        xgb_model = final_model.calibrated_classifiers_[0].estimator
    else:
        xgb_model = final_model

    importances = xgb_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    feat_names = MODEL_FEATURE_COLUMNS
    for rank, idx in enumerate(indices, 1):
        bar = "█" * int(importances[idx] * 100)
        print(f"  {rank:>2}. {feat_names[idx]:<30s} {importances[idx]:.4f} {bar}")

    # ── 12. 保存模型（joblib 格式）───────────────────────────────
    xgb_path = os.path.join(models_dir, "xgboost_model.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    feature_names_path = os.path.join(models_dir, "feature_names.json")

    joblib.dump(final_model, xgb_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)

    # 保存元信息
    with open(feature_names_path, "w", encoding="utf-8") as f:
        json.dump({
            "version": "v3",
            "model_feature_columns": MODEL_FEATURE_COLUMNS,
            "db_feature_columns": DB_FEATURE_COLUMNS,
            "feature_count": N_FEATURES,
            "num_classes": num_classes,
            "classes": list(label_encoder.classes_),
            "smote_applied": True,
            "calibration": "sigmoid_cv3",
            "cv_macro_f1_mean": float(cv_scores.mean()) if cv_scores is not None else None,
            "test_accuracy": float(test_acc),
            "test_macro_f1": float(test_f1),
            "feature_importances": {
                feat_names[i]: float(importances[i])
                for i in indices
            },
        }, f, ensure_ascii=False, indent=2)

    print(f"\n  {'='*60}")
    print(f"  模型资产已保存（joblib 格式 v3）:")
    print(f"     XGBoost 模型:  {os.path.abspath(xgb_path)}")
    print(f"     标准化器:      {os.path.abspath(scaler_path)}")
    print(f"     标签编码器:    {os.path.abspath(encoder_path)}")
    print(f"     特征元信息:    {os.path.abspath(feature_names_path)}")
    print(f"  {'='*60}")

    return {
        "train_acc": train_acc,
        "train_macro_f1": train_f1,
        "test_acc": test_acc,
        "test_macro_f1": test_f1,
        "num_classes": num_classes,
        "feature_count": N_FEATURES,
        "cv_macro_f1_mean": float(cv_scores.mean()) if cv_scores is not None else None,
        "removed_classes": removed,
    }


if __name__ == "__main__":
    try:
        result = run_train_pipeline()
        print(f"\n{'='*70}")
        print(f"  训练完成摘要")
        print(f"{'='*70}")
        for k, v in result.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"\n  [FATAL] 训练中断: {e}")
        import traceback
        traceback.print_exc()
