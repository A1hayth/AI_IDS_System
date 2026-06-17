# coding=utf-8
"""
AI-IDS 数据预处理模块 (v3)

改进点:
    - clean_labels(): 修复 Unicode 编码问题，统一标签格式
    - filter_rare_classes(): 剔除样本过少的类别
    - align_and_extract_features(): 从 6 维扩展到 15 维精选特征
    - 使用 config.py 的 CIC_TO_MODEL_COLUMN_MAP 统一映射
"""
import os
import sys
import gc
import numpy as np
import pandas as pd
from collections import Counter

# 路径注入
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
for p in [current_dir, parent_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from config import (
    MODEL_FEATURE_COLUMNS,
    CIC_TO_MODEL_COLUMN_MAP,
    MIN_SAMPLES_PER_CLASS,
)


# ============================================================================
# 标签清洗
# ============================================================================

def clean_labels(y: pd.Series) -> pd.Series:
    """清洗并统一标签格式。

    处理:
        1. 修复 Unicode 替换字符（� → –，如 'Web Attack � Brute Force'）
        2. 统一 'BENIGN'/'Benign' → 'Benign'
        3. 去除首尾空格
        4. 标准化已知攻击标签名

    Args:
        y: 原始标签 Series。

    Returns:
        清洗后的标签 Series。
    """
    # 1. 修复 Unicode 替换字符
    y = y.astype(str).str.replace('�', '–', regex=False)  # � → – (en dash)
    y = y.str.replace('�', '-', regex=False)                   # fallback: � → -

    # 2. 统一 Benign 标签
    y = y.str.strip()
    y = y.replace({'BENIGN': 'Benign', 'benign': 'Benign', 'BENIGN': 'Benign'})

    # 3. 标准化已知变体
    label_fixes = {
        'Web Attack – Brute Force': 'Web Attack - Brute Force',
        'Web Attack – Sql Injection': 'Web Attack - Sql Injection',
        'Web Attack – XSS': 'Web Attack - XSS',
        'Web Attack � Brute Force': 'Web Attack - Brute Force',
        'Web Attack � Sql Injection': 'Web Attack - Sql Injection',
        'Web Attack � XSS': 'Web Attack - XSS',
        'Web Attack - Brute Force': 'Web Attack - Brute Force',
        'Web Attack - Sql Injection': 'Web Attack - Sql Injection',
        'Web Attack - XSS': 'Web Attack - XSS',
    }
    y = y.replace(label_fixes)

    return y


def filter_rare_classes(X: pd.DataFrame, y: pd.Series,
                        min_samples: int = None) -> tuple:
    """剔除样本数过少的类别。

    Args:
        X: 特征 DataFrame。
        y: 标签 Series（已清洗）。
        min_samples: 最少样本数阈值，默认使用 config.MIN_SAMPLES_PER_CLASS。

    Returns:
        (X_filtered, y_filtered, removed_classes) 三元组。
    """
    if min_samples is None:
        min_samples = MIN_SAMPLES_PER_CLASS

    counts = Counter(y)
    removed = [c for c, n in counts.items() if n < min_samples]

    if removed:
        print(f"  剔除稀有类别 (样本数 < {min_samples}):")
        for c in removed:
            print(f"    - {c}: {counts[c]} 样本")
        mask = ~y.isin(removed)
        X = X.loc[mask].copy()
        y = y.loc[mask].copy()
    else:
        print(f"  所有类别样本数 ≥ {min_samples}，无需剔除")

    return X, y, removed


# ============================================================================
# 数据加载与清洗
# ============================================================================

def load_and_clean_parquet(file_path):
    """读取 Parquet 数据集，清洗无穷大 (inf) 和缺失值 (NaN)。

    解决 scikit-learn 的 'Input X contains infinity or a value too large' 经典报错。
    """
    print(f"  正在加载: {os.path.basename(file_path)} ...")
    df = pd.read_parquet(file_path)

    # 1. 净化列名（移除前后置多余空格）
    df.columns = df.columns.str.strip()

    # 2. 核心清洗逻辑
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    return df


# ============================================================================
# 特征提取（v3: 6 → 15 维）
# ============================================================================

def align_and_extract_features(df):
    """从 CIC-IDS-2017 原始数据中提取 15 维精选特征 + 标签。

    使用 config.py 的 CIC_TO_MODEL_COLUMN_MAP 映射列名，
    确保与训练/推理全链路一致。

    Args:
        df: 已清洗的原始 DataFrame（含 78 列 CIC-IDS-2017 特征）。

    Returns:
        (X_df, y_series) — 15 维特征 DataFrame 和标签 Series。
    """
    # ── 特征列映射 ──
    # 先重命名 CIC 原始列名 → 模型 lowercase 列名
    rename_map = {}
    for cic_name, model_name in CIC_TO_MODEL_COLUMN_MAP.items():
        if cic_name in df.columns:
            rename_map[cic_name] = model_name

    reduced_df = df.rename(columns=rename_map)

    # ── 提取 15 个特征列 ──
    required_cols = list(MODEL_FEATURE_COLUMNS)
    missing = set(required_cols) - set(reduced_df.columns)
    if missing:
        raise ValueError(
            f"Parquet 数据集中缺少必需列: {missing}\n"
            f"可用列: {list(reduced_df.columns)}"
        )

    X_df = reduced_df[required_cols].copy()

    # ── 标签提取 ──
    if 'Label' in df.columns:
        y_series = df['Label'].copy()
    elif 'label' in df.columns:
        y_series = df['label'].copy()
    else:
        # 无标签时默认 Benign（不应在训练时发生）
        y_series = pd.Series(['Benign'] * len(X_df))
        print(f"    警告: 未找到 Label 列，默认全部标记为 Benign")

    # ── 标签清洗 ──
    y_series = clean_labels(y_series)

    # ── 数值安全防护 ──
    X_df = X_df.apply(pd.to_numeric, errors='coerce')
    X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_df.fillna(0, inplace=True)

    # ── 打印数据概况 ──
    label_counts = Counter(y_series)
    print(f"    样本: {len(X_df):,} 行, {len(X_df.columns)} 维特征")
    print(f"    标签分布: {dict(label_counts.most_common(5))}"
          + (f" ...共 {len(label_counts)} 类" if len(label_counts) > 5 else ""))

    return X_df, y_series


# ============================================================================
# 兜底接口
# ============================================================================

def extract_advanced_features(X_raw):
    """高级衍生特征接口（兜底供 predictor 调用）。"""
    return X_raw
