# coding=utf-8
import os
import gc
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

def load_and_clean_parquet(file_path):
    """
    读取 Parquet 数据集，并清洗其中的无穷大 (inf) 和缺失值 (NaN)。
    解决 scikit-learn 的 'Input X contains infinity or a value too large' 经典报错。
    """
    print(f"正在加载数据文件: {file_path} ...")
    # 读取 parquet 原始文件
    df = pd.read_parquet(file_path)
    
    # 1. 净化列名（移除前后置多余空格）
    df.columns = df.columns.str.strip()
    
    # 2. 核心清洗逻辑（重要！修复 inf 和 NaN 的极值报错）
    # 将 np.inf 和 -np.inf 字段批量替换为标准的 np.nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # 丢弃所有包含 nan 异常的观测数据行
    df.dropna(inplace=True)
    
    return df

def align_and_extract_features(df):
    """
    提取并映射 6 大核心特征维度与标签，处理非数值或遗留空字符。
    """
    # 6 大核心特征映射表 (自适应各种大小写、带空格或下划线版本字段)
    column_mapping = {
        'Protocol': 'protocol',
        'Flow Duration': 'flow_duration',
        'Total Fwd Packets': 'total_fwd_packets',
        'Total Backward Packets': 'total_backward_packets',
        'Fwd Packet Length Max': 'fwd_packet_length_max',
        'Bwd Packet Length Max': 'bwd_packet_length_max',
        'protocol': 'protocol',
        'flow_duration': 'flow_duration',
        'total_fwd_packets': 'total_fwd_packets',
        'total_backward_packets': 'total_backward_packets',
        'fwd_packet_length_max': 'fwd_packet_length_max',
        'bwd_packet_length_max': 'bwd_packet_length_max',
        'Label': 'label',
        'label': 'label'
    }
    
    # 重构列命名
    reduced_df = df.rename(columns=column_mapping)
    
    # 提取的核心列集合
    required_cols = ['protocol', 'flow_duration', 'total_fwd_packets', 'total_backward_packets', 'fwd_packet_length_max', 'bwd_packet_length_max']
    
    # 必要列交叉验证
    existing_cols = [col for col in required_cols if col in reduced_df.columns]
    if len(existing_cols) < len(required_cols):
        missing = set(required_cols) - set(existing_cols)
        raise ValueError(f"Parquet 数据集中缺少以下必需列: {missing}")
        
    X_df = reduced_df[required_cols].copy()
    
    # 标签判断提取
    if 'label' in reduced_df.columns:
        y_series = reduced_df['label'].copy()
    else:
        y_series = pd.Series(['BENIGN'] * len(X_df))
        
    # 数值二次安全防护
    X_df = X_df.apply(pd.to_numeric, errors='coerce')
    X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_df.fillna(0, inplace=True)
    
    return X_df, y_series

def extract_advanced_features(X_raw):
    """
    高级衍生特征接口（兜底供 predictor 调用）
    """
    return X_raw