import pandas as pd
import glob
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np

def load_and_merge_parquet(folder_path):
    all_files = glob.glob(os.path.join(folder_path, "*.parquet"))
    data_list = []
    
    print(f"发现 {len(all_files)} 个数据文件，正在加载...")
    
    for file in all_files:
        df = pd.read_parquet(file)
        # CIC-IDS-2017 常见的清理工作：去掉空格前缀的列名
        df.columns = df.columns.str.strip()
        data_list.append(df)
    
    # 合并所有数据
    full_df = pd.concat(data_list, axis=0, ignore_index=True)
    
    # 清理：处理无穷大(inf)和缺失值(NaN)，这是该数据集的常见问题
    full_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    full_df.dropna(inplace=True)
    
    return full_df

def prepare_ids_data(folder_path):
    df = load_and_merge_parquet(folder_path)
    
    # 1. 选择特征 (基于任务书和成员1能提取的字段)
    # 注意：具体列名需要打印 df.columns 查看，以下是常见核心特征
    features = [
        'Destination Port', 'Protocol', 'Flow Duration', 
        'Total Fwd Packets', 'Total Backward Packets',
        'Fwd Packet Length Max', 'Bwd Packet Length Max'
    ]
    
    # 确保这些列在数据集中存在
    available_features = [f for f in features if f in df.columns]
    
    X = df[available_features]
    y = df['Label']  # 数据集中通常有一列叫 Label

    # 2. 标签处理
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # 3. 标准化
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"数据处理完成！总样本量: {len(X_scaled)}, 类别: {le.classes_}")
    
    return train_test_split(X_scaled, y_encoded, test_size=0.2), scaler, le