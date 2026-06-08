import pandas as pd
import numpy as np
import glob
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

def prepare_ids_data(folder_path):
    """
    加载 CIC-IDS-2017 Parquet 数据集，并进行样本平衡处理
    """
    # 1. 获取所有 parquet 文件
    all_files = glob.glob(os.path.join(folder_path, "*.parquet"))
    if not all_files:
        raise FileNotFoundError(f"❌ 在路径 {folder_path} 下未找到数据文件！")

    # 2. 定义经过验证的 6 个核心特征（严格按顺序）
    # 这 6 个特征在大多数 CIC-IDS-2017 Parquet 版本中都存在
    SELECTED_FEATURES = [
        'Protocol', 
        'Flow Duration', 
        'Total Fwd Packets', 
        'Total Backward Packets',
        'Fwd Packet Length Max', 
        'Bwd Packet Length Max'
    ]

    data_list = []
    print(f"📂 正在加载 {len(all_files)} 个数据文件...")

    for file in all_files:
        df = pd.read_parquet(file)
        # 清洗列名：去空格
        df.columns = df.columns.str.strip()
        
        # 确保标签列存在
        label_col = 'Label' if 'Label' in df.columns else 'label'
        
        # 只提取需要的 6 个特征和标签
        # 使用 try-except 防止个别文件缺失列
        try:
            data_list.append(df[SELECTED_FEATURES + [label_col]])
        except KeyError as e:
            print(f"⚠️ 跳过文件 {os.path.basename(file)}，原因: 缺失列 {e}")

    # 合并数据
    full_df = pd.concat(data_list, axis=0, ignore_index=True)

    # 3. 数据清洗
    # 将 inf 替换为 NaN 并删除
    full_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    full_df.dropna(inplace=True)

    # 4. 【核心改进】样本平衡处理 (下采样)
    print("⚖️ 正在进行样本平衡处理...")
    
    # 分离正常样本和攻击样本
    benign_df = full_df[full_df[label_col].isin(['Benign', 'BENIGN'])]
    attack_df = full_df[~full_df[label_col].isin(['Benign', 'BENIGN'])]

    # 计算攻击样本总数
    num_attacks = len(attack_df)
    
    # 强制让正常样本的数量等于攻击样本的 1.5 倍（既保证了平衡，又保留了一定的真实分布）
    # 如果正常样本实在太多，就进行随机抽样
    num_benign_needed = int(num_attacks * 1.5)
    
    if len(benign_df) > num_benign_needed:
        benign_df = benign_df.sample(n=num_benign_needed, random_state=42)

    # 合并平衡后的数据并彻底打乱顺序
    balanced_df = pd.concat([benign_df, attack_df]).sample(frac=1, random_state=42)
    
    print(f"📊 平衡后统计: 正常样本={len(benign_df)}, 攻击样本={len(attack_df)}")

    # 5. 提取特征和标签
    X = balanced_df[SELECTED_FEATURES].values  # 转换为 NumPy 数组
    y = balanced_df[label_col].values

    # 6. 编码与标准化
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"✅ 数据预处理完成！最终特征数量: {X.shape[1]}")
    print(f"类别映射: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    return train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42), scaler, le

if __name__ == "__main__":
    # 测试代码逻辑
    # folder = "../../archive"
    # (X_train, X_test, y_train, y_test), scaler, le = prepare_ids_data(folder)
    pass