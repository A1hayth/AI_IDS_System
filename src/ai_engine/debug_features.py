import pandas as pd
import glob
import os
import sys

# 设置路径
base_path = os.path.dirname(os.path.abspath(__file__))
# 这里的路径请确保指向你的 parquet 文件夹
dataset_path = os.path.join(base_path, "../../archive") 

# 读取第一个文件
all_files = glob.glob(os.path.join(dataset_path, "*.parquet"))
df = pd.read_parquet(all_files[0])
df.columns = df.columns.str.strip() # 去空格

# 检查你 config.py 里的 SELECTED_FEATURES 哪些真实存在了
# 这就是训练时 preprocess.py 执行的逻辑
selected = [
    'Destination Port', 'Protocol', 'Flow Duration', 
    'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Max', 'Bwd Packet Length Max'
]

actual_used = [f for f in selected if f in df.columns]

print("="*50)
print(f"📊 模型训练时【真实使用】的 6 个特征及其顺序是：")
for i, name in enumerate(actual_used):
    print(f"位置 {i}: {name}")
print("="*50)
print("请把这个顺序发给我，或者根据这个顺序重新排列你的 test_samples 数组。")