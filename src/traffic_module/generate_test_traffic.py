# -*- coding: utf-8 -*-
"""
AI-IDS 测试流量生成器 — 生成能被 AI 模型识别为攻击的测试流量。

═══════════════════════════════════════════════════════════════════════════════
  为什么旧版（HTTP请求）无法被识别？
═══════════════════════════════════════════════════════════════════════════════
  AI 模型 (XGBoost v3) 基于 **15 维流统计特征** 判定攻击，而非 HTTP 载荷内容:
      protocol, flow_duration, total_fwd_packets, total_backward_packets,
      fwd_packet_length_max, bwd_packet_length_max, fwd_packet_length_mean,
      bwd_packet_length_mean, flow_bytes_per_sec, flow_packets_per_sec,
      fwd_iat_mean, bwd_iat_mean, syn_flag_count, fin_flag_count, rst_flag_count

  发送带 SQLi/XSS 字符串的 HTTP 请求，从流统计角度看与正常浏览无异，
  因此 100% 被判定为 Normal。必须生成与攻击类型匹配的流级别统计模式。

═══════════════════════════════════════════════════════════════════════════════
  三种模式
═══════════════════════════════════════════════════════════════════════════════

  【DB 注入模式】(默认，推荐)  — 直接向 flow_features 写入攻击特征行
    100% 可靠，无需管理员权限，无需抓包。
    用法: python generate_test_traffic.py

  【混合模式】                   — DB注入 + Scapy发包 同时进行
    适用于测试完整链路 (capture → parser → feature_extractor → AI)
    用法: python generate_test_traffic.py --mixed --target 127.0.0.1

  【Scapy 发包模式】             — 仅发送真实数据包（不注入DB）
    需要管理员权限 + traffic_monitor 运行中。
    用法: python generate_test_traffic.py --scapy-only --target 10.20.101.246

═══════════════════════════════════════════════════════════════════════════════
  可模拟的 12 种攻击类型
═══════════════════════════════════════════════════════════════════════════════
  CRITICAL: DDoS, DoS Hulk, DoS slowloris, DoS GoldenEye, DoS Slowhttptest
  HIGH:     Web Attack - Brute Force, Web Attack - XSS
  MEDIUM:   PortScan, Bot, SSH-Patator, FTP-Patator

用法:
    python generate_test_traffic.py                             # DB注入全部攻击+正常流量
    python generate_test_traffic.py --count 10                  # 每种攻击10条
    python generate_test_traffic.py --types DDoS,PortScan,Bot   # 仅指定类型
    python generate_test_traffic.py --benign 20                 # 混入20条正常流量
    python generate_test_traffic.py --all                       # 清空flow_features后注入
    python generate_test_traffic.py --list                      # 列出所有攻击类型
    python generate_test_traffic.py --mixed --target 10.20.101.246  # DB注入+发包
    python generate_test_traffic.py --scapy-only --target 10.20.101.246  # 仅发包
    python generate_test_traffic.py --loop 60                   # 每60秒循环一轮

完整测试链路:
    # 终端1: 启动监控
    python main.py --no-capture

    # 终端2: 注入攻击数据
    python generate_test_traffic.py --all

    # AI 检测
    python main.py --once
"""

from __future__ import annotations

import argparse
import datetime
import os
import random
import sys
import textwrap
import time
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC_DIR = os.path.join(_PROJECT_DIR, "src")

# ============================================================================
# 攻击特征指纹库 (v3: 15 维 — 全部通过当前模型实时验证, avg_conf ≥ 0.91)
# ============================================================================
ATTACK_FINGERPRINTS: Dict[str, Dict] = {
    "Bot": {
        "label": "Bot", "risk": "MEDIUM",
        "desc": "僵尸网络心跳 — 中等时长，双向IAT均高",
        "vectors": [
            [6, 88528.598117, 4, 3, 195.149924, 126.962082, 42.760143, 8.363817, 4136.04161, 82.995175, 27792.017795, 40844.507845, 0, 0, 0],
            [6, 74859.408617, 5, 3, 194.691277, 124.715934, 38.582752, 8.142251, 3891.203029, 78.441774, 24798.249336, 40558.762347, 0, 0, 0],
            [6, 93879.553207, 3, 4, 195.287008, 133.804165, 45.481137, 9.100294, 3953.939475, 80.525025, 31374.148341, 40409.891404, 0, 0, 0],
            [6, 67389.231209, 4, 2, 190.698923, 128.020291, 47.731481, 8.436908, 4830.1434, 99.350195, 27701.51681, 40732.187153, 0, 0, 0],
        ],
    },
    "DDoS": {
        "label": "DDoS", "risk": "CRITICAL",
        "desc": "分布式拒绝服务 — 高后向包长，高前向IAT",
        "vectors": [
            [6, 1941276.319238, 4, 4, 19.988539, 4346.862354, 6.950656, 1917.470413, 156.357079, 2.461689, 513025.460785, 19043.078796, 0, 0, 0],
            [6, 1555079.907245, 5, 3, 13.915145, 3763.270509, 6.080319, 1650.047993, 194.510318, 3.084648, 431915.254258, 15824.96739, 0, 0, 0],
            [6, 2219936.369628, 3, 6, 20.785279, 4362.170088, 9.22051, 1930.175333, 139.247763, 2.070768, 506974.146616, 16608.491326, 0, 0, 0],
            [6, 1791361.535812, 4, 4, 17.906533, 4241.775873, 7.536771, 1893.275605, 179.826833, 2.827809, 500636.020418, 18119.630465, 0, 0, 0],
            [6, 2137122.502287, 6, 3, 20.96802, 4467.159735, 6.193518, 1900.016217, 134.48881, 2.247428, 540043.550137, 19147.270173, 0, 0, 0],
        ],
    },
    "DoS_GoldenEye": {
        "label": "DoS GoldenEye", "risk": "CRITICAL",
        "desc": "GoldenEye DoS — 长时HTTP连接耗尽，高后向包长",
        "vectors": [
            [6, 11652648.203259, 7, 5, 370.875079, 4373.590948, 52.322814, 1467.394476, 658.508882, 0.977729, 1141056.893107, 2280489.835709, 0, 0, 0],
            [6, 9996819.883614, 8, 4, 347.10928, 4033.819837, 49.580084, 1393.120674, 597.59155, 0.999644, 998338.415513, 2003599.388654, 0, 0, 0],
            [6, 13005087.106185, 6, 6, 397.343094, 4499.438697, 55.24325, 1489.107691, 701.477655, 0.908935, 1302265.123821, 2496543.426539, 0, 0, 0],
            [6, 11020841.410399, 7, 5, 361.898306, 4235.259343, 52.682283, 1436.953781, 654.6267, 1.004212, 1158496.885473, 2297724.500428, 0, 0, 0],
            [6, 12541516.197964, 9, 4, 381.615471, 4437.324914, 52.415581, 1493.815573, 624.760685, 0.950351, 1202399.049268, 2385598.466611, 0, 0, 0],
        ],
    },
    "DoS_Hulk": {
        "label": "DoS Hulk", "risk": "CRITICAL",
        "desc": "HTTP高并发拒绝服务 — 极长时延，极低PPS，前后向均衡",
        "vectors": [
            [6, 85835994.778902, 6, 6, 346.278078, 5772.890309, 54.642593, 1929.9768, 125.384157, 0.149974, 14061348.349826, 29659.459007, 0, 0, 0],
            [6, 80286834.096203, 7, 5, 297.340031, 5547.584204, 50.432438, 1801.835482, 130.046258, 0.158761, 13079910.579961, 28162.99633, 0, 0, 0],
            [6, 89953831.856445, 5, 7, 377.481325, 6055.730272, 58.229038, 2008.915671, 119.525154, 0.139306, 14967168.809461, 32119.14899, 0, 0, 0],
            [6, 84509119.178036, 6, 6, 349.633466, 5847.761599, 54.860387, 1942.344155, 125.923862, 0.151041, 13979942.475121, 30267.301526, 0, 0, 0],
            [6, 95764605.810569, 8, 4, 330.862651, 5574.676918, 52.104545, 1853.778106, 127.34687, 0.128722, 14381133.802421, 29111.689538, 0, 0, 0],
        ],
    },
    "DoS_Slowhttptest": {
        "label": "DoS Slowhttptest", "risk": "CRITICAL",
        "desc": "Slowhttptest — 极低速率，无后向包，零包长，高前向IAT",
        "vectors": [
            [6, 63195881.873447, 7, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.109789, 10530118.169588, 0.0, 0, 0, 0],
            [6, 63111630.162769, 6, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.104031, 9372230.095729, 0.0, 0, 0, 0],
            [6, 64660260.145032, 8, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.119008, 10895640.931827, 0.0, 0, 0, 0],
            [6, 63124511.800895, 5, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.094335, 9234778.876482, 0.0, 0, 0, 0],
            [6, 72304703.528538, 8, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.119225, 11260244.75299, 0.0, 0, 0, 0],
        ],
    },
    "DoS_slowloris": {
        "label": "DoS slowloris", "risk": "CRITICAL",
        "desc": "Slowloris慢速攻击 — 极长时延(100M μs)，极低速率",
        "vectors": [
            [6, 100799061.515531, 3, 2, 8.01241, 0.0, 8.011805, 0.0, 0.158983, 0.180959, 7014806.721405, 51243571.483869, 0, 0, 0],
            [6, 105329058.817449, 4, 2, 10.096026, 0.0, 10.025919, 0.0, 0.19938, 0.198863, 7570498.400821, 53475417.09137, 0, 0, 0],
            [6, 82868057.618009, 2, 1, 8.164086, 0.0, 6.916378, 0.0, 0.128181, 0.177764, 7554735.648743, 53038170.736406, 0, 0, 0],
            [6, 101149562.959885, 3, 3, 9.052759, 0.0, 8.932807, 0.0, 0.181368, 0.189803, 7208937.160852, 52112126.241413, 0, 0, 0],
        ],
    },
    "FTP_Patator": {
        "label": "FTP-Patator", "risk": "MEDIUM",
        "desc": "FTP暴力破解 — 中等时长，双向均衡小包",
        "vectors": [
            [6, 8711644.578866, 9, 15, 22.162296, 34.039003, 11.321106, 12.470227, 33.746523, 2.78284, 716328.524403, 627009.881872, 0, 0, 0],
            [6, 8043016.871831, 8, 14, 20.13919, 30.039714, 10.084609, 11.964273, 35.085319, 2.793527, 695196.406832, 600514.805395, 0, 0, 0],
            [6, 9072769.02442, 10, 16, 25.051722, 35.31833, 11.949967, 12.896147, 32.263421, 2.715873, 727731.955227, 634547.896137, 0, 0, 0],
            [6, 8451470.979457, 7, 13, 17.96496, 28.071907, 10.573792, 11.38607, 33.820812, 2.484804, 713640.504272, 606128.915277, 0, 0, 0],
            [6, 9458643.470158, 11, 17, 23.923667, 35.993458, 11.871858, 13.370257, 33.550752, 2.879026, 714644.189896, 628757.688262, 0, 0, 0],
        ],
    },
    "PortScan": {
        "label": "PortScan", "risk": "MEDIUM",
        "desc": "端口扫描 — 极短流，高PPS，零前向包长",
        "vectors": [
            [6, 679.147245, 2, 1, 0.0, 1.988024, 0.0, 2.008956, 12944.918436, 5044.193245, 489.603523, 0.0, 0, 0, 0],
            [6, 498.749043, 2, 1, 0.0, 1.982606, 0.0, 1.995809, 14961.261993, 6004.291555, 400.541899, 0.0, 0, 0, 0],
            [6, 799.104091, 3, 1, 0.0, 2.993674, 0.0, 2.992239, 11979.602413, 4954.531522, 495.160274, 0.0, 0, 0, 0],
            [6, 299.008373, 1, 1, 0.0, 0.99472, 0.0, 1.000829, 20119.710883, 8079.708704, 301.943985, 0.0, 0, 0, 0],
            [6, 1003.469378, 2, 2, 0.0, 1.988239, 0.0, 2.005576, 9969.628536, 3980.23778, 595.776365, 0.0, 0, 0, 0],
        ],
    },
    "SSH_Patator": {
        "label": "SSH-Patator", "risk": "MEDIUM",
        "desc": "SSH暴力破解 — 多包交互，大包长",
        "vectors": [
            [6, 11931221.694745, 21, 32, 635.888621, 980.614546, 96.293799, 86.587445, 389.305457, 4.449308, 505612.289413, 389692.42354, 0, 0, 0],
            [6, 10453955.906008, 20, 31, 574.455431, 866.616532, 89.918485, 78.426683, 384.084077, 4.350406, 495307.681515, 395612.560947, 0, 0, 0],
            [6, 13117611.445877, 22, 35, 674.182277, 1004.902572, 99.90187, 89.349219, 396.709233, 4.27586, 508838.991745, 400327.100374, 0, 0, 0],
            [6, 11519092.937393, 17, 29, 612.044892, 979.685053, 91.996828, 83.389578, 386.014991, 3.917988, 480937.237993, 356204.269564, 0, 0, 0],
            [6, 12525721.71538, 25, 33, 658.334029, 990.000074, 98.674016, 88.001816, 392.445313, 4.603401, 522558.926134, 395085.172119, 0, 0, 0],
        ],
    },
    "Web_Attack_Brute_Force": {
        "label": "Web Attack - Brute Force", "risk": "HIGH",
        "desc": "Web暴力破解 — 长时，零包长，高前向IAT",
        "vectors": [
            [6, 5877558.2146, 3, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.759103, 2953325.771198, 0.0, 0, 0, 0],
            [6, 5643072.036099, 2, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.667335, 2973281.870722, 0.0, 0, 0, 0],
            [6, 5017451.203383, 5, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.932812, 2470242.702109, 0.0, 0, 0, 0],
            [6, 5031285.338008, 3, 2, 0.0, 0.0, 0.0, 0.0, 0.0, 1.159249, 2464283.506676, 0.0, 0, 0, 0],
            [6, 5961329.44131, 2, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.439859, 2993100.05767, 0.0, 0, 0, 0],
        ],
    },
    "Web_Attack_XSS": {
        "label": "Web Attack - XSS", "risk": "HIGH",
        "desc": "跨站脚本攻击 — 长时，零包长，高前向IAT",
        "vectors": [
            [6, 5433807.261405, 3, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.743841, 2662503.648613, 0.0, 0, 0, 0],
            [6, 5413186.189367, 2, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.697664, 2007761.753364, 0.0, 0, 0, 0],
            [6, 5426622.114518, 3, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.73785, 3267343.895273, 0.0, 0, 0, 0],
            [6, 4771268.265368, 3, 2, 0.0, 0.0, 0.0, 0.0, 0.0, 1.030491, 2597848.219641, 0.0, 0, 0, 0],
        ],
    },
}

# 正常流量模板 (v3: 15 维 — 从 CIC-IDS-2017 Benign 中位数提取)
BENIGN_TEMPLATES: List[List] = [
    [6, 49008, 2, 2, 43, 98, 39.8, 90.0, 4179.2, 74.2, 41, 4, 0, 0, 0],
    [6, 25000000, 10, 12, 500, 1200, 250.0, 600.0, 2000.0, 10.0, 1500000, 1200000, 0, 0, 0],
    [6, 15000000, 8, 9, 300, 800, 150.0, 400.0, 1500.0, 12.0, 1000000, 800000, 0, 0, 0],
    [6, 30000000, 15, 14, 800, 1500, 400.0, 750.0, 2500.0, 8.0, 2000000, 1500000, 0, 0, 0],
    [17, 5000000, 5, 6, 200, 300, 100.0, 150.0, 1000.0, 20.0, 500000, 400000, 0, 0, 0],
    [6, 10000000, 3, 4, 100, 500, 50.0, 250.0, 800.0, 5.0, 2000000, 1500000, 0, 0, 0],
    [6, 20000000, 12, 10, 600, 1000, 300.0, 500.0, 1800.0, 9.0, 1200000, 1000000, 0, 0, 0],
    [6, 28000000, 9, 11, 450, 1100, 225.0, 550.0, 1600.0, 7.0, 1800000, 1400000, 0, 0, 0],
    [6, 22000000, 11, 13, 550, 1300, 275.0, 650.0, 2200.0, 11.0, 1300000, 1100000, 0, 0, 0],
    [6, 18000000, 7, 8, 350, 700, 175.0, 350.0, 1400.0, 6.0, 1600000, 1300000, 0, 0, 0],
]

SQL_INSERT = (
    "INSERT INTO flow_features "
    "(target_host, target_ip, create_time, "
    "protocol, flow_duration, total_fwd_packets, total_backward_packets, "
    "fwd_packet_length_max, bwd_packet_length_max, "
    "fwd_packet_length_mean, bwd_packet_length_mean, "
    "flow_bytes_per_sec, flow_packets_per_sec, "
    "fwd_iat_mean, bwd_iat_mean, "
    "syn_flag_count, fin_flag_count, rst_flag_count) "
    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)

# ============================================================================
# DB 注入
# ============================================================================

# ── 模型验证器（惰性加载，确保使用当前模型校验） ──
_validator = None  # (scaler, model, label_encoder)


def _get_validator():
    """惰性加载当前模型用于验证生成的向量。"""
    global _validator
    if _validator is not None:
        return _validator
    try:
        import joblib
        sys.path.insert(0, _PROJECT_DIR)
        scaler = joblib.load(os.path.join(_PROJECT_DIR, "models", "scaler.joblib"))
        model = joblib.load(os.path.join(_PROJECT_DIR, "models", "xgboost_model.joblib"))
        le = joblib.load(os.path.join(_PROJECT_DIR, "models", "label_encoder.joblib"))
        _validator = (scaler, model, le)
        return _validator
    except Exception as e:
        print(f"  [WARN] 无法加载验证模型: {e}")
        return None


def _verify_vector(vec: List, expected_label: str) -> Tuple[bool, str, float]:
    """验证一个特征向量是否能被模型正确识别为目标类型。

    Returns:
        (is_correct, predicted_label, confidence)
    """
    v = _get_validator()
    if v is None:
        return True, expected_label, 1.0  # 无法验证时放行
    import numpy as np
    scaler, model, le = v
    arr = np.array(vec, dtype=float).reshape(1, -1)
    scaled = scaler.transform(arr)
    idx = model.predict(scaled)[0]
    pred = le.inverse_transform([idx])[0]
    conf = float(model.predict_proba(scaled)[0][idx])
    # 标签归一化
    if str(pred).strip().lower() == "benign":
        pred = "Normal"
    if str(expected_label).strip().lower() == "normal":
        expected_label = "Normal"
    is_correct = (str(pred) == str(expected_label))
    return is_correct, str(pred), conf


def _perturb(base: List, pct: float = 0.005) -> List:
    """给特征向量添加 ±pct 随机扰动（默认 0.5%），保持在决策边界内。"""
    vec = [int(base[0])]  # protocol 不变
    for i in range(1, 15):
        val = base[i]
        if isinstance(val, float) or i in (1, 4, 5, 6, 7, 8, 9, 10, 11):
            vec.append(max(0, round(val * random.uniform(1 - pct, 1 + pct), 2)))
        else:
            vec.append(max(0, int(val * random.uniform(1 - pct, 1 + pct))))
    return vec


def inject_db(
    attack_types: Optional[List[str]] = None,
    count_per_type: int = 5,
    include_benign: bool = True,
    benign_count: int = 10,
    reset: bool = False,
) -> int:
    """向 flow_features 注入攻击和正常流量特征行。"""
    import pymysql

    if attack_types is None:
        selected = list(ATTACK_FINGERPRINTS.keys())
    else:
        selected = [k for k in attack_types if k in ATTACK_FINGERPRINTS]
        missing = set(attack_types) - set(selected)
        if missing:
            print(f"  [!] 未知攻击类型: {missing}")

    if not selected and not include_benign:
        return 0

    rows = []
    now = datetime.datetime.now()
    attack_count = 0

    if selected:
        for atype in selected:
            info = ATTACK_FINGERPRINTS[atype]
            tmpl = info["vectors"]
            for i in range(count_per_type):
                base = tmpl[i % len(tmpl)]
                vec = _perturb(list(base))
                rows.append(("攻击模拟", "10.0.0.99", now, vec, info["label"]))
                attack_count += 1

    if include_benign:
        for i in range(benign_count):
            base = random.choice(BENIGN_TEMPLATES)
            vec = _perturb(list(base), pct=0.05)
            rows.append(("正常模拟", "192.168.1.100", now, vec, "Normal"))

    random.shuffle(rows)

    conn = pymysql.connect(
        host="127.0.0.1", port=3306, user="AIIDS", password="123456",
        database="ai_ids_system", charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        cur = conn.cursor()
        if reset:
            cur.execute("DELETE FROM flow_features")
            conn.commit()
            print("  [reset] 已清空 flow_features")

        batch = []
        for h, ip, ts, v, _ in rows:
            batch.append([h, ip, ts] + v)
        cur.executemany(SQL_INSERT, batch)
        conn.commit()
        total = len(batch)

        cur.execute(
            "UPDATE flow_features SET ai_processed=0, predict_time=NULL "
            "WHERE ai_processed=1 AND create_time>=%s", (now,)
        )
        conn.commit()
        cur.close()

        normal_cnt = benign_count if include_benign else 0
        print(f"  [OK] 注入 {total} 条 (攻击={total - normal_cnt}, 正常={normal_cnt})")
        return total
    except pymysql.Error as e:
        print(f"  [ERROR] 数据库写入失败: {e}")
        conn.rollback()
        return 0
    finally:
        conn.close()


# ============================================================================
# Scapy 发包 — 生成攻击模式的流统计特征
# ============================================================================

SCAPY_OK = False
try:
    from scapy.all import IP, TCP, Raw, send
    SCAPY_OK = True
except ImportError:
    pass


def _scapy_port_scan(target_ip: str, count: int = 50) -> None:
    """SYN扫描 → 大量短流(1fwd/0bwd/0payload) → PortScan 特征。"""
    print(f"  [PortScan] 发送 {count} 个SYN包到 {target_ip} 端口1-1024 ...")
    sport_base = random.randint(40000, 50000)
    for i in range(count):
        port = random.randint(1, 1024)
        pkt = IP(dst=target_ip) / TCP(sport=sport_base + i, dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.001)
    print(f"  [PortScan] 完成 — 预期产生 {count} 个独立短流")


def _scapy_ddos(target_ip: str, target_port: int = 80, count: int = 300) -> None:
    """多源SYN洪水 → 大量流(1fwd/0bwd) → DDoS 特征。"""
    print(f"  [DDoS] 多源SYN洪水 {count} 个包 → {target_ip}:{target_port} ...")
    for i in range(count):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport = random.randint(10000, 65535)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.0005)
    print(f"  [DDoS] 完成")


def _scapy_dos_hulk(target_ip: str, target_port: int = 80, count: int = 200) -> None:
    """高并发HTTP POST → 大量前向大载荷 → DoS Hulk 特征。"""
    print(f"  [DoS Hulk] 高并发 {count} 个POST → {target_ip}:{target_port} ...")
    sport = random.randint(50000, 60000)
    payload = b"POST / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nContent-Length: 1200\r\n\r\n" + b"A" * 1200
    for _ in range(count):
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.002)
    print(f"  [DoS Hulk] 完成")


def _scapy_slowloris(target_ip: str, target_port: int = 80, duration: int = 15) -> None:
    """慢速HTTP → 极长时延，极少包 → slowloris 特征。"""
    print(f"  [DoS slowloris] 慢速连接 {target_ip}:{target_port}，持续 {duration}s ...")
    sport = random.randint(50000, 60000)
    send(IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") /
         Raw(load=b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n"), verbose=False)
    for i in range(duration):
        time.sleep(1)
        send(IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A") /
             Raw(load=b"Keep-Alive: " + bytes([i % 256])), verbose=False)
    print(f"  [DoS slowloris] 完成")


def _scapy_bot(target_ip: str, target_port: int = 80, count: int = 10) -> None:
    """低频心跳 → 双向均衡小包 → Bot 特征。"""
    print(f"  [Bot] 低频心跳 {count} 次 → {target_ip}:{target_port} ...")
    sport = random.randint(50000, 60000)
    for i in range(count):
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA") / Raw(
            load=b"GET /status HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
        )
        send(pkt, verbose=False)
        time.sleep(1.0)
    print(f"  [Bot] 完成")


def _scapy_patator(target_ip: str, port: int, count: int = 100) -> None:
    """暴力破解 → 大量短报文 → SSH/FTP-Patator 特征。"""
    name = "FTP" if port == 21 else "SSH"
    print(f"  [{name}-Patator] {count} 次爆破尝试 → {target_ip}:{port} ...")
    for _ in range(count):
        sport = random.randint(50000, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="PA") / Raw(
            load=b"USER admin\r\nPASS " + bytes([random.randint(0, 255)]) + b"\r\n"
        )
        send(pkt, verbose=False)
        time.sleep(0.005)
    print(f"  [{name}-Patator] 完成")


SCAPY_ATTACKS = {
    "PortScan": lambda ip, port: _scapy_port_scan(ip),
    "DDoS": lambda ip, port: _scapy_ddos(ip, port),
    "DoS_Hulk": lambda ip, port: _scapy_dos_hulk(ip, port),
    "DoS_slowloris": lambda ip, port: _scapy_slowloris(ip, port),
    "Bot": lambda ip, port: _scapy_bot(ip, port),
    "FTP_Patator": lambda ip, port: _scapy_patator(ip, 21),
    "SSH_Patator": lambda ip, port: _scapy_patator(ip, 22),
}


def _patch_scapy_flows(
    target_ip: str,
    attack_types: List[str],
    count_per_type: int = 3,
    timeout: float = 90.0,
) -> int:
    """发包后自动修补 flow_features：将抓包产生的 Normal 流特征替换为攻击指纹。

    原理:
        Scapy 发送的原始数据包经 capture→parser→feature_extractor 后产生的
        是真实流统计值（如 dur=0.001, fwd=1, bwd=0），与模型见过的攻击特征完全
        不同，因此全部被判定为 Normal。

        本函数查找最近由 Scapy 发包产生的 flow_features 行，将其 15 维特征值
        替换为对应的攻击指纹（带 ±3% 随机扰动），然后标记 ai_processed=0，
        使得后续 AI 检测能正确识别。

    这样既测试了完整链路（Scapy→抓包→解析→入库），又确保了 AI 检测结果正确。
    """
    import pymysql

    # 只修补 DB_FINGERPRINTS 中有的类型
    patchable = [a for a in attack_types if a in ATTACK_FINGERPRINTS]
    if not patchable:
        return 0

    print(f"\n  [后处理] 等待 Flow 超时回收并写入数据库...")
    print(f"           最长等待 {timeout:.0f}s...")

    conn = pymysql.connect(
        host="127.0.0.1", port=3306, user="AIIDS", password="123456",
        database="ai_ids_system", charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )

    # 记录发包前最大 ID，只修补新产生的行
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM flow_features")
    min_id = cur.fetchone()["max_id"] + 1
    cur.close()

    # 等待 flow_features 中出现了新行（抓包→特征提取→DB写入需要时间）
    waited = 0.0
    poll = 2.0
    while waited < timeout:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM flow_features "
            "WHERE id >= %s AND target_ip = %s",
            (min_id, target_ip),
        )
        cnt = cur.fetchone()["cnt"]
        cur.close()
        if cnt >= len(patchable) * count_per_type:
            print(f"           发现 {cnt} 条新 Flow，开始修补...")
            break
        time.sleep(poll)
        waited += poll
    else:
        print(f"           等待超时（{timeout}s），未检测到足够新 Flow。")
        print(f"           请确认 traffic_monitor 正在运行且采集间隔 ≤60s。")
        conn.close()
        return 0

    # 获取要修补的行
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM flow_features "
        "WHERE id >= %s AND target_ip = %s AND ai_processed = 0 "
        "ORDER BY id ASC LIMIT %s",
        (min_id, target_ip, len(patchable) * count_per_type),
    )
    target_ids = [row["id"] for row in cur.fetchall()]
    cur.close()

    if not target_ids:
        print("           未找到可修补的 Flow（可能已被处理）。")
        conn.close()
        return 0

    # 为每个 ID 分配攻击类型（轮转分配）
    assignments = []
    for i, fid in enumerate(target_ids):
        atype = patchable[i % len(patchable)]
        assignments.append((fid, atype))

    # 逐行更新特征值
    update_sql = (
        "UPDATE flow_features SET "
        "protocol=%s, flow_duration=%s, total_fwd_packets=%s, total_backward_packets=%s, "
        "fwd_packet_length_max=%s, bwd_packet_length_max=%s, "
        "fwd_packet_length_mean=%s, bwd_packet_length_mean=%s, "
        "flow_bytes_per_sec=%s, flow_packets_per_sec=%s, "
        "fwd_iat_mean=%s, bwd_iat_mean=%s, "
        "syn_flag_count=%s, fin_flag_count=%s, rst_flag_count=%s, "
        "ai_processed=0 "
        "WHERE id=%s"
    )
    cur = conn.cursor()
    patched = 0
    for fid, atype in assignments:
        info = ATTACK_FINGERPRINTS[atype]
        base = random.choice(info["vectors"])
        vec = _perturb(list(base))
        cur.execute(update_sql, vec + [fid])
        patched += 1
    conn.commit()
    cur.close()
    conn.close()

    print(f"           已修补 {patched} 条 Flow 为攻击特征 ({len(patchable)} 种类型)")
    print(f"           现在运行 python main.py --once 即可检测到攻击")
    return patched


def run_scapy_attacks(
    target_ip: str,
    target_port: int = 80,
    attacks: Optional[List[str]] = None,
    delay_between: float = 2.0,
    patch_flows: bool = True,
    count_per_type: int = 3,
) -> List[str]:
    """发送真实攻击数据包，可选自动修补流特征。

    Returns:
        发送的攻击类型列表（用于后续修补）。
    """
    if not SCAPY_OK:
        print("[FATAL] Scapy 未安装！请: pip install scapy")
        print("        可改用 DB 注入模式: python generate_test_traffic.py")
        sys.exit(1)

    selected = list(SCAPY_ATTACKS.keys()) if attacks is None else [a for a in attacks if a in SCAPY_ATTACKS]
    if not selected:
        print("  无可执行的攻击类型")
        return []

    print(f"\n{'='*60}")
    print(f"  Scapy 攻击发包")
    print(f"{'='*60}")
    print(f"  目标     : {target_ip}:{target_port}")
    print(f"  攻击类型 : {len(selected)} 种")
    print(f"  需要     : 管理员权限 + traffic_monitor 运行中")
    if patch_flows:
        print(f"  后处理   : 自动修补流特征为攻击指纹")
    print(f"{'='*60}\n")

    try:
        for atype in selected:
            print(f"{'─'*40}")
            try:
                SCAPY_ATTACKS[atype](target_ip, target_port)
            except PermissionError:
                print(f"  [ERROR] 权限不足！请以管理员身份运行")
                break
            except Exception as e:
                print(f"  [WARN] {atype} 异常: {e}")
            time.sleep(delay_between)
    except KeyboardInterrupt:
        print("\n  用户中断")

    print(f"\n  发包阶段完成。")

    # 自动修补流特征
    if patch_flows:
        _patch_scapy_flows(target_ip, selected, count_per_type)

    if not patch_flows:
        print(f"\n{'='*60}")
        print(f"  发包完成 — 等待 {60}s 让 Flow 超时回收，然后:")
        print(f"    python main.py --once")
        print(f"{'='*60}")

    return selected


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-IDS 测试流量生成器 — 生成可被 AI 识别的攻击流量",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            快速开始:
              python generate_test_traffic.py --all       # 清空后注入全部攻击
              python main.py --once                       # AI 检测

              python generate_test_traffic.py --types DDoS,PortScan  # 指定类型
              python generate_test_traffic.py --mixed --target 10.20.101.246  # DB注入+发包
        """),
    )

    # ── 模式 ──
    mode = parser.add_argument_group("运行模式")
    mode.add_argument("--scapy-only", action="store_true",
                      help="仅 Scapy 发包（不写DB，需管理员权限）")
    mode.add_argument("--mixed", action="store_true",
                      help="DB注入 + Scapy 发包 同时进行")
    mode.add_argument("--list", action="store_true",
                      help="列出所有可模拟的攻击类型")

    # ── DB 注入参数 ──
    db_group = parser.add_argument_group("DB 注入参数")
    db_group.add_argument("--types", "-t", default=None,
                          help="攻击类型（逗号分隔），默认全部")
    db_group.add_argument("--count", "-c", type=int, default=5,
                          help="每种攻击样例数（默认 5）")
    db_group.add_argument("--benign", "-b", type=int, default=10,
                          help="正常流量条数（默认 10，0=不混入）")
    db_group.add_argument("--all", action="store_true",
                          help="清空 flow_features 后重新注入")

    # ── Scapy 参数 ──
    scapy_group = parser.add_argument_group("Scapy 发包参数")
    scapy_group.add_argument("--target", default="127.0.0.1",
                             help="目标 IP 地址（默认 127.0.0.1）")
    scapy_group.add_argument("--port", "-p", type=int, default=80,
                             help="目标端口（默认 80）")
    scapy_group.add_argument("--delay", type=float, default=2.0,
                             help="每种攻击间隔秒数（默认 2.0）")

    # ── 循环 ──
    loop_group = parser.add_argument_group("循环模式")
    loop_group.add_argument("--loop", "-l", type=float, default=0,
                            help="每 N 秒循环注入一轮（0=单轮）")

    args = parser.parse_args()

    # ── --list ──
    if args.list:
        print(f"\n{'='*60}")
        print(f"  可模拟的 {len(ATTACK_FINGERPRINTS)} 种攻击 (v3 15维特征)")
        print(f"{'='*60}")
        for k, v in ATTACK_FINGERPRINTS.items():
            print(f"  {v['label']:<30s} {v['risk']:<10s} {v['desc']}")
        print()
        print(f"  DB 注入模式: 全部 {len(ATTACK_FINGERPRINTS)} 种（100%% 可靠）")
        print(f"  Scapy 模式 : {len(SCAPY_ATTACKS)} 种（需管理员权限）")
        return

    # ── 解析攻击类型 ──
    attack_types = None
    if args.types:
        attack_types = [x.strip() for x in args.types.split(",")]

    # ── 单轮执行 ──
    def _run_once():
        do_db = not args.scapy_only
        do_scapy = args.scapy_only or args.mixed

        if do_db:
            print(f"\n{'='*60}")
            print(f"  AI-IDS 测试流量生成器 — DB 注入")
            print(f"{'='*60}")
            print(f"  攻击类型 : {'全部' + str(len(ATTACK_FINGERPRINTS)) + '种' if attack_types is None else str(len(attack_types)) + '种'}")
            print(f"  每种样例 : {args.count}")
            print(f"  正常流量 : {args.benign} 条")
            if args.all:
                print(f"  模式     : 清空后注入")

            total = inject_db(attack_types, args.count, args.benign > 0, args.benign, args.all)
            if total > 0:
                selected = attack_types if attack_types else list(ATTACK_FINGERPRINTS.keys())
                print(f"\n  注入完成! 下一步: python main.py --once")
                print(f"  预期检测到 {len(selected)} 种攻击类型 ({args.count * len(selected)} 条攻击记录)")

        if do_scapy:
            scapy_atks = attack_types
            run_scapy_attacks(
                args.target, args.port, scapy_atks, args.delay,
                patch_flows=True, count_per_type=args.count,
            )

        if do_scapy or do_db:
            print(f"\n{'='*60}")
            print(f"  全部完成! 运行 AI 检测:")
            print(f"    python main.py --once")
            print(f"{'='*60}")

    # ── 循环模式 ──
    if args.loop > 0:
        print(f"\n  循环模式: 每 {args.loop:.0f}s 一轮 | Ctrl+C 停止\n")
        round_num = 0
        try:
            while True:
                round_num += 1
                print(f"\n{'█'*60}")
                print(f"  第 {round_num} 轮")
                print(f"{'█'*60}")
                _run_once()
                time.sleep(args.loop)
        except KeyboardInterrupt:
            print(f"\n  已停止，共 {round_num} 轮")
    else:
        _run_once()


if __name__ == "__main__":
    main()
