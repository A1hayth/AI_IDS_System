# coding=utf-8
"""
AI-IDS 流量主动研判引擎 (v2 — 优化版)

改进点:
    - 优先加载 joblib 格式模型（兼容性更好）
    - 统一使用 config.py 的 MODEL_FEATURE_COLUMNS 做特征对齐
    - 加载 feature_names.json 校验特征一致性
    - 标准化器 feature_names_in_ 确保与训练时完全一致
    - 预测时自动对齐列名，消除 Scaling 警告
"""
import os
import sys
import json
import warnings
import numpy as np
import pandas as pd

# 静默 sklearn 版本差异警告
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# 注入路径
_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from config import (
    MODELS_DIR, MODEL_FEATURE_COLUMNS, DB_FEATURE_COLUMNS,
    MODEL_TO_DB_COLUMN_MAP,
    MIN_CONFIDENCE_THRESHOLD, BENIGN_LABELS,
    PROTOCOL_MAP,
)


class Detector:
    """AI-IDS 流量主动研判引擎。

    自动检测并载入标准化器 + XGBoost 分类器 + 标签编码器。
    优先使用 joblib 格式，回退到 pkl 格式。
    """

    def __init__(self, models_dir=None):
        self.scaler = None
        self.model = None
        self.label_encoder = None
        self._feature_columns = MODEL_FEATURE_COLUMNS
        self._loaded_from = None

        # 搜索路径（优先级: joblib > pkl）
        search_dirs = [models_dir] if models_dir else []
        search_dirs += [
            MODELS_DIR,
            os.path.join(os.path.dirname(__file__), '..', '..', 'models'),
            'models',
        ]

        loaded = False
        for path in search_dirs:
            if not os.path.isdir(path):
                continue

            # 优先尝试 joblib
            if self._try_load_joblib(path):
                loaded = True
                break
            # 回退到 pkl
            if self._try_load_pkl(path):
                loaded = True
                break

        if not loaded:
            print("[AI CORE] 未能在任何路径找到模型资产，将启用启发式降级检测规则。")
        else:
            print(f"[AI CORE] 模型加载成功: {self._loaded_from}")

    # ==================================================================
    # 模型加载
    # ==================================================================

    def _try_load_joblib(self, path):
        """尝试加载 joblib 格式模型。"""
        try:
            import joblib
            scaler_path = os.path.join(path, 'scaler.joblib')
            model_path = os.path.join(path, 'xgboost_model.joblib')
            encoder_path = os.path.join(path, 'label_encoder.joblib')

            if not all(os.path.exists(p) for p in [scaler_path, model_path, encoder_path]):
                return False

            self.scaler = joblib.load(scaler_path)
            self.model = joblib.load(model_path)
            self.label_encoder = joblib.load(encoder_path)
            self._loaded_from = f"{path} (joblib)"
            self._verify_feature_names(path)
            return True
        except Exception as e:
            print(f"  joblib 加载失败 ({path}): {e}")
            return False

    def _try_load_pkl(self, path):
        """回退方案：加载 pickle 格式模型。"""
        try:
            import pickle
            scaler_path = os.path.join(path, 'scaler.pkl')
            model_path = os.path.join(path, 'xgboost_model.pkl')
            encoder_path = os.path.join(path, 'label_encoder.pkl')

            if not all(os.path.exists(p) for p in [scaler_path, model_path, encoder_path]):
                return False

            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            with open(encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
            self._loaded_from = f"{path} (pkl)"
            self._verify_feature_names(path)
            return True
        except Exception as e:
            print(f"  pkl 加载失败 ({path}): {e}")
            return False

    def _verify_feature_names(self, path):
        """校验特征列名一致性。"""
        # 1. 检查 feature_names.json
        meta_path = os.path.join(path, 'feature_names.json')
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                saved_features = meta.get('model_feature_columns', [])
                if saved_features and saved_features != self._feature_columns:
                    print(f"  feature_names.json 特征列名更新: {saved_features}")
                    self._feature_columns = saved_features
            except Exception:
                pass

        # 2. 确保 scaler 有 feature_names_in_
        if self.scaler is not None:
            if not hasattr(self.scaler, 'feature_names_in_') or self.scaler.feature_names_in_ is None:
                self.scaler.feature_names_in_ = np.array(self._feature_columns)
                print(f"  已补充 scaler.feature_names_in_: {self._feature_columns}")

    # ==================================================================
    # 特征预处理（核心：列名对齐）
    # ==================================================================

    def _prepare_features(self, raw_features):
        """特征 DataFrame 构建 + 列名对齐 + 标准化。

        彻底解决 'X does not have valid feature names' 警告：
        - 统一使用 self._feature_columns 作为 DataFrame 列名
        - 确保与训练时的 scaler.feature_names_in_ 完全一致
        """
        feature_cols = list(self._feature_columns)

        if isinstance(raw_features, np.ndarray):
            if raw_features.ndim == 1:
                raw_features = raw_features.reshape(1, -1)
            raw_features = pd.DataFrame(raw_features, columns=feature_cols, dtype=np.float64)

        elif isinstance(raw_features, list):
            if not isinstance(raw_features[0], list):
                raw_features = [raw_features]
            raw_features = pd.DataFrame(raw_features, columns=feature_cols, dtype=np.float64)

        elif isinstance(raw_features, pd.DataFrame):
            # 重命名列以对齐（兼容 Mixed_Case 和 lowercase 输入）
            rename_map = {}
            for col in raw_features.columns:
                if col in MODEL_TO_DB_COLUMN_MAP:
                    rename_map[col] = MODEL_TO_DB_COLUMN_MAP[col]
            if rename_map:
                raw_features = raw_features.rename(columns=rename_map)
            # 确保列顺序
            available = [c for c in feature_cols if c in raw_features.columns]
            raw_features = raw_features[available]

        # 标准化
        if self.scaler:
            return self.scaler.transform(raw_features)
        return raw_features.values if isinstance(raw_features, pd.DataFrame) else raw_features

    # ==================================================================
    # 预测接口
    # ==================================================================

    def predict(self, raw_features):
        """推理并返回 (attack_type, confidence)。

        始终返回二元组。
        """
        # 兜底：模型未加载时使用启发式规则
        if self.model is None or self.scaler is None or self.label_encoder is None:
            return self._heuristic_predict(raw_features)

        try:
            scaled = self._prepare_features(raw_features)
            pred_idx = self.model.predict(scaled)
            attack_type = self.label_encoder.inverse_transform(pred_idx)[0]

            # 置信度
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(scaled)[0]
                confidence = float(np.max(proba))
            else:
                confidence = 1.0

            # 标签归一化
            if str(attack_type).strip().lower() in {"benign", "benign"}:
                attack_type = "Normal"

            return str(attack_type), confidence

        except Exception as e:
            print(f"[AI CORE ERROR] 预测失败: {e}")
            return "Normal", 0.50

    def predict_proba(self, raw_features):
        """返回原始概率矩阵。"""
        if self.model is None or not hasattr(self.model, "predict_proba"):
            return np.array([[1.0, 0.0]])
        try:
            scaled = self._prepare_features(raw_features)
            return self.model.predict_proba(scaled)
        except Exception as e:
            print(f"[AI CORE ERROR] predict_proba 失败: {e}")
            return np.array([[1.0, 0.0]])

    def predict_with_details(self, raw_features):
        """增强预测：返回 (attack_type, confidence, top3_candidates)。

        top3_candidates: [(label, prob), ...]  用于前端展示备选判定。
        """
        attack_type, confidence = self.predict(raw_features)

        top3 = []
        if self.model is not None and hasattr(self.model, "predict_proba"):
            try:
                scaled = self._prepare_features(raw_features)
                proba = self.model.predict_proba(scaled)[0]
                top_indices = np.argsort(proba)[-3:][::-1]
                top3 = [
                    (str(self.label_encoder.inverse_transform([i])[0]), float(proba[i]))
                    for i in top_indices
                ]
            except Exception:
                top3 = [(attack_type, confidence)]

        is_low_confidence = confidence < MIN_CONFIDENCE_THRESHOLD
        return attack_type, confidence, top3, is_low_confidence

    # ==================================================================
    # 启发式降级规则（模型未加载时使用）
    # ==================================================================

    def _heuristic_predict(self, raw_features):
        """基于规则的启发式检测（模型未加载时的降级方案，v3: 15 维）。"""
        # 提取特征值（兼容 DataFrame / array 输入）
        if isinstance(raw_features, pd.DataFrame):
            row = raw_features.iloc[0]
            proto = int(row.get('protocol', row.get('Protocol', 6)))
            flow_dur = float(row.get('flow_duration', row.get('Flow_Duration', 0)))
            fwd_pkts = int(row.get('total_fwd_packets', row.get('Total_Fwd_Packets', 0)))
            bwd_pkts = int(row.get('total_backward_packets', row.get('Total_Backward_Packets', 0)))
            fwd_max = float(row.get('fwd_packet_length_max', row.get('Fwd_Packet_Length_Max', 0)))
            bwd_max = float(row.get('bwd_packet_length_max', row.get('Bwd_Packet_Length_Max', 0)))
            # v3 新增特征
            bytes_ps = float(row.get('flow_bytes_per_sec', row.get('Flow_Bytes_Per_Sec', 0)))
            syn_cnt = int(row.get('syn_flag_count', row.get('SYN_Flag_Count', 0)))
            rst_cnt = int(row.get('rst_flag_count', row.get('RST_Flag_Count', 0)))
            fwd_iat = float(row.get('fwd_iat_mean', row.get('Fwd_IAT_Mean', 0)))
        else:
            flat = np.array(raw_features).flatten()
            proto, flow_dur, fwd_pkts, bwd_pkts, fwd_max, bwd_max = (
                flat[0], flat[1], flat[2], flat[3], flat[4], flat[5]
            )
            # v3 新增特征（索引 6-14）
            fwd_mean = flat[6] if len(flat) > 6 else 0
            bwd_mean = flat[7] if len(flat) > 7 else 0
            bytes_ps = flat[8] if len(flat) > 8 else 0
            pkts_ps = flat[9] if len(flat) > 9 else 0
            fwd_iat = flat[10] if len(flat) > 10 else 0
            bwd_iat = flat[11] if len(flat) > 11 else 0
            syn_cnt = int(flat[12]) if len(flat) > 12 else 0
            fin_cnt = int(flat[13]) if len(flat) > 13 else 0
            rst_cnt = int(flat[14]) if len(flat) > 14 else 0

        # 基于扩展特征的启发式规则
        if flow_dur > 10000000 and fwd_pkts > 500 and fwd_max > 1200:
            return "DoS Hulk", 0.95
        elif flow_dur > 5000000 and fwd_pkts < 10 and bwd_max == 0 and proto == 6:
            return "DoS slowloris", 0.92
        elif fwd_pkts > 1000 and bwd_max > 500 and bytes_ps > 100000:
            return "DDoS", 0.97
        elif flow_dur < 500 and fwd_pkts < 3 and fwd_max == 0 and proto == 6:
            return "PortScan", 0.88
        elif syn_cnt > 100 and rst_cnt > 10:
            return "PortScan", 0.85
        elif fwd_iat < 0.001 and fwd_pkts > 100:
            return "DoS Hulk", 0.90
        else:
            return "Normal", 0.99
