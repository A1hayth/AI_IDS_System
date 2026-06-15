# -*- coding: utf-8 -*-
"""
AI-IDS 持续检测服务 — PipelineService

数据流:
    traffic_monitor.py  ──写入──▶  flow_features (ai_processed=0)
                                        │
    run_pipeline.py  ──每60秒轮询──▶  WHERE ai_processed = 0
                                        │
                                   XGBoost Detector
                                        │
                                   predict_proba() → (attack_type, confidence)
                                        │
                                        ▼
                                  traffic_logs (1:1 via flow_id)
                                        │
                                        ▼
                               UPDATE ai_processed = 1, predict_time = NOW()

用法:
    python run_pipeline.py                 # 持续运行，每 60 秒检测一次
    python run_pipeline.py --once          # 单次检测，检测完立即退出
    python run_pipeline.py --interval 30   # 自定义轮询间隔（秒）
    python run_pipeline.py --all           # 重置所有 ai_processed=0，全量重新检测后进入持续模式
"""

import os
import sys
import argparse
import datetime
import logging
import threading
import time
import traceback

import pymysql

# ============================================================================
# Windows GBK 编码兼容
# ============================================================================
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ============================================================================
# 路径 & 导入
# ============================================================================
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_THIS_DIR)
_PROJECT_DIR = os.path.dirname(_SRC_DIR)
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from src.ai_engine.predictor import Detector

# ============================================================================
# 数据库配置（与 web/backend/config.py、traffic_monitor.py 保持一致）
# ============================================================================
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "AIIDS",
    "password": "123456",
    "database": "ai_ids_system",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": False,
    "connect_timeout": 10,
    "read_timeout": 30,
    "write_timeout": 30,
}

# ============================================================================
# 6 个模型特征（必须与 preprocess.py SELECTED_FEATURES 严格对齐）
# ============================================================================
FEATURE_COLUMNS = [
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "fwd_packet_length_max",
    "bwd_packet_length_max",
]

# ============================================================================
# 日志系统
# ============================================================================
LOG_DIR = os.path.join(_PROJECT_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "run_pipeline.log")


def _setup_logging() -> logging.Logger:
    """配置 PipelineService 专用日志器（文件 + 控制台）。"""
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("pipeline_service")
    logger.setLevel(logging.DEBUG)

    # 防止重复添加 handler
    if logger.handlers:
        return logger

    # 文件 handler —— 记录所有级别
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # 控制台 handler —— INFO 及以上
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(ch)

    return logger


# ============================================================================
# 威胁等级映射（含 CRITICAL）
# ============================================================================

def calculate_risk(attack_type: str) -> str:
    """根据攻击类型映射威胁等级 — 返回 CRITICAL / HIGH / MEDIUM / LOW。"""
    critical = {"DDoS", "DoS Hulk", "DoS slowloris", "DoS GoldenEye",
                "DoS Slowhttptest", "Heartbleed", "Infiltration"}
    high = {"Web Attack", "Web Attack - Brute Force", "Web Attack - XSS",
            "Web Attack - Sql Injection", "SQL Injection", "Brute Force"}
    medium = {"PortScan", "Bot", "FTP-Patator", "SSH-Patator"}

    if attack_type in ("Benign", "Normal"):
        return "LOW"
    if attack_type in critical:
        return "CRITICAL"
    if attack_type in high:
        return "HIGH"
    if attack_type in medium:
        return "MEDIUM"
    # 未知攻击类型默认 MEDIUM
    return "MEDIUM"


# 兼容旧接口
def calculate_severity(attack_type: str) -> str:
    return calculate_risk(attack_type)


# ============================================================================
# AI 判定理由生成
# ============================================================================

def generate_ai_reason(features: list, attack_type: str) -> str:
    """
    根据 6 维特征值自动生成中文 AI 判定理由。
    features: [protocol, flow_duration, total_fwd, total_bwd, fwd_max, bwd_max]
    """
    proto_map = {6: "TCP", 17: "UDP"}
    proto = proto_map.get(int(features[0]), f"Protocol({features[0]})")
    duration = float(features[1])
    fwd_pkts = int(features[2])
    bwd_pkts = int(features[3])
    fwd_len_max = int(features[4])
    total_pkts = fwd_pkts + bwd_pkts

    if attack_type in ("Benign", "Normal"):
        return (f"流量特征均衡，协议 {proto}，前向/反向报文比 {fwd_pkts}/{bwd_pkts}，"
                f"流持续时间 {duration:.2f}μs，判定为常规无害会话。")
    elif attack_type == "DoS Hulk":
        return (f"检测到瞬时高并发前向载荷。前向报文最大长度 {fwd_len_max}B，"
                f"前向总报文数 ({fwd_pkts}) 异常偏高，与 HTTP Hulk DoS 特征强吻合。")
    elif attack_type == "DoS slowloris":
        return (f"流持续时间极长 ({duration:.1f}μs)，而报文总数极低 (仅 {total_pkts} 个包)，"
                f"涉嫌利用 Slowloris 耗尽服务器线程池。")
    elif attack_type == "DDoS":
        return (f"检测到高密度不对称流量突发。前/反向报文比例严重失衡，"
                f"前向包数 {fwd_pkts}，判定为协同分布式拒绝服务攻击。")
    elif attack_type == "PortScan":
        return (f"流生存期极短 ({duration:.2f}μs) 且前向最大报文无应用负载 (Fwd Max=0)，"
                f"识别为快速 SYN 静默扫描探测。")
    elif attack_type == "Bot":
        return (f"通信模式展现僵尸网络(Botnet)控端与受控主机的低频心跳特征，"
                f"已标记为可疑僵尸会话。")
    elif "Web Attack" in attack_type or "SQL" in attack_type or "Brute" in attack_type:
        return (f"检测到 Web 应用层攻击特征，协议 {proto}，前向报文最大长度 {fwd_len_max}B，"
                f"分类为 [{attack_type}]。")
    else:
        return (f"异常流量命中特征偏移，协议 {proto}，前/反向发包比 {fwd_pkts}/{bwd_pkts}，"
                f"判定攻击分类为 [{attack_type}]。")


# ============================================================================
# PipelineService — 持续运行的 AI 检测服务
# ============================================================================

class PipelineService:
    """AI-IDS 持续检测服务。

    职责:
        1. 每 N 秒轮询 flow_features 中 ai_processed=0 的新行
        2. 调用 XGBoost Detector.predict_proba() 进行推理
        3. 将判定结果写入 traffic_logs（1:1 映射 via flow_id）
        4. 更新 flow_features 的 ai_processed=1, predict_time=当前时间
        5. 全流程异常捕获，绝不崩溃退出

    使用方式::

        service = PipelineService(poll_interval=60)
        service.start()   # 持续运行
        service.stop()    # 优雅退出
    """

    BANNER: str = (
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║         AI-IDS  智能检测服务  Pipeline Service              ║\n"
        "║         flow_features  →  XGBoost  →  traffic_logs         ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )

    SEPARATOR: str = "=" * 60

    def __init__(self, poll_interval: float = 60.0) -> None:
        self._poll_interval: float = max(1.0, poll_interval)
        self._logger: logging.Logger = _setup_logging()
        self._detector: Detector | None = None
        self._running: bool = False
        self._stop_event: threading.Event = threading.Event()
        self._start_time: float = 0.0
        self._total_analyzed: int = 0
        self._total_attacks: int = 0

    # ==================================================================
    # 数据库连接
    # ==================================================================

    def _get_connection(self) -> pymysql.Connection | None:
        """建立数据库连接（带重试）。失败返回 None。"""
        for attempt in range(1, 4):
            try:
                conn = pymysql.connect(**DB_CONFIG)
                if conn.open:
                    return conn
            except pymysql.Error as e:
                self._logger.warning(
                    "数据库连接失败 (attempt %d/3): %s", attempt, e
                )
                if attempt < 3:
                    time.sleep(2)
        self._logger.error("数据库连接最终失败")
        return None

    # ==================================================================
    # 初始化 — 检查并补充数据库结构
    # ==================================================================

    def ensure_db_structure(self) -> bool:
        """检查并补充 flow_features 表结构（幂等操作）。

        补充字段:
            - ai_processed INT DEFAULT 0   —— 是否已被 AI 分析
            - predict_time DATETIME NULL    —— AI 分析时间

        Returns:
            True 结构就绪，False 失败。
        """
        conn = self._get_connection()
        if not conn:
            return False

        try:
            cur = conn.cursor()

            # 1. 补充 ai_processed 字段
            cur.execute("DESCRIBE flow_features")
            columns = {row["Field"] for row in cur.fetchall()}

            if "ai_processed" not in columns:
                cur.execute(
                    "ALTER TABLE flow_features "
                    "ADD COLUMN ai_processed INT DEFAULT 0 "
                    "COMMENT 'AI analysis status: 0=pending, 1=done'"
                )
                conn.commit()
                self._logger.info("已补充字段 flow_features.ai_processed")

            if "predict_time" not in columns:
                cur.execute(
                    "ALTER TABLE flow_features "
                    "ADD COLUMN predict_time DATETIME NULL "
                    "COMMENT 'AI prediction timestamp' "
                    "AFTER ai_processed"
                )
                conn.commit()
                self._logger.info("已补充字段 flow_features.predict_time")

            # 2. 检查 traffic_logs.flow_id 字段
            cur.execute("DESCRIBE traffic_logs")
            tl_columns = {row["Field"] for row in cur.fetchall()}

            if "flow_id" not in tl_columns:
                cur.execute(
                    "ALTER TABLE traffic_logs "
                    "ADD COLUMN flow_id BIGINT NULL "
                    "COMMENT 'source flow_features.id' "
                    "AFTER id"
                )
                conn.commit()
                self._logger.info("已补充字段 traffic_logs.flow_id")

            cur.close()
            self._logger.info("数据库结构检查完成，所有字段就绪")
            return True

        except pymysql.Error as e:
            self._logger.error("数据库结构检查失败: %s", e)
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ==================================================================
    # 加载 AI 模型
    # ==================================================================

    def _load_model(self) -> bool:
        """加载 XGBoost 检测模型。"""
        try:
            self._detector = Detector()
            self._logger.info("AI 检测模型加载成功")
            return True
        except Exception as e:
            self._logger.error("AI 模型加载失败: %s", e)
            return False

    # ==================================================================
    # analyze_once — 单次检测
    # ==================================================================

    def analyze_once(self) -> int:
        """执行一次完整的检测周期。

        流程:
            1. 读取 flow_features 中 ai_processed=0 的行
            2. 逐行调用 AI 模型预测
            3. 写入 traffic_logs
            4. 更新 flow_features.ai_processed=1, predict_time=NOW()

        Returns:
            本次实际分析并写入的行数（-1 表示数据库/模型不可用）。
        """
        if self._detector is None:
            self._logger.error("AI 检测器未初始化，无法执行分析")
            return -1

        conn = self._get_connection()
        if not conn:
            self._logger.error("分析周期跳过——数据库不可用")
            return -1

        rows: list[dict] = []
        new_count = 0
        attack_count = 0
        insert_rows: list[tuple] = []
        processed_ids: list[int] = []

        try:
            cur = conn.cursor()

            # ── 步骤 1: 读取未分析的流量 ──────────────────────────
            cur.execute(
                "SELECT * FROM flow_features "
                "WHERE ai_processed = 0 "
                "ORDER BY id ASC "
                "LIMIT 500"
            )
            rows = cur.fetchall()
            cur.close()

            if not rows:
                return 0

            self._logger.info("发现未分析流量: %d 条", len(rows))

            # ── 步骤 2 & 3: AI 推理 + 组装写入数据 ─────────────────
            for row in rows:
                row_id = row["id"]

                # 提取 6 维特征向量
                try:
                    feature_vector = [row[col] for col in FEATURE_COLUMNS]
                except KeyError as e:
                    self._logger.warning(
                        "Flow ID=%d 缺少特征列 %s，跳过", row_id, e
                    )
                    continue

                # AI 预测（含置信度）
                try:
                    attack_type, confidence = self._detector.predict_proba(
                        feature_vector
                    )
                except Exception as e:
                    self._logger.error(
                        "Flow ID=%d 模型预测失败: %s", row_id, e
                    )
                    continue

                # 清洗标签
                if str(attack_type).upper() in ("BENIGN", "NORMAL"):
                    is_attack = 0
                    clean_type = "Normal"
                else:
                    is_attack = 1
                    clean_type = str(attack_type)

                # 映射字段
                timestamp = row.get("create_time") or datetime.datetime.now()
                client_ip = row.get("target_ip") or "0.0.0.0"
                risk = calculate_risk(clean_type)
                ai_reason = generate_ai_reason(feature_vector, clean_type)

                # 输出到控制台
                self._print_flow_result(row_id, clean_type, confidence, risk)

                insert_rows.append((
                    timestamp, client_ip, is_attack, clean_type, risk,
                    ai_reason, row_id,
                ))
                processed_ids.append(row_id)

                new_count += 1
                if is_attack:
                    attack_count += 1

            # ── 步骤 4: 写入 traffic_logs ──────────────────────────
            if insert_rows:
                cur = conn.cursor()

                # 先查询已存在的 flow_id，过滤掉避免 UNIQUE 冲突
                all_fids = [r[6] for r in insert_rows]  # flow_id is 7th element (index 6)
                placeholders = ",".join(["%s"] * len(all_fids))
                cur.execute(
                    f"SELECT flow_id FROM traffic_logs WHERE flow_id IN ({placeholders})",
                    all_fids,
                )
                existing_fids = {row["flow_id"] for row in cur.fetchall()}

                # 仅插入新的 flow_id
                new_rows = [
                    r for r in insert_rows if r[6] not in existing_fids
                ]
                skipped_dup = len(insert_rows) - len(new_rows)

                if new_rows:
                    insert_sql = (
                        "INSERT INTO traffic_logs "
                        "(timestamp, client_ip, is_attack, attack_type, severity, "
                        "ai_reason, flow_id) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    )
                    cur.executemany(insert_sql, new_rows)
                    self._logger.info("已写入 traffic_logs: %d 条", len(new_rows))

                if skipped_dup > 0:
                    self._logger.info(
                        "跳过重复 flow_id: %d 条（已在 traffic_logs 中存在）",
                        skipped_dup,
                    )

                # ── 步骤 5: 更新 ai_processed 标记 ────────────────
                # 分批更新（每批 50 个 ID）
                batch_size = 50
                for i in range(0, len(processed_ids), batch_size):
                    batch = processed_ids[i:i + batch_size]
                    placeholders = ",".join(["%s"] * len(batch))
                    cur.execute(
                        f"UPDATE flow_features "
                        f"SET ai_processed = 1, predict_time = CURRENT_TIMESTAMP "
                        f"WHERE id IN ({placeholders})",
                        batch,
                    )
                conn.commit()
                cur.close()
                self._logger.info(
                    "已更新 ai_processed=1: %d 条", len(processed_ids)
                )

            # ── 累计统计 ─────────────────────────────────────────
            self._total_analyzed += new_count
            self._total_attacks += attack_count

            return new_count

        except pymysql.err.OperationalError as e:
            self._logger.error("数据库操作异常: %s", e)
            try:
                conn.rollback()
            except Exception:
                pass
            return -1
        except Exception as e:
            self._logger.error("分析周期异常: %s\n%s", e, traceback.format_exc())
            try:
                conn.rollback()
            except Exception:
                pass
            return -1
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ==================================================================
    # 控制台输出
    # ==================================================================

    @staticmethod
    def _print_flow_result(
        flow_id: int, prediction: str, confidence: float, risk: str
    ) -> None:
        """打印单条流量判定结果到控制台。"""
        print(f"\nFlow ID: {flow_id}")
        print(f"Prediction: {prediction}")
        print(f"Confidence: {confidence:.4f}")
        print(f"Risk: {risk}")

    # ==================================================================
    # run_forever — 持续运行循环
    # ==================================================================

    def run_forever(self) -> None:
        """持续运行检测循环（阻塞，直到 stop() 被调用）。

        每 self._poll_interval 秒执行一次 analyze_once()。
        """
        self._running = True
        self._start_time = time.time()

        self._logger.info("检测循环已启动，间隔 = %d 秒", self._poll_interval)

        while self._running and not self._stop_event.is_set():
            loop_start = time.time()

            try:
                analyzed = self.analyze_once()

                if analyzed > 0:
                    self._logger.info(
                        "本轮检测完成 | 新增 %d 条 | "
                        "累计 %d 条 (其中攻击 %d 条)",
                        analyzed, self._total_analyzed, self._total_attacks,
                    )
                elif analyzed == 0:
                    self._logger.debug("未发现新流量，等待下一轮...")

            except Exception:
                self._logger.exception(
                    "run_forever 迭代异常（已恢复继续运行）"
                )

            # 计算剩余等待时间
            elapsed = time.time() - loop_start
            wait_time = max(0.0, self._poll_interval - elapsed)

            if wait_time > 0 and self._running:
                self._stop_event.wait(wait_time)

        self._logger.info("检测循环已退出")

    # ==================================================================
    # 公共 API
    # ==================================================================

    def start(self) -> None:
        """启动持续检测服务（阻塞运行）。

        完整流程:
            1. 初始化日志系统
            2. 检查数据库结构并补充缺失字段
            3. 加载 AI 检测模型
            4. 打印启动横幅
            5. 进入 run_forever() 持续循环
        """
        self._logger.info("=" * 60)
        self._logger.info("AI Detection Service 启动中...")
        self._logger.info("=" * 60)

        # 1. 数据库结构检查
        self._logger.info("正在检查数据库结构...")
        if not self.ensure_db_structure():
            print("[FATAL] 数据库结构初始化失败，退出")
            return

        # 2. 加载模型
        self._logger.info("正在加载 AI 检测模型...")
        if not self._load_model():
            print("[FATAL] AI 模型加载失败，退出")
            return

        # 3. 打印横幅
        self._print_banner()

        # 4. 进入持续循环
        try:
            self.run_forever()
        except KeyboardInterrupt:
            print("\n收到中断信号 (Ctrl+C)，正在优雅退出...")
        finally:
            self._shutdown()

    def stop(self) -> None:
        """停止检测服务（可从其他线程调用）。"""
        self._logger.info("收到停止请求")
        self._running = False
        self._stop_event.set()

    # ==================================================================
    # 内部方法
    # ==================================================================

    def _print_banner(self) -> None:
        """打印启动横幅。"""
        print(self.BANNER)
        print()
        print(f"  轮询间隔: {self._poll_interval:.0f} 秒")
        print(f"  日志文件: {LOG_FILE}")
        print(f"  数据库  : {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
        print()
        print(self.SEPARATOR)

    def _shutdown(self) -> None:
        """优雅关闭。"""
        self._logger.info("正在关闭 AI Detection Service...")
        self._running = False

        # 最后一次分析
        try:
            self._logger.info("执行最后一次检测...")
            analyzed = self.analyze_once()
            if analyzed > 0:
                self._logger.info("最终检测完成: %d 条", analyzed)
        except Exception as e:
            self._logger.warning("最终检测异常: %s", e)

        # 打印汇总
        total_time = time.time() - self._start_time if self._start_time > 0 else 0
        hours, rem = divmod(int(total_time), 3600)
        minutes, seconds = divmod(rem, 60)

        print()
        print(self.SEPARATOR)
        print("  运行摘要")
        print(self.SEPARATOR)
        print(f"  运行时长  : {hours:02d}:{minutes:02d}:{seconds:02d}")
        print(f"  累计分析  : {self._total_analyzed} 条")
        print(f"  检测攻击  : {self._total_attacks} 条")
        print(f"  日志文件  : {LOG_FILE}")
        print(self.SEPARATOR)

        self._logger.info(
            "AI Detection Service 已停止 — 累计分析=%d 攻击=%d 运行时长=%s",
            self._total_analyzed, self._total_attacks,
            f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        )


# ============================================================================
# main 入口
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-IDS 持续检测服务 — 从 flow_features 读取特征、调用 AI 推理、写入 traffic_logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python run_pipeline.py                    持续运行，每 60 秒检测一次\n"
            "  python run_pipeline.py --once             单次检测，检测完立即退出\n"
            "  python run_pipeline.py --interval 30      每 30 秒检测一次\n"
            "  python run_pipeline.py --all              重置所有 ai_processed=0 后全量检测\n"
        ),
    )
    parser.add_argument(
        "--once", action="store_true",
        help="仅执行一次检测，然后退出（不进入持续循环）",
    )
    parser.add_argument(
        "--interval", "-i", type=float, default=60.0,
        help="轮询间隔（秒），默认 60",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="重置所有 flow_features.ai_processed=0，全量重新检测",
    )
    args = parser.parse_args()

    # ── 创建服务实例 ──────────────────────────────────────────
    service = PipelineService(poll_interval=args.interval)

    # ── 数据库结构检查 ───────────────────────────────────────
    if not service.ensure_db_structure():
        print("[FATAL] 数据库初始化失败，退出")
        sys.exit(1)

    # ── 加载模型 ─────────────────────────────────────────────
    if not service._load_model():
        print("[FATAL] AI 模型加载失败，退出")
        sys.exit(1)

    # ── 如有 --all 参数，重置所有 ai_processed ───────────────
    if args.all:
        conn = service._get_connection()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE flow_features SET ai_processed = 0, predict_time = NULL"
                )
                conn.commit()
                affected = cur.rowcount
                cur.close()
                service._logger.info(
                    "已重置 %d 条记录的 ai_processed=0，将全量重新检测", affected
                )
                print(f"\n已重置 {affected} 条记录，将全量重新检测\n")
            except pymysql.Error as e:
                service._logger.error("重置 ai_processed 失败: %s", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    # ── 打印横幅 ─────────────────────────────────────────────
    service._print_banner()

    # ── 单次模式 ─────────────────────────────────────────────
    if args.once:
        service._logger.info("单次检测模式")
        print(f"\n{service.SEPARATOR}")
        analyzed = service.analyze_once()
        if analyzed > 0:
            print(f"\n已写入 traffic_logs")
            print(f"已更新 ai_processed=1")
        elif analyzed == 0:
            print("未发现未分析流量")
        else:
            print("检测失败，请查看日志")
        print(f"{service.SEPARATOR}\n")
        return

    # ── 持续运行模式 ─────────────────────────────────────────
    try:
        service.run_forever()
    except KeyboardInterrupt:
        print("\n收到中断信号 (Ctrl+C)，正在优雅退出...")
    finally:
        service._shutdown()


if __name__ == "__main__":
    main()
