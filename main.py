# -*- coding: utf-8 -*-
"""
AI-IDS 一体化启动入口 —— 一键启动流量监控 + AI 检测

系统架构:

    main.py
      ├── 线程1: TrafficMonitor  (持续抓包 → 解析 → 写入 flow_features)
      └── 线程2: PipelineService (每 N 秒轮询 ai_processed=0 → AI 推理 → traffic_logs)

完整数据流:

    网络流量 ──Scapy──▶ capture.py ──▶ parser.py ──▶ feature_extractor.py
                                                          │
                                                   flow_features (MySQL)
                                                   (ai_processed=0)
                                                          │
                                              run_pipeline.py (每 60s)
                                                   XGBoost Detector
                                                          │
                                                     traffic_logs
                                                   (ai_processed=1)

用法:
    python main.py                                          # 启动全部服务
    python main.py --target www.baidu.com                   # 指定监控目标
    python main.py --target 192.168.1.100                   # IP 目标
    python main.py --no-capture                             # 仅 AI 检测（跳过抓包）
    python main.py --skip-pipeline                          # 仅流量采集（跳过 AI）
    python main.py --monitor-interval 30                    # 采集间隔 30 秒
    python main.py --pipeline-interval 30                   # AI 检测间隔 30 秒
    python main.py --once                                   # 单次 AI 检测后退出
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import textwrap
import threading
import time
from typing import Optional

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
# 路径设置
# ============================================================================
_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_PROJECT_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

# ============================================================================
# 导入子模块
# ============================================================================
from src.traffic_module.traffic_monitor import (
    TrafficMonitor,
    MonitorConfig,
    DatabaseConfig as MonitorDBConfig,
)
from src.ai_engine.run_pipeline import PipelineService

# ============================================================================
# 公共日志器
# ============================================================================
LOG_DIR = os.path.join(_PROJECT_DIR, "logs")
MAIN_LOG = os.path.join(LOG_DIR, "main.log")


def _setup_main_logger() -> logging.Logger:
    """配置主进程日志器。"""
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("ai_ids_main")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    # 文件
    fh = logging.FileHandler(MAIN_LOG, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # 控制台
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(ch)

    return logger


# ============================================================================
# 主启动横幅
# ============================================================================
_MAIN_BANNER: str = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                ║
║       █████╗ ██╗      ██╗██████╗ ███████╗                     ║
║      ██╔══██╗██║      ██║██╔══██╗██╔════╝                     ║
║      ███████║██║      ██║██║  ██║███████╗                     ║
║      ██╔══██║██║      ██║██║  ██║╚════██║                     ║
║      ██║  ██║██║█████╗██║██████╔╝███████║                     ║
║      ╚═╝  ╚═╝╚═╝╚════╝╚═╝╚═════╝ ╚══════╝                     ║
║                                                                ║
║          AI 网络入侵检测与安全预警系统  v2.0                     ║
║          AI-Powered Intrusion Detection System                 ║
║                                                                ║
╚══════════════════════════════════════════════════════════════════╝"""


_SERVICE_BANNER: str = """
┌──────────────────────────────────────────────────────────────────┐
│                        服务启动状态                               │
├──────────────────────────────────────────────────────────────────┤
│  [1] Traffic Monitor   —  流量采集与特征提取                      │
│      目标: {target:<45} │
│      采集间隔: {monitor_interval}s   AI检测间隔: {pipeline_interval}s │
│                                                                  │
│  [2] Pipeline Service  —  XGBoost AI 检测引擎                    │
│      模型: XGBoost (6 维流量特征)                                │
│      数据源: flow_features (WHERE ai_processed=0)                 │
│      输出: traffic_logs (威胁判定 + 置信度 + AI理由)              │
│                                                                  │
│  数据库: {db_host}:{db_port}/{db_name}                             │
│  日志目录: {log_dir}                                    │
└──────────────────────────────────────────────────────────────────┘"""


# ============================================================================
# AIIDSMaster — 主控器
# ============================================================================

class AIIDSMaster:
    """AI-IDS 主控器 — 统一管理流量采集和 AI 检测两个子系统。

    使用方式::

        master = AIIDSMaster(
            target="www.example.com",
            monitor_interval=60,
            pipeline_interval=60,
            enable_monitor=True,
            enable_pipeline=True,
        )
        master.start()   # 阻塞运行，Ctrl+C 优雅退出
    """

    def __init__(
        self,
        target: str = "www.example.com",
        monitor_interval: float = 60.0,
        pipeline_interval: float = 60.0,
        enable_monitor: bool = True,
        enable_pipeline: bool = True,
        no_capture: bool = False,
    ) -> None:
        # 配置
        self._target: str = target
        self._monitor_interval: float = monitor_interval
        self._pipeline_interval: float = pipeline_interval
        self._enable_monitor: bool = enable_monitor
        self._enable_pipeline: bool = enable_pipeline
        self._no_capture: bool = no_capture

        # 日志
        self._logger: logging.Logger = _setup_main_logger()

        # 子系统实例（延迟初始化）
        self._monitor: Optional[TrafficMonitor] = None
        self._pipeline: Optional[PipelineService] = None

        # 线程管理
        self._monitor_thread: Optional[threading.Thread] = None
        self._pipeline_thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()

        # 状态
        self._start_time: float = 0.0

    # ==================================================================
    # 公共 API
    # ==================================================================

    def start(self) -> None:
        """启动全部服务（阻塞，直到 Ctrl+C 或任意子系统异常退出）。"""
        self._logger.info("=" * 60)
        self._logger.info("AI-IDS 一体化系统启动中...")
        self._logger.info("=" * 60)

        # ── 阶段 1: 打印横幅 ────────────────────────────────────
        self._print_banners()

        # ── 阶段 2: 初始化子系统 ────────────────────────────────
        self._init_subsystems()

        if not self._enable_monitor and not self._enable_pipeline:
            self._logger.warning("未启用任何服务，退出")
            print("未启用任何服务，请检查命令行参数。")
            return

        # ── 阶段 3: 启动各子系统线程 ───────────────────────────
        threads: list[tuple[str, threading.Thread]] = []

        if self._enable_monitor and self._monitor is not None:
            self._monitor_thread = threading.Thread(
                target=self._run_monitor,
                name="TrafficMonitor",
                daemon=True,
            )
            threads.append(("Traffic Monitor", self._monitor_thread))

        if self._enable_pipeline and self._pipeline is not None:
            self._pipeline_thread = threading.Thread(
                target=self._run_pipeline,
                name="PipelineService",
                daemon=True,
            )
            threads.append(("Pipeline Service", self._pipeline_thread))

        for name, t in threads:
            t.start()
            self._logger.info("%s 线程已启动", name)

        self._start_time = time.time()
        print(f"\n  [OK] 全部服务已启动，按 Ctrl+C 停止\n")
        print("=" * 60)
        print()

        # ── 阶段 4: 主线程监控 ─────────────────────────────────
        try:
            # 持续监控所有子线程状态
            while not self._stop_event.is_set():
                all_alive = True
                for name, t in threads:
                    if not t.is_alive():
                        self._logger.error("%s 线程意外退出！", name)
                        all_alive = False
                if not all_alive:
                    self._logger.warning("检测到子线程退出，正在停止全部服务...")
                    break
                self._stop_event.wait(2.0)

        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    def stop(self) -> None:
        """停止全部服务（可从其他线程调用）。"""
        self._logger.info("收到外部停止请求")
        self._stop_event.set()

    # ==================================================================
    # 子系统初始化和运行
    # ==================================================================

    def _init_subsystems(self) -> None:
        """初始化流量监控器和 AI 检测管线。"""

        # ── TrafficMonitor ──────────────────────────────────────
        if self._enable_monitor:
            print("  [1/2] 初始化 TrafficMonitor ...")
            try:
                db_cfg = MonitorDBConfig()
                mon_cfg = MonitorConfig(
                    target_host=self._target,
                    db=db_cfg,
                    write_interval=self._monitor_interval,
                )
                self._monitor = TrafficMonitor(mon_cfg)
                self._logger.info("TrafficMonitor 初始化成功")
                print("         TrafficMonitor 初始化成功")
            except Exception as e:
                self._logger.error("TrafficMonitor 初始化失败: %s", e)
                print(f"         [ERROR] TrafficMonitor 初始化失败: {e}")
                print("         流量采集功能已禁用。")
                self._enable_monitor = False

        # ── PipelineService ─────────────────────────────────────
        if self._enable_pipeline:
            print("  [2/2] 初始化 PipelineService ...")
            try:
                self._pipeline = PipelineService(
                    poll_interval=self._pipeline_interval
                )
                # 检查数据库结构
                if not self._pipeline.ensure_db_structure():
                    raise RuntimeError("数据库结构初始化失败")
                # 加载模型
                if not self._pipeline._load_model():
                    raise RuntimeError("AI 模型加载失败")
                self._logger.info("PipelineService 初始化成功")
                print("         PipelineService 初始化成功 (XGBoost 模型已加载)")
            except Exception as e:
                self._logger.error("PipelineService 初始化失败: %s", e)
                print(f"         [ERROR] PipelineService 初始化失败: {e}")
                print("         AI 检测功能已禁用。")
                self._enable_pipeline = False

    # ── 线程执行体 ──────────────────────────────────────────────

    def _run_monitor(self) -> None:
        """TrafficMonitor 线程执行体。"""
        assert self._monitor is not None
        try:
            # 使用无抓包模式
            if self._no_capture:
                self._logger.info("TrafficMonitor 以无抓包模式启动")
                # 绕过抓包直接进入监控循环（仅处理已有数据或模拟环境）
                self._monitor._logger = logging.getLogger("traffic_monitor")
                self._monitor._logger.info("无抓包模式 — 仅监控数据库变化")
                # 直接进入监控循环（跳过了 capture start）
                # 注意：此处不调用 start() 因为需要管理员权限抓包
                # 在无抓包模式下只保持存活，不退出
                while not self._stop_event.is_set():
                    self._stop_event.wait(10)
            else:
                self._monitor.start()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self._logger.exception("TrafficMonitor 线程异常: %s", e)
        finally:
            self._logger.info("TrafficMonitor 线程已退出")

    def _run_pipeline(self) -> None:
        """PipelineService 线程执行体。"""
        assert self._pipeline is not None
        try:
            self._pipeline.run_forever()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self._logger.exception("PipelineService 线程异常: %s", e)
        finally:
            self._logger.info("PipelineService 线程已退出")

    # ==================================================================
    # 输出与控制
    # ==================================================================

    def _print_banners(self) -> None:
        """打印启动横幅。"""
        print(_MAIN_BANNER)
        print()
        print(_SERVICE_BANNER.format(
            target=self._target,
            monitor_interval=f"{self._monitor_interval:.0f}",
            pipeline_interval=f"{self._pipeline_interval:.0f}",
            db_host="127.0.0.1",
            db_port="3306",
            db_name="ai_ids_system",
            log_dir=LOG_DIR,
        ))

    def _shutdown(self) -> None:
        """优雅关闭所有服务。"""
        print()
        print("=" * 60)
        print("  正在关闭所有服务...")
        print("=" * 60)

        self._stop_event.set()

        # 1. 停止 PipelineService
        if self._pipeline is not None:
            print("  [1/2] 停止 PipelineService ...")
            try:
                self._pipeline.stop()
            except Exception as e:
                self._logger.warning("停止 PipelineService 异常: %s", e)
            if self._pipeline_thread and self._pipeline_thread.is_alive():
                self._pipeline_thread.join(timeout=10)
                print("         PipelineService 已停止")

        # 2. 停止 TrafficMonitor
        if self._monitor is not None:
            print("  [2/2] 停止 TrafficMonitor ...")
            try:
                self._monitor.stop()
            except Exception as e:
                self._logger.warning("停止 TrafficMonitor 异常: %s", e)
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=10)
                print("         TrafficMonitor 已停止")

        # 3. 打印汇总
        total_time = time.time() - self._start_time if self._start_time > 0 else 0
        hours, rem = divmod(int(total_time), 3600)
        minutes, seconds = divmod(rem, 60)

        print()
        print("=" * 60)
        print("  AI-IDS 系统已停止")
        print("=" * 60)
        print(f"  运行时长     : {hours:02d}:{minutes:02d}:{seconds:02d}")
        if self._pipeline is not None:
            print(f"  AI 分析累计  : {self._pipeline._total_analyzed} 条")
            print(f"  检测攻击     : {self._pipeline._total_attacks} 条")
        print(f"  主日志文件   : {MAIN_LOG}")
        print("=" * 60)

        self._logger.info(
            "AI-IDS 系统已停止 — 运行时长=%s",
            f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        )


# ============================================================================
# CLI 入口
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        description="AI-IDS 一体化启动入口 — 流量采集 + AI 检测 一键启动",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            使用示例:
              python main.py                                        # 默认启动全部服务
              python main.py --target www.baidu.com                 # 指定监控目标
              python main.py --target 192.168.1.100                 # IP 目标
              python main.py --no-capture                           # 仅 AI 检测（跳过抓包）
              python main.py --monitor-interval 30                  # 采集间隔 30s
              python main.py --pipeline-interval 30                 # AI 检测间隔 30s
              python main.py --once                                 # 单次 AI 检测后退出
              python main.py --all                                  # 重置并全量重检测

            目标网站示例:
              www.baidu.com     — 百度首页
              www.example.com   — 测试站点
              www.httpbin.org   — HTTP 测试工具
        """),
    )

    # ── 目标配置 ────────────────────────────────────────────────
    target_group = parser.add_argument_group("目标配置")
    target_group.add_argument(
        "--target", "-t",
        default="www.example.com",
        help="目标网站域名或 IP（默认: www.example.com）",
    )

    # ── 服务开关 ────────────────────────────────────────────────
    svc_group = parser.add_argument_group("服务开关")
    svc_group.add_argument(
        "--no-capture", action="store_true",
        help="跳过 Scapy 实时抓包（无需管理员权限，仅运行 AI 检测）",
    )
    svc_group.add_argument(
        "--skip-monitor", action="store_true",
        help="跳过流量采集模块，仅运行 AI 检测",
    )
    svc_group.add_argument(
        "--skip-pipeline", action="store_true",
        help="跳过 AI 检测模块，仅运行流量采集",
    )

    # ── 调度参数 ────────────────────────────────────────────────
    sched_group = parser.add_argument_group("调度参数")
    sched_group.add_argument(
        "--monitor-interval", type=float, default=60.0,
        help="流量采集写入间隔（秒，默认 60）",
    )
    sched_group.add_argument(
        "--pipeline-interval", type=float, default=60.0,
        help="AI 检测轮询间隔（秒，默认 60）",
    )

    # ── 单次模式 ────────────────────────────────────────────────
    once_group = parser.add_argument_group("运行模式")
    once_group.add_argument(
        "--once", action="store_true",
        help="仅执行一次 AI 检测后退出（不进入持续循环）",
    )
    once_group.add_argument(
        "--all", action="store_true",
        help="重置所有 ai_processed=0 后全量重新检测",
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # ── 模式判断 ─────────────────────────────────────────────────
    enable_monitor = not args.skip_monitor and not args.once and not args.no_capture
    enable_pipeline = not args.skip_pipeline

    # --no-capture 隐含 --skip-monitor
    if args.no_capture:
        enable_monitor = False

    # ── 单次模式：快速路径 ───────────────────────────────────────
    if args.once or (args.all and not enable_monitor):
        # 不启动 TrafficMonitor，仅执行一次 AI 检测
        pipeline = PipelineService(poll_interval=args.pipeline_interval)

        if not pipeline.ensure_db_structure():
            print("[FATAL] 数据库初始化失败，退出")
            sys.exit(1)

        if not pipeline._load_model():
            print("[FATAL] AI 模型加载失败，退出")
            sys.exit(1)

        if args.all:
            conn = pipeline._get_connection()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE flow_features "
                        "SET ai_processed = 0, predict_time = NULL"
                    )
                    conn.commit()
                    affected = cur.rowcount
                    cur.close()
                    print(f"已重置 {affected} 条记录的 ai_processed=0")
                except Exception as e:
                    print(f"重置 ai_processed 失败: {e}")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

        pipeline._print_banner()
        print(f"\n{pipeline.SEPARATOR}")
        analyzed = pipeline.analyze_once()
        if analyzed > 0:
            print(f"\n已写入 traffic_logs")
            print(f"已更新 ai_processed=1")
        elif analyzed == 0:
            print("未发现未分析流量")
        else:
            print("检测失败，请查看日志")
        print(f"{pipeline.SEPARATOR}\n")
        return

    # ── 持续运行模式 ─────────────────────────────────────────────
    master = AIIDSMaster(
        target=args.target,
        monitor_interval=args.monitor_interval,
        pipeline_interval=args.pipeline_interval,
        enable_monitor=enable_monitor,
        enable_pipeline=enable_pipeline,
        no_capture=args.no_capture,
    )

    # 如有 --all 参数，先重置再启动持续模式
    if args.all:
        pipeline = PipelineService(poll_interval=args.pipeline_interval)
        if pipeline.ensure_db_structure():
            conn = pipeline._get_connection()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE flow_features "
                        "SET ai_processed = 0, predict_time = NULL"
                    )
                    conn.commit()
                    affected = cur.rowcount
                    cur.close()
                    print(f"已重置 {affected} 条记录的 ai_processed=0\n")
                except Exception as e:
                    print(f"重置 ai_processed 失败: {e}")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

    try:
        master.start()
    except KeyboardInterrupt:
        print("\n用户中断，程序退出。")
    except Exception as e:
        logger = logging.getLogger("ai_ids_main")
        logger.critical("系统异常退出: %s", e, exc_info=True)
        print(f"\n[FATAL] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
