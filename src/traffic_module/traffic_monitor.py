"""
流量监控模块 — 持续监控目标网站流量并定时写入 MySQL。

traffic_monitor.py 在现有模块基础上实现：
    capture.py           — 后台抓包（DNS 解析 + BPF 过滤 + 域名过滤）
    parser.py            — 深度协议解析（PacketParser）
    feature_extractor.py — 流特征统计（FlowManager → FlowFeature）

数据流:
    目标网站 ──Scapy──▶ capture.py ──raw packets──▶ parser.py ──ParsedPacket──▶
    feature_extractor.py ──FlowFeature──▶ MySQL ──▶ AI 模块 / 告警平台

职责:
    1. 目标网站 DNS 解析与 IP 跟踪
    2. 启动/管理后台抓包（仅采集目标 IP 相关流量）
    3. 每 60 秒: 回收超时 Flow → 提取特征 → 批量写入 MySQL
    4. 实时控制台状态展示
    5. 完整日志记录
    6. 全面异常处理（数据库断开/DNS 失败/抓包异常均不退出）

用法:
    python traffic_monitor.py
    python traffic_monitor.py --target www.example.com
    python traffic_monitor.py --target 192.168.1.100 --interval 30
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import socket
import sys
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 确保可导入同包模块（使用包前缀，避免 capture.py 中的相对导入失败）
# ---------------------------------------------------------------------------

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_THIS_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from traffic_module.capture import (  # noqa: E402
    start_capture,
    stop_capture,
    get_recent_raw_packets,
    get_packet_count,
    get_statistics as get_capture_statistics,
    set_target_domains,
    is_running as is_capture_running,
)
from traffic_module.parser import PacketParser  # noqa: E402
from traffic_module.feature_extractor import FlowManager, FlowFeature, FLOW_TIMEOUT  # noqa: E402

# ---------------------------------------------------------------------------
# 可选依赖检查
# ---------------------------------------------------------------------------

try:
    import pymysql
    PYMSQL_AVAILABLE = True
except ImportError:
    PYMSQL_AVAILABLE = False
    pymysql = None  # type: ignore[assignment]


# ============================================================================
# 配置数据类
# ============================================================================

@dataclass
class DatabaseConfig:
    """MySQL 数据库连接配置。"""

    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "AIIDS"
    password: str = "123456"
    database: str = "ai_ids_system"

    # 连接池/重连参数
    connect_timeout: int = 10
    read_timeout: int = 30
    write_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 2.0
    charset: str = "utf8mb4"


@dataclass
class MonitorConfig:
    """流量监控器配置。"""

    # 目标
    target_host: str = "www.example.com"
    """目标网站域名或 IP 地址。"""

    # 数据库
    db: DatabaseConfig = field(default_factory=DatabaseConfig)

    # 定时任务
    write_interval: float = 60.0
    """数据库写入间隔（秒）。"""

    # Flow 超时
    flow_timeout: float = FLOW_TIMEOUT
    """Flow 空闲超时（秒），超时后自动关闭。"""

    # 日志
    log_path: str = os.path.join(_THIS_DIR, "logs", "traffic_monitor.log")

    # 抓包
    capture_interface: Optional[str] = None
    """网卡名称，None 为自动检测。"""

    # 控制台
    status_interval: float = 60.0
    """控制台状态刷新间隔（秒）。"""

    # DNS
    dns_refresh_interval: float = 300.0
    """DNS 重新解析间隔（秒），仅对域名目标有效。"""

    # 采样（调试用）
    packet_sample_limit: int = 0
    """每次轮询最多处理的数据包数，0 表示不限制。"""


# ============================================================================
# 日志系统
# ============================================================================

def _setup_logging(log_path: str) -> logging.Logger:
    """配置 traffic_monitor 专用日志器。"""
    logger = logging.getLogger("traffic_monitor")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    # 确保日志目录存在
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    # 文件处理器 — 记录所有级别
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    # 控制台处理器 — INFO 及以上
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    ))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ============================================================================
# DatabaseManager — MySQL 操作封装
# ============================================================================

class DatabaseManager:
    """MySQL 数据库操作管理器。

    职责:
        - 连接管理（自动重连）
        - 表创建（CREATE TABLE IF NOT EXISTS）
        - 单条/批量 Flow 特征写入
        - 连接健康检查

    所有数据库异常均被捕获并记录日志，不会向上传播导致程序崩溃。
    """

    # 表结构 SQL
    CREATE_TABLE_SQL: str = """
        CREATE TABLE IF NOT EXISTS flow_features (
            id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
            create_time     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            COMMENT '记录创建时间',
            target_host     VARCHAR(255)    NOT NULL
                                            COMMENT '目标主机域名或IP',
            target_ip       VARCHAR(45)     NOT NULL
                                            COMMENT '目标IP地址',
            Protocol        INT             NOT NULL
                                            COMMENT '协议号 (6=TCP, 17=UDP, 1=ICMP)',
            Flow_Duration   DOUBLE          NOT NULL DEFAULT 0.0
                                            COMMENT '流持续时间(秒)',
            Total_Fwd_Packets       INT     NOT NULL DEFAULT 0
                                            COMMENT '前向数据包数量',
            Total_Backward_Packets  INT     NOT NULL DEFAULT 0
                                            COMMENT '后向数据包数量',
            Fwd_Packet_Length_Max   DOUBLE  NOT NULL DEFAULT 0.0
                                            COMMENT '前向最大包长(字节)',
            Bwd_Packet_Length_Max   DOUBLE  NOT NULL DEFAULT 0.0
                                            COMMENT '后向最大包长(字节)',
            INDEX idx_create_time (create_time),
            INDEX idx_target_host (target_host),
            INDEX idx_target_ip (target_ip),
            INDEX idx_protocol (Protocol)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        COMMENT='AI-IDS 流特征表 — 供 AI 模块与告警平台读取';
    """

    # 批量插入 SQL
    INSERT_SQL: str = """
        INSERT INTO flow_features
            (target_host, target_ip, Protocol, Flow_Duration,
             Total_Fwd_Packets, Total_Backward_Packets,
             Fwd_Packet_Length_Max, Bwd_Packet_Length_Max)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s);
    """

    def __init__(self, config: DatabaseConfig) -> None:
        self._config: DatabaseConfig = config
        self._conn: Any = None
        self._lock: threading.Lock = threading.Lock()
        self._logger: logging.Logger = logging.getLogger("traffic_monitor.db")

    # ---- 连接管理 ----------------------------------------------------------

    def connect(self) -> bool:
        """建立数据库连接。

        Returns:
            True 连接成功，False 连接失败。
        """
        if not PYMSQL_AVAILABLE:
            self._logger.error("PyMySQL 未安装，无法连接数据库。请运行: pip install pymysql")
            return False

        with self._lock:
            for attempt in range(1, self._config.max_retries + 1):
                try:
                    self._conn = pymysql.connect(
                        host=self._config.host,
                        port=self._config.port,
                        user=self._config.user,
                        password=self._config.password,
                        database=self._config.database,
                        connect_timeout=self._config.connect_timeout,
                        read_timeout=self._config.read_timeout,
                        write_timeout=self._config.write_timeout,
                        charset=self._config.charset,
                        autocommit=True,
                    )
                    self._logger.info(
                        "数据库连接成功 | host=%s:%d db=%s",
                        self._config.host, self._config.port, self._config.database,
                    )
                    return True

                except pymysql.err.OperationalError as e:
                    self._logger.warning(
                        "数据库连接失败 (attempt %d/%d): %s",
                        attempt, self._config.max_retries, e,
                    )
                    if attempt < self._config.max_retries:
                        time.sleep(self._config.retry_delay)
                except Exception as e:
                    self._logger.error("数据库连接异常: %s", e)
                    break

        self._logger.error("数据库连接最终失败，将跳过后续写入操作")
        return False

    def close(self) -> None:
        """关闭数据库连接。"""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                    self._logger.info("数据库连接已关闭")
                except Exception as e:
                    self._logger.warning("关闭数据库连接时异常: %s", e)
                finally:
                    self._conn = None

    def is_connected(self) -> bool:
        """检查数据库连接是否有效。"""
        with self._lock:
            if self._conn is None:
                return False
            try:
                self._conn.ping(reconnect=False)
                return True
            except Exception:
                return False

    def _ensure_connection(self) -> bool:
        """确保数据库连接有效，必要时重连。"""
        if self.is_connected():
            return True
        self._logger.info("数据库连接已断开，尝试重新连接...")
        # 关闭旧连接
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
        return self.connect()

    # ---- 表管理 -------------------------------------------------------------

    def create_table(self) -> bool:
        """创建 flow_features 表（幂等操作）。

        Returns:
            True 创建成功，False 失败。
        """
        if not self._ensure_connection():
            return False

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(self.CREATE_TABLE_SQL)
                cursor.close()
                self._logger.info("数据表 flow_features 已就绪")
                return True
            except Exception as e:
                self._logger.error("创建数据表失败: %s", e)
                return False

    # ---- 单条写入 -----------------------------------------------------------

    def insert_flow(
        self,
        flow: FlowFeature,
        target_host: str,
        target_ip: str,
    ) -> bool:
        """写入单条 Flow 特征记录。

        Args:
            flow: FlowFeature 实例。
            target_host: 目标主机名（域名或 IP）。
            target_ip: 目标 IP 地址。

        Returns:
            True 写入成功，False 失败。
        """
        if not self._ensure_connection():
            return False

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.execute(self.INSERT_SQL, (
                    target_host,
                    target_ip,
                    flow.Protocol,
                    flow.Flow_Duration,
                    flow.Total_Fwd_Packets,
                    flow.Total_Backward_Packets,
                    flow.Fwd_Packet_Length_Max,
                    flow.Bwd_Packet_Length_Max,
                ))
                cursor.close()
                return True
            except Exception as e:
                self._logger.error("写入单条 Flow 失败: %s", e)
                return False

    # ---- 批量写入 -----------------------------------------------------------

    def insert_batch(
        self,
        flows: List[FlowFeature],
        target_host: str,
        target_ip: str,
    ) -> int:
        """批量写入 Flow 特征记录。

        使用 executemany 一次性提交，显著提升写入效率。

        Args:
            flows: FlowFeature 列表。
            target_host: 目标主机名。
            target_ip: 目标 IP。

        Returns:
            实际成功写入的记录数（0 表示全部失败或数据库不可用）。
        """
        if not flows:
            return 0

        if not self._ensure_connection():
            return 0

        rows: List[Tuple[Any, ...]] = [
            (
                target_host,
                target_ip,
                f.Protocol,
                f.Flow_Duration,
                f.Total_Fwd_Packets,
                f.Total_Backward_Packets,
                f.Fwd_Packet_Length_Max,
                f.Bwd_Packet_Length_Max,
            )
            for f in flows
        ]

        with self._lock:
            try:
                cursor = self._conn.cursor()
                cursor.executemany(self.INSERT_SQL, rows)
                cursor.close()
                self._logger.info("批量写入成功 | 记录数=%d", len(flows))
                return len(flows)
            except pymysql.err.OperationalError as e:
                self._logger.error("批量写入失败（连接问题）: %s", e)
                # 标记连接失效，下次自动重连
                self._conn = None
                return 0
            except Exception as e:
                self._logger.error("批量写入失败: %s", e)
                return 0

    # ---- 统计查询 -----------------------------------------------------------

    def get_record_count(self) -> int:
        """查询当前表中的记录总数。"""
        if not self.is_connected():
            return -1
        try:
            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM flow_features;")
                count: int = cursor.fetchone()[0]
                cursor.close()
                return count
        except Exception:
            return -1


# ============================================================================
# DNS 解析工具
# ============================================================================

# IPv4 正则
_IPV4_PATTERN: re.Pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _is_ip_address(host: str) -> bool:
    """判断字符串是否为 IPv4 地址。"""
    if not _IPV4_PATTERN.match(host):
        return False
    # 验证每段范围 0-255
    try:
        parts = [int(p) for p in host.split(".")]
        return all(0 <= p <= 255 for p in parts)
    except ValueError:
        return False


def resolve_host(host: str) -> Tuple[str, List[str]]:
    """解析目标主机为 IP 地址。

    Args:
        host: 域名或 IP 地址。

    Returns:
        (target_ip, [all_resolved_ips]) — 主 IP 和全部解析结果。

    Raises:
        socket.gaierror: DNS 解析失败。
        ValueError: host 为空。
    """
    if not host or not host.strip():
        raise ValueError("目标主机不能为空")

    host = host.strip()

    if _is_ip_address(host):
        return host, [host]

    # DNS 解析
    ips: List[str] = []
    try:
        # 获取所有 IP（IPv4 + IPv6）
        addrinfo = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = list(set(ai[4][0] for ai in addrinfo))
    except socket.gaierror:
        # getaddrinfo 失败，回退到 gethostbyname
        pass

    if not ips:
        try:
            ip = socket.gethostbyname(host)
            ips = [ip]
        except socket.gaierror as e:
            raise socket.gaierror(f"DNS 解析失败: {host} — {e}") from e

    return ips[0], ips


# ============================================================================
# TrafficMonitor — 核心监控引擎
# ============================================================================

class TrafficMonitor:
    """流量监控器 — 核心编排引擎。

    串联 capture → parser → feature_extractor → MySQL 全流程，
    实现长期稳定运行的流量监控与定期数据持久化。

    使用方式::

        config = MonitorConfig(target_host="www.example.com")
        monitor = TrafficMonitor(config)
        monitor.start()  # 阻塞运行，直到 Ctrl+C 或 stop()
    """

    # 控制台模板
    _BANNER: str = """
╔══════════════════════════════════════════════════════════════╗
║            AI-IDS  流量监控系统  Traffic Monitor            ║
╚══════════════════════════════════════════════════════════════╝"""

    _STATUS_TEMPLATE: str = """
┌──────────────────────────────────────────────────────────────┐
│                   Traffic Monitor  Status                    │
├──────────────────────────────────────────────────────────────┤
│  Target Host       : {target_host:<40} │
│  Target IP         : {target_ip:<40} │
│  Active Flows      : {active_flows:>8}                          │
│  Captured Packets  : {captured_packets:>8}                          │
│  Database Records  : {db_records:>8}                          │
│  Uptime            : {uptime:<40} │
│  Last DB Write     : {last_write:<40} │
└──────────────────────────────────────────────────────────────┘"""

    def __init__(self, config: MonitorConfig) -> None:
        self._config: MonitorConfig = config
        self._logger: logging.Logger = _setup_logging(config.log_path)

        # 核心组件
        self._parser: PacketParser = PacketParser()
        self._flow_manager: FlowManager = FlowManager(timeout=config.flow_timeout)
        self._db: DatabaseManager = DatabaseManager(config.db)

        # 目标信息
        self._target_ip: str = ""
        self._target_ips: List[str] = []
        self._is_domain_target: bool = False

        # 运行状态
        self._running: bool = False
        self._stop_event: threading.Event = threading.Event()
        self._start_time: float = 0.0
        self._last_write_time: float = 0.0
        self._last_status_time: float = 0.0
        self._last_dns_refresh: float = 0.0

        # 数据包处理追踪 — 使用时间戳标记，避免 deque 容量满后计数追踪失效
        self._last_packet_time: float = 0.0
        self._total_captured: int = 0

        # 数据库写入追踪
        self._written_flow_ids: Set[str] = set()
        self._db_total_records: int = 0

        # 状态锁
        self._state_lock: threading.Lock = threading.Lock()

    # ==================================================================
    # 公共 API
    # ==================================================================

    def start(self) -> None:
        """启动流量监控（阻塞运行）。"""
        self._logger.info("=" * 60)
        self._logger.info("Traffic Monitor 启动中...")
        self._logger.info("=" * 60)

        # ---- 阶段 1: DNS 解析 ----
        self._resolve_target()

        # ---- 阶段 2: 数据库连接 ----
        self._init_database()

        # ---- 阶段 3: 启动抓包 ----
        self._start_capture()

        # ---- 阶段 4: 主监控循环 ----
        self._running = True
        self._start_time = time.time()
        self._last_write_time = self._start_time
        self._last_status_time = self._start_time
        self._last_dns_refresh = self._start_time

        # 打印启动 Banner
        self._print_banner()

        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            self._logger.info("收到中断信号 (Ctrl+C)，正在优雅退出...")
        finally:
            self._shutdown()

    def stop(self) -> None:
        """停止监控（可从其他线程调用）。"""
        self._logger.info("收到停止请求")
        self._stop_event.set()
        self._running = False

    # ==================================================================
    # 阶段 1: DNS 解析
    # ==================================================================

    def _resolve_target(self) -> None:
        """解析目标主机名，获取目标 IP。"""
        host = self._config.target_host
        self._is_domain_target = not _is_ip_address(host)

        self._logger.info(
            "目标类型: %s",
            "域名" if self._is_domain_target else "IP 地址",
        )

        try:
            self._target_ip, self._target_ips = resolve_host(host)
            self._logger.info("目标主机: %s", host)
            self._logger.info("目标 IP  : %s", self._target_ip)
            if len(self._target_ips) > 1:
                self._logger.info("全部 IP  : %s", ", ".join(self._target_ips))
        except (socket.gaierror, ValueError) as e:
            self._logger.error("DNS 解析失败: %s", e)
            self._logger.error("请检查目标主机名是否正确，以及网络连接是否正常")
            raise

    def _refresh_dns(self) -> None:
        """定期刷新 DNS 解析（仅对域名目标生效）。"""
        if not self._is_domain_target:
            return

        now = time.time()
        if now - self._last_dns_refresh < self._config.dns_refresh_interval:
            return

        self._logger.info("正在刷新 DNS 解析...")
        try:
            new_ip, new_ips = resolve_host(self._config.target_host)
            if new_ip != self._target_ip or set(new_ips) != set(self._target_ips):
                self._logger.info(
                    "DNS 记录已变更 | 旧 IP: %s → 新 IP: %s",
                    self._target_ip, new_ip,
                )
                self._target_ip = new_ip
                self._target_ips = new_ips
                # 更新域名过滤器
                set_target_domains([self._config.target_host])
            else:
                self._logger.debug("DNS 记录未变化")
        except Exception as e:
            self._logger.warning("DNS 刷新失败（将保留旧 IP）: %s", e)
        finally:
            self._last_dns_refresh = now

    # ==================================================================
    # 阶段 2: 数据库初始化
    # ==================================================================

    def _init_database(self) -> None:
        """初始化数据库连接与表结构。"""
        if not PYMSQL_AVAILABLE:
            self._logger.warning(
                "PyMySQL 未安装，数据库功能不可用。请运行: pip install pymysql"
            )
            return

        if self._db.connect():
            self._db.create_table()
            self._db_total_records = self._db.get_record_count()
            if self._db_total_records >= 0:
                self._logger.info("数据库中现有记录数: %d", self._db_total_records)
        else:
            self._logger.warning("数据库初始化失败，将在后续周期自动重试")

    # ==================================================================
    # 阶段 3: 启动抓包
    # ==================================================================

    def _start_capture(self) -> None:
        """配置并启动后台抓包。"""
        try:
            from scapy.all import sniff  # noqa: F401
        except ImportError:
            self._logger.error(
                "Scapy 未安装！请运行: pip install scapy\n"
                "Windows 用户还需安装 Npcap: https://npcap.com/"
            )
            raise

        # 域名目标: 使用域名过滤器（含 HTTP Host + TLS SNI 检测）
        if self._is_domain_target:
            self._logger.info("启用域名过滤模式: %s", self._config.target_host)
            set_target_domains([self._config.target_host])

        # IP 目标: 直接用 BPF host 过滤
        bpf_filter: Optional[str] = None
        if not self._is_domain_target:
            bpf_filter = f"host {self._target_ip}"
            self._logger.info("BPF 过滤器: %s", bpf_filter)

        try:
            start_capture(
                interface=self._config.capture_interface,
                bpf_filter=bpf_filter,
            )
            self._logger.info("后台抓包已启动")
        except RuntimeError as e:
            self._logger.error("启动抓包失败: %s", e)
            self._logger.error("可能原因: 1) 管理员权限  2) Npcap 未安装  3) 抓包已在运行")
            raise
        except PermissionError:
            self._logger.error("权限不足！请以管理员身份运行此程序")
            raise

    # ==================================================================
    # 阶段 4: 主监控循环
    # ==================================================================

    def _monitor_loop(self) -> None:
        """主监控循环 — 持续处理流量并定期写入数据库。"""
        poll_interval: float = 1.0  # 每秒轮询一次新数据包

        while self._running and not self._stop_event.is_set():
            loop_start = time.time()

            try:
                # ---- 步骤 A: DNS 刷新 ----
                self._refresh_dns()

                # ---- 步骤 B: 处理新数据包 ----
                self._process_new_packets()

                # ---- 步骤 C: 定时写入数据库 ----
                now = time.time()
                if now - self._last_write_time >= self._config.write_interval:
                    self._write_cycle()

                # ---- 步骤 D: 定时刷新控制台 ----
                if now - self._last_status_time >= self._config.status_interval:
                    self._print_status()

            except Exception:
                self._logger.exception("监控循环迭代异常（已恢复继续运行）")

            # 控制轮询频率
            elapsed = time.time() - loop_start
            sleep_time = max(0.0, poll_interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)

    # ---- 步骤 B: 处理新数据包 -----------------------------------------------

    def _process_new_packets(self) -> None:
        """从 raw cache 中获取新数据包，解析并送入 FlowManager。

        使用时间戳增量筛选替代计数偏移追踪——彻底解决 deque 达到 maxlen
        后旧包被新包驱逐导致 ``total_raw`` 不变进而漏掉新包的问题。
        """
        try:
            raw_packets = get_recent_raw_packets()
        except Exception as e:
            self._logger.warning("获取 raw packets 失败: %s", e)
            return

        if not raw_packets:
            return

        # ---- 时间戳增量筛选（Scaly sniff 为每个包附加 .time 属性） ----
        new_packets: List[Any] = []
        max_ts: float = self._last_packet_time

        for pkt in raw_packets:
            pkt_ts: float = getattr(pkt, "time", 0.0) or 0.0
            if pkt_ts > self._last_packet_time:
                new_packets.append(pkt)
                if pkt_ts > max_ts:
                    max_ts = pkt_ts

        if not new_packets:
            return

        # 采样限制
        limit = self._config.packet_sample_limit
        if limit > 0 and len(new_packets) > limit:
            # 按时间戳排序后取最近 N 条
            new_packets.sort(key=lambda p: getattr(p, "time", 0))
            new_packets = new_packets[-limit:]

        # ---- 解析 ----
        try:
            parsed_list = self._parser.parse_packets(new_packets)
        except Exception as e:
            self._logger.warning("批量解析失败: %s", e)
            # 即使解析失败也更新标记，避免死循环重试同一批坏包
            self._last_packet_time = max_ts
            return

        # ---- 送入 FlowManager ----
        processed = 0
        for parsed in parsed_list:
            try:
                closed_flow_id = self._flow_manager.process_packet(parsed)
                processed += 1
                if closed_flow_id:
                    self._logger.debug("Flow 主动关闭: %s", closed_flow_id)
            except Exception:
                self._logger.debug("Flow 处理异常（单包）", exc_info=True)

        # ---- 回收超时 Flow ----
        try:
            self._flow_manager.cleanup_expired_flows()
        except Exception:
            self._logger.warning("超时回收异常", exc_info=True)

        # ---- 更新状态 ----
        with self._state_lock:
            self._total_captured += processed

        # 仅当解析成功后才推进时间戳标记（避免时钟跳变导致漏包）
        self._last_packet_time = max_ts

        if processed > 0:
            self._logger.debug(
                "处理批次 | 原始缓存=%d 增量=%d 解析=%d 处理=%d",
                len(raw_packets), len(new_packets), len(parsed_list), processed,
            )

    # ---- 步骤 C: 定时写入数据库 ---------------------------------------------

    def _write_cycle(self) -> None:
        """执行一次完整的数据库写入周期。

        流程: 获取已完成 Flow → 过滤已写入 → 批量 INSERT → 标记已写入
        """
        now = time.time()
        self._last_write_time = now

        # 1. 获取已完成 Flow
        try:
            completed = self._flow_manager.get_completed_flows()
        except Exception as e:
            self._logger.warning("获取已完成 Flow 失败: %s", e)
            return

        if not completed:
            self._logger.debug("无已完成 Flow，跳过写入")
            return

        # 2. 过滤已写入的 Flow（按 flow_id 去重）
        new_flows: List[FlowFeature] = [
            f for f in completed
            if f.flow_id and f.flow_id not in self._written_flow_ids
        ]

        if not new_flows:
            self._logger.debug(
                "无新 Flow 需写入 (已完成=%d 已写入=%d)",
                len(completed), len(self._written_flow_ids),
            )
            return

        self._logger.info(
            "准备写入数据库 | 新增 Flow=%d (总计已完成=%d)",
            len(new_flows), len(completed),
        )

        # 3. 批量写入
        written = self._db.insert_batch(
            new_flows,
            target_host=self._config.target_host,
            target_ip=self._target_ip,
        )

        if written > 0:
            # 4. 标记已写入
            for f in new_flows:
                if f.flow_id:
                    self._written_flow_ids.add(f.flow_id)

            with self._state_lock:
                self._db_total_records += written

            self._logger.info(
                "数据库写入完成 | 写入=%d 条 | 累计=%d 条",
                written, self._db_total_records,
            )

            # 5. 清理旧 ID（避免内存无限增长）
            if len(self._written_flow_ids) > 100000:
                # 仅保留最近 50000 个 ID
                to_keep = set(list(self._written_flow_ids)[-50000:])
                self._logger.info("清理已写入 ID 缓存: %d → %d",
                                  len(self._written_flow_ids), len(to_keep))
                self._written_flow_ids = to_keep
        else:
            self._logger.warning("数据库写入失败，将在下个周期重试")

    # ---- 步骤 D: 控制台展示 -------------------------------------------------

    def _print_banner(self) -> None:
        """打印启动横幅与初始状态。"""
        print(self._BANNER)
        print()
        print(f"  Target Host       : {self._config.target_host}")
        print(f"  Target IP         : {self._target_ip}")
        print(f"  Write Interval    : {self._config.write_interval:.0f}s")
        print(f"  Flow Timeout      : {self._config.flow_timeout:.0f}s")
        print(f"  Database          : {self._config.db.host}:{self._config.db.port}/{self._config.db.database}")
        print(f"  Log File          : {self._config.log_path}")
        print()
        self._logger.info("Traffic Monitor 已启动，持续监控中...")

    def _print_status(self) -> None:
        """打印实时状态到控制台。"""
        self._last_status_time = time.time()

        # 收集状态数据
        try:
            fs = self._flow_manager.statistics
            capture_stats = get_capture_statistics()
        except Exception:
            return

        with self._state_lock:
            total_captured = self._total_captured
            db_records = self._db_total_records

        # 计算运行时长
        uptime_seconds = int(time.time() - self._start_time)
        hours, rem = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # 上次写入时间
        if self._last_write_time > self._start_time:
            last_write_dt = datetime.fromtimestamp(self._last_write_time)
            last_write_str = last_write_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_write_str = "等待首次写入..."

        # 获取抓包计数
        captured = get_packet_count() if is_capture_running() else total_captured

        print(self._STATUS_TEMPLATE.format(
            target_host=self._config.target_host,
            target_ip=self._target_ip,
            active_flows=fs["active_flows"],
            captured_packets=captured,
            db_records=db_records,
            uptime=uptime_str,
            last_write=last_write_str,
        ))

        self._logger.debug(
            "状态 | 活跃Flow=%d 已关闭=%d 捕获=%d DB记录=%d",
            fs["active_flows"], fs["closed_flows"], captured, db_records,
        )

    # ==================================================================
    # 关闭流程
    # ==================================================================

    def _shutdown(self) -> None:
        """优雅关闭：停止抓包 → 最后写入 → 关闭数据库。"""
        self._logger.info("正在关闭 Traffic Monitor...")
        self._running = False

        # 1. 停止抓包
        try:
            stop_capture()
            self._logger.info("抓包已停止")
        except Exception as e:
            self._logger.warning("停止抓包时异常: %s", e)

        # 2. 强制回收所有超时 Flow
        try:
            self._flow_manager.cleanup_expired_flows(now=float("inf"))
        except Exception as e:
            self._logger.warning("最终回收异常: %s", e)

        # 3. 最后写入数据库
        try:
            self._write_cycle()
        except Exception as e:
            self._logger.warning("最终写入异常: %s", e)

        # 4. 打印最终统计
        self._print_final_summary()

        # 5. 关闭数据库
        try:
            self._db.close()
        except Exception:
            pass

        self._logger.info("Traffic Monitor 已停止")

    def _print_final_summary(self) -> None:
        """打印最终运行摘要。"""
        total_time = time.time() - self._start_time if self._start_time > 0 else 0

        try:
            fs = self._flow_manager.statistics
            ps = self._parser.statistics
        except Exception:
            fs, ps = {}, {}

        print()
        print("=" * 60)
        print("  Traffic Monitor — 运行摘要")
        print("=" * 60)
        print(f"  目标主机          : {self._config.target_host}")
        print(f"  目标 IP           : {self._target_ip}")
        print(f"  总运行时长        : {total_time:.1f} 秒")
        print(f"  处理数据包        : {self._total_captured}")
        print(f"  解析统计 (TCP/UDP/ICMP): {ps.get('tcp', 0)}/{ps.get('udp', 0)}/{ps.get('icmp', 0)}")
        print(f"  HTTP/HTTPS        : {ps.get('http', 0)}/{ps.get('https', 0)}")
        print(f"  创建 Flow 总数    : {fs.get('total_created', 0)}")
        print(f"  已关闭 Flow       : {fs.get('total_closed', 0)}")
        print(f"    ├─ 超时回收     : {fs.get('closed_by_timeout', 0)}")
        print(f"    └─ FIN/RST      : {fs.get('closed_by_fin_rst', 0)}")
        print(f"  活跃 Flow         : {fs.get('active_flows', 0)}")
        print(f"  数据库写入        : {self._db_total_records} 条")
        print(f"  日志文件          : {self._config.log_path}")
        print("=" * 60)


# ============================================================================
# CLI 入口
# ============================================================================

def _parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(
        description="AI-IDS 流量监控系统 — 持续监控目标网站并写入 MySQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            使用示例:
              python traffic_monitor.py
              python traffic_monitor.py --target www.example.com
              python traffic_monitor.py --target 192.168.1.100
              python traffic_monitor.py --target www.baidu.com --interval 30
              python traffic_monitor.py --target www.google.com \\
                  --db-host 192.168.1.50 --db-user ids_user --db-password secret

            数据库配置也可通过环境变量设置:
              AI_IDS_DB_HOST, AI_IDS_DB_PORT, AI_IDS_DB_USER,
              AI_IDS_DB_PASSWORD, AI_IDS_DB_NAME
        """),
    )

    # 目标
    parser.add_argument(
        "--target", "-t",
        default=os.environ.get("AI_IDS_TARGET", "www.example.com"),
        help="目标网站域名或 IP（默认: www.example.com）",
    )

    # 数据库（使用 None 作为默认值，让 DatabaseConfig 的字段默认值生效）
    db_group = parser.add_argument_group("数据库配置")
    db_group.add_argument(
        "--db-host",
        default=None,
        help="MySQL 主机地址（默认: 127.0.0.1）",
    )
    db_group.add_argument(
        "--db-port",
        type=int,
        default=None,
        help="MySQL 端口（默认: 3306）",
    )
    db_group.add_argument(
        "--db-user",
        default=None,
        help="MySQL 用户名（默认: AIIDS）",
    )
    db_group.add_argument(
        "--db-password",
        default=None,
        help="MySQL 密码（默认: 123456）",
    )
    db_group.add_argument(
        "--db-name",
        default=None,
        help="MySQL 数据库名（默认: ai_ids_system）",
    )

    # 监控参数
    mon_group = parser.add_argument_group("监控参数")
    mon_group.add_argument(
        "--interval", "-i",
        type=float,
        default=60.0,
        help="数据库写入间隔（秒，默认: 60）",
    )
    mon_group.add_argument(
        "--flow-timeout",
        type=float,
        default=FLOW_TIMEOUT,
        help=f"Flow 超时时间（秒，默认: {FLOW_TIMEOUT}）",
    )
    mon_group.add_argument(
        "--interface", "-I",
        default=None,
        help="监听的网卡名称（默认: 自动检测）",
    )
    mon_group.add_argument(
        "--log-path",
        default=os.path.join(_THIS_DIR, "logs", "traffic_monitor.log"),
        help="日志文件路径",
    )
    mon_group.add_argument(
        "--sample-limit",
        type=int,
        default=0,
        help="每次轮询最多处理的数据包数（0=不限制，调试用）",
    )

    return parser.parse_args()


def main() -> None:
    """主入口函数。"""
    args = _parse_args()

    # 构建配置 — 仅传入用户在 CLI/环境变量中显式指定的值，其余用 DatabaseConfig 默认值
    db_kwargs: Dict[str, Any] = {}
    if args.db_host is not None:
        db_kwargs["host"] = args.db_host
    if args.db_port is not None:
        db_kwargs["port"] = args.db_port
    if args.db_user is not None:
        db_kwargs["user"] = args.db_user
    if args.db_password is not None:
        db_kwargs["password"] = args.db_password
    if args.db_name is not None:
        db_kwargs["database"] = args.db_name
    db_config = DatabaseConfig(**db_kwargs)

    monitor_config = MonitorConfig(
        target_host=args.target,
        db=db_config,
        write_interval=args.interval,
        flow_timeout=args.flow_timeout,
        capture_interface=args.interface,
        log_path=args.log_path,
        packet_sample_limit=args.sample_limit,
    )

    # 创建并启动监控器
    monitor = TrafficMonitor(monitor_config)

    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\n用户中断，程序退出。")
        sys.exit(0)
    except Exception as e:
        logger = logging.getLogger("traffic_monitor")
        logger.critical("监控器异常退出: %s", e, exc_info=True)
        print(f"\n[FATAL] {e}")
        sys.exit(1)


# ============================================================================
# __main__
# ============================================================================

if __name__ == "__main__":
    main()
