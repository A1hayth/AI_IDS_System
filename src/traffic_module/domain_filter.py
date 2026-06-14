"""
域名过滤模块 — 在 capture 回调中按目标域名过滤流量。

过滤策略：
    Tier 1 (BPF kernel):   目标域名 IP 注入 BPF → 内核级预过滤
    Tier 2 (HTTP Host):    双向服务端口 → 字节级扫描 Host 头匹配域名
    Tier 3 (TLS SNI):      双向服务端口 → 提取 TLS SNI 扩展匹配域名
    连接追踪:               批准后缓存四元组 → 双向后续包自动放行

设计约束：
    - 零外部依赖（仅标准库 socket / threading）
    - 线程安全（DNS 后台刷新 + 回调热路径并发读）
    - 回退兼容：空域名列表 → 不启用过滤，全量捕获
    - 本地 Web 服务器场景：连接追踪确保服务器响应包不丢失
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# 可配置参数
# ---------------------------------------------------------------------------

DNS_RESOLVE_TIMEOUT: float = 3.0
"""单个域名 DNS 解析超时（秒）。"""

DNS_CACHE_TTL: float = 300.0
"""DNS 缓存刷新周期（秒），默认 5 分钟。"""

DNS_INITIAL_RESOLVE_TIMEOUT: float = 10.0
"""首次批量 DNS 解析总超时（秒）。"""

MAX_BPF_IPS: int = 50
"""BPF 过滤器中最多包含的 IP 数量，防止表达式过长超出内核限制。"""

MAX_TLS_EXTENSION_SCAN: int = 8
"""TLS 扩展最大扫描数量（安全上限）。"""

MAX_SNI_LENGTH: int = 256
"""SNI 主机名最大长度（防止畸形包）。"""

CONNECTION_CACHE_TTL: float = 120.0
"""已批准连接的缓存有效期（秒），超时后需重新通过域名检查。
应与 TCP 连接超时保持同一量级，默认 2 分钟。"""

MAX_CONNECTION_CACHE: int = 5000
"""已批准连接缓存最大容量，超出时淘汰最旧记录。"""

SERVER_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8000, 8443})
"""HTTP/HTTPS 服务端口集合，用于双向端口匹配。"""

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------

_logger = logging.getLogger("domain_filter")
_logger.setLevel(logging.DEBUG)

# 不添加 handler，由 capture.py 统一管理日志输出
if not _logger.handlers:
    _logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class DomainEntry:
    """单个目标域名的 DNS 解析状态。"""

    domain: str
    """规范化后的域名（小写，去除端口，去除通配符前缀）。"""

    ips: Set[str] = field(default_factory=set)
    """已解析的 IP 地址集合。"""

    resolved_at: float = 0.0
    """最近一次解析时间戳（epoch）。"""

    resolve_error: Optional[str] = None
    """最近一次解析错误信息，成功时为 None。"""


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _normalize_domain(raw: str) -> str:
    """规范化域名输入。

    - 去除首尾空白
    - 转小写
    - 去除 ``*.`` 通配符前缀
    - 去除端口号（如 ``example.com:8080`` → ``example.com``）
    """
    domain = raw.strip().lower()
    # 去除 *. 通配符
    if domain.startswith("*."):
        domain = domain[2:]
    # 去除端口
    if ":" in domain and not domain.startswith("["):
        # 不以 [ 开头说明不是 IPv6，冒号是端口分隔符
        domain = domain.rsplit(":", 1)[0]
    return domain


def _hostname_matches(hostname: str, target_domain: str) -> bool:
    """检查主机名是否匹配目标域名（后缀匹配）。

    规则：
        - 完全相等 → 匹配
        - 以 ``.target_domain`` 结尾 → 匹配（子域名）
        - 否则不匹配

    示例：
        >>> _hostname_matches("example.com", "example.com")      # True
        >>> _hostname_matches("www.example.com", "example.com")  # True
        >>> _hostname_matches("api.v2.example.com", "example.com") # True
        >>> _hostname_matches("maliciousexample.com", "example.com") # False
    """
    if not hostname or not target_domain:
        return False
    hostname = hostname.lower().strip().rstrip(".")
    target = target_domain.lower().strip().rstrip(".")
    if hostname == target:
        return True
    if hostname.endswith("." + target):
        return True
    return False


# ---------------------------------------------------------------------------
# DomainFilter
# ---------------------------------------------------------------------------

class DomainFilter:
    """域名过滤器 — DNS 预解析 + HTTP Host + TLS SNI 三级检查。

    用法：
        df = DomainFilter(["example.com", "test.org"])
        # ...在 capture 回调中...
        if df.should_keep(packet):
            process(packet)
        # ...获取 BPF 扩展...
        extension = df.build_bpf_extension()
        # ...停止时...
        df.shutdown()
    """

    def __init__(self, domains: List[str]) -> None:
        """初始化过滤器，执行首次 DNS 解析并启动后台刷新线程。

        Args:
            domains: 目标域名列表。空列表将导致 ``should_keep`` 始终返回 True。
        """
        # 规范化并去重
        normalized: List[str] = []
        seen: Set[str] = set()
        for raw in domains:
            d = _normalize_domain(raw)
            if d and d not in seen:
                normalized.append(d)
                seen.add(d)

        self._domains = normalized
        self._entries: Dict[str, DomainEntry] = {}
        self._lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._refresh_thread: Optional[threading.Thread] = None

        # 连接追踪：批准后同一连接的双向包自动放行
        self._conn_cache: Dict[tuple, float] = {}  # conn_key → expiry_time
        self._conn_cache_lock = threading.Lock()

        # 初始化条目
        for domain in self._domains:
            self._entries[domain] = DomainEntry(domain=domain)

        # 首次 DNS 解析（阻塞，有总超时控制）
        if self._domains:
            self._resolve_all(initial=True)
            # 启动后台 DNS 刷新线程
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop,
                daemon=True,
                name="domain-filter-dns-refresh",
            )
            self._refresh_thread.start()
            _logger.info(
                "域名过滤器已初始化 | domains=%d | total_ips=%d",
                len(self._domains),
                self.ip_count(),
            )

    # ---- DNS 解析 ----------------------------------------------------------

    def _resolve_domain(self, domain: str) -> Set[str]:
        """解析单个域名，返回 IP 集合（通过 socket 超时控制）。"""
        ips: Set[str] = set()
        error_msg: Optional[str] = None

        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(DNS_RESOLVE_TIMEOUT)
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    addrinfo = socket.getaddrinfo(
                        domain, None, family=family, type=socket.SOCK_STREAM
                    )
                    for item in addrinfo:
                        ips.add(item[4][0])
                except socket.gaierror:
                    continue
                except socket.timeout:
                    if not ips:
                        error_msg = f"timeout ({DNS_RESOLVE_TIMEOUT}s)"
                    break
                except OSError:
                    continue
        except Exception as exc:
            error_msg = str(exc)
        finally:
            socket.setdefaulttimeout(old_timeout)

        with self._lock:
            entry = self._entries.get(domain)
            if entry:
                if error_msg and not ips:
                    entry.resolve_error = error_msg
                elif ips:
                    entry.resolve_error = None
                elif not ips and not entry.resolve_error:
                    entry.resolve_error = "no addresses found"

        if not ips and error_msg:
            _logger.warning("DNS 解析未获取 IP | domain=%s | error=%s", domain, error_msg)

        return ips

    def _resolve_all(self, initial: bool = False) -> None:
        """批量解析所有域名。

        Args:
            initial: True 表示首次解析，受 ``DNS_INITIAL_RESOLVE_TIMEOUT`` 限制。
        """
        deadline = time.time() + (
            DNS_INITIAL_RESOLVE_TIMEOUT if initial else DNS_CACHE_TTL
        )
        for domain in self._domains:
            if time.time() > deadline:
                _logger.warning(
                    "DNS 解析超时，已跳过剩余域名 | resolved=%d/%d",
                    sum(1 for e in self._entries.values() if e.ips),
                    len(self._domains),
                )
                break
            ips = self._resolve_domain(domain)
            with self._lock:
                entry = self._entries.get(domain)
                if entry:
                    entry.ips = ips
                    entry.resolved_at = time.time()
            if ips:
                _logger.debug("DNS 解析成功 | domain=%s | ips=%s", domain, ips)

    def _refresh_loop(self) -> None:
        """后台 DNS 刷新循环。"""
        _logger.debug("DNS 刷新线程已启动 | interval=%ss", DNS_CACHE_TTL)
        while not self._shutdown_event.wait(DNS_CACHE_TTL):
            _logger.debug("DNS 缓存刷新中…")
            self._resolve_all(initial=False)

    # ---- BPF 扩展 -----------------------------------------------------------

    def build_bpf_extension(self) -> str:
        """生成 BPF 过滤器扩展片段。

        将已解析的所有目标域名 IP 组合为 ``(host ip1 or host ip2 or ...)``。
        最多包含 ``MAX_BPF_IPS`` 个 IP。

        Returns:
            BPF 片段字符串，如 ``"(host 1.2.3.4 or host 5.6.7.8)"``。
            无可用 IP 时返回空字符串。
        """
        all_ips: List[str] = []
        with self._lock:
            for entry in self._entries.values():
                all_ips.extend(entry.ips)

        if not all_ips:
            return ""

        # 截断到上限
        if len(all_ips) > MAX_BPF_IPS:
            _logger.warning(
                "BPF IP 数量超过上限 | total=%d | capped=%d",
                len(all_ips),
                MAX_BPF_IPS,
            )
            all_ips = all_ips[:MAX_BPF_IPS]

        clauses = " or ".join(f"host {ip}" for ip in all_ips)
        return f"({clauses})"

    # ---- HTTP Host 检测 -----------------------------------------------------

    def _check_http_host(self, raw_load: bytes) -> bool:
        """字节级扫描 HTTP Host 头，匹配目标域名。

        不进行完整 HTTP 解析 — 仅搜索 ``Host:`` 头部字段。
        """
        if not raw_load or len(raw_load) < 6:
            return False

        # 小写化以支持大小写不敏感匹配
        lowered = raw_load.lower()

        # 查找 "host:" 标记
        idx = lowered.find(b"host:")
        if idx < 0:
            return False

        # 跳过 "host:" 和后续空白
        idx += 5  # len(b"host:")
        while idx < len(lowered) and lowered[idx : idx + 1] in (b" ", b"\t"):
            idx += 1

        if idx >= len(lowered):
            return False

        # 提取主机名字节直到遇到 \r, \n, :, 空格
        end = idx
        while end < len(lowered):
            byte = lowered[end : end + 1]
            if byte in (b"\r", b"\n", b" ", b"\t"):
                break
            if byte == b":":
                # 冒号可能是端口分隔符，停止
                break
            end += 1

        if end == idx:
            return False

        try:
            hostname = lowered[idx:end].decode("ascii", errors="replace").strip()
        except Exception:
            return False

        if not hostname:
            return False

        # 后缀匹配所有目标域名
        for domain in self._domains:
            if _hostname_matches(hostname, domain):
                _logger.debug("HTTP Host 匹配 | hostname=%s | domain=%s", hostname, domain)
                return True

        return False

    # ---- TLS SNI 检测 -------------------------------------------------------

    def _check_tls_sni(self, raw_load: bytes) -> bool:
        """从 TLS ClientHello 中提取 SNI 主机名并匹配目标域名。

        TLS Record 格式 (RFC 5246):
            byte 0:     content_type (0x16 = Handshake)
            bytes 1-2:  version
            bytes 3-4:  length (uint16 big-endian)

        TLS Handshake (ClientHello):
            byte 5:     handshake_type (0x01 = ClientHello)
            bytes 6-8:  length (3-byte big-endian)
            bytes 9-10: version
            bytes 11-42: random (32 bytes)
            byte 43:    session_id_length
            ... session_id ...
            ... cipher_suites ...
            ... compression_methods ...
            ... extensions ...
                type=0x0000 → SNI
        """
        _MIN_LEN = 44  # TLS record(5) + handshake header(4) + version(2) + random(32) + session_id_len(1)
        if not raw_load or len(raw_load) < _MIN_LEN:
            return False

        try:
            # ---- TLS Record 验证 ----
            if raw_load[0] != 0x16:  # ContentType: Handshake
                return False

            # ---- Handshake 验证 ----
            if raw_load[5] != 0x01:  # HandshakeType: ClientHello
                return False

            # ---- 跳过 Session ID ----
            session_id_len = raw_load[43]
            pos = 44 + session_id_len

            if pos + 2 > len(raw_load):
                return False

            # ---- 跳过 Cipher Suites ----
            cipher_suites_len = int.from_bytes(raw_load[pos : pos + 2], "big")
            pos += 2 + cipher_suites_len

            if pos + 1 > len(raw_load):
                return False

            # ---- 跳过 Compression Methods ----
            compression_len = raw_load[pos]
            pos += 1 + compression_len

            if pos + 2 > len(raw_load):
                return False

            # ---- 读取 Extensions ----
            extensions_len = int.from_bytes(raw_load[pos : pos + 2], "big")
            pos += 2
            extensions_end = pos + extensions_len
            if extensions_end > len(raw_load):
                extensions_end = len(raw_load)

            scanned = 0
            while pos + 4 <= extensions_end and scanned < MAX_TLS_EXTENSION_SCAN:
                scanned += 1
                ext_type = int.from_bytes(raw_load[pos : pos + 2], "big")
                ext_len = int.from_bytes(raw_load[pos + 2 : pos + 4], "big")
                pos += 4

                if ext_type == 0x0000:  # SNI extension
                    if pos + 2 > extensions_end:
                        return False
                    # Server Name List
                    sni_list_len = int.from_bytes(raw_load[pos : pos + 2], "big")
                    pos += 2
                    sni_list_end = pos + sni_list_len
                    if sni_list_end > extensions_end:
                        return False

                    # 遍历 Server Name 条目
                    while pos + 3 <= sni_list_end:
                        name_type = raw_load[pos]
                        name_len = int.from_bytes(raw_load[pos + 1 : pos + 3], "big")
                        pos += 3
                        if name_len <= 0 or pos + name_len > sni_list_end:
                            break
                        if name_type == 0x00:  # hostname
                            if name_len > MAX_SNI_LENGTH:
                                break
                            try:
                                sni_hostname = raw_load[pos : pos + name_len].decode(
                                    "ascii", errors="replace"
                                ).strip().lower()
                            except Exception:
                                break
                            if sni_hostname:
                                for domain in self._domains:
                                    if _hostname_matches(sni_hostname, domain):
                                        _logger.debug(
                                            "TLS SNI 匹配 | sni=%s | domain=%s",
                                            sni_hostname,
                                            domain,
                                        )
                                        return True
                            return False  # SNI 找到了但不匹配目标域名
                        pos += name_len
                    return False  # SNI 扩展中没有 hostname 条目

                else:
                    # 跳过非 SNI 扩展
                    pos += ext_len

        except Exception:
            _logger.debug("TLS SNI 解析异常", exc_info=True)

        return False

    # ---- 连接追踪（双向自动放行）----------------------------------------------

    @staticmethod
    def _make_conn_key(
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        protocol: int,
    ) -> tuple:
        """构造双向归一化连接键。

        通过排序 IP 和端口对，使得 A→B 与 B→A 映射到同一 key。
        与 ``feature_extractor.make_flow_key`` 一致。
        """
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)

    def _conn_cache_lookup(self, conn_key: tuple) -> bool:
        """查询连接缓存（带过期淘汰）。"""
        with self._conn_cache_lock:
            if conn_key in self._conn_cache:
                expiry = self._conn_cache[conn_key]
                if time.time() < expiry:
                    return True
                # 过期，清理
                del self._conn_cache[conn_key]
            return False

    def _conn_cache_add(self, conn_key: tuple) -> None:
        """将连接加入缓存。"""
        with self._conn_cache_lock:
            # 容量控制：先淘汰最旧的
            if len(self._conn_cache) >= MAX_CONNECTION_CACHE:
                now = time.time()
                stale = [k for k, v in self._conn_cache.items() if v <= now]
                for k in stale:
                    del self._conn_cache[k]
                # 如果还不够，淘汰最先到期的一半
                if len(self._conn_cache) >= MAX_CONNECTION_CACHE:
                    sorted_keys = sorted(
                        self._conn_cache.keys(),
                        key=lambda k: self._conn_cache[k],
                    )
                    remove_count = max(1, len(sorted_keys) // 4)
                    for k in sorted_keys[:remove_count]:
                        del self._conn_cache[k]

            self._conn_cache[conn_key] = time.time() + CONNECTION_CACHE_TTL

    # ---- 主入口 -------------------------------------------------------------

    def should_keep(self, packet: Any) -> bool:
        """三级域名过滤 + 连接追踪入口。

        对于本地部署的 Web 服务器场景：
            1. 客户端→服务器 的 HTTP 请求通过 Host 头匹配
            2. 匹配成功后，双向四元组被缓存
            3. 服务器→客户端 的 HTTP 响应通过连接缓存自动放行
            4. TLS 连接同理，通过 SNI 匹配后整条连接放行

        Args:
            packet: Scapy Packet 对象。

        Returns:
            True → 保留数据包，False → 丢弃。
        """
        # 未配置域名 → 全量捕获
        if not self._domains:
            return True

        # 非 IP 包（如 ARP）放行
        if not packet.haslayer("IP"):
            return True

        # ---- 提取 IP + 端口信息 ----
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        sport: Optional[int] = None
        dport: Optional[int] = None
        proto_num: Optional[int] = None
        raw_load: Optional[bytes] = None

        try:
            ip_layer = packet["IP"]
            src_ip = getattr(ip_layer, "src", None)
            dst_ip = getattr(ip_layer, "dst", None)
            proto_num = getattr(ip_layer, "proto", None)
            if proto_num is not None:
                proto_num = int(proto_num)
        except Exception:
            return True  # 无法读取 IP 层则放行

        if packet.haslayer("TCP"):
            try:
                tcp_layer = packet["TCP"]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
            except (TypeError, ValueError):
                pass
        elif packet.haslayer("UDP"):
            try:
                udp_layer = packet["UDP"]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
            except (TypeError, ValueError):
                pass

        # ---- 连接缓存快速路径 ----
        if src_ip and dst_ip and sport is not None and dport is not None and proto_num is not None:
            conn_key = self._make_conn_key(src_ip, dst_ip, sport, dport, proto_num)
            if self._conn_cache_lookup(conn_key):
                return True  # 已批准连接，双向放行
        else:
            conn_key = None

        # ---- 提取 Raw 载荷 ----
        if packet.haslayer("Raw"):
            try:
                raw_load = bytes(packet["Raw"].load)
            except Exception:
                raw_load = None

        # ---- 域名检查 ----
        approved = False

        if raw_load and dport is not None and sport is not None:
            # HTTP 检测：客户端→服务器 (dport 是服务端口) 或 服务器→客户端但带有请求载荷
            if dport in SERVER_PORTS:
                if self._check_http_host(raw_load):
                    approved = True

            # 反向 HTTP 检测：如果本地服务器在 sport（即源端口=80），
            # 说明这是从其他服务器来的请求（对本地部署场景不太常见，但保留）
            elif sport in SERVER_PORTS and self._check_http_host(raw_load):
                approved = True

            # TLS 检测：TLS ClientHello 出现在客户端到服务器的方向
            if not approved and raw_load and len(raw_load) >= 6 and raw_load[0] == 0x16:
                if dport in SERVER_PORTS or sport in SERVER_PORTS:
                    if self._check_tls_sni(raw_load):
                        approved = True

        elif raw_load and dport is None and packet.haslayer("UDP"):
            # UDP + TLS（QUIC 等）
            if raw_load and len(raw_load) >= 6 and raw_load[0] == 0x16:
                if self._check_tls_sni(raw_load):
                    approved = True

        # ---- 决策 ----
        if approved:
            if conn_key is not None:
                self._conn_cache_add(conn_key)
            return True

        # 未命中域名检查 → 有载荷的包丢弃，无载荷的包放行（依赖 BPF IP 层过滤）
        # 注意：无载荷的包（SYN/ACK/FIN/RST）如果 IP 不在 BPF 中，
        # 则内核已经丢弃；到达这里的包在 IP 层面已经通过了 BPF 筛选
        if raw_load is None:
            # 控制包：如果 dport 或 sport 是服务端口，且连接可能在未来被批准，放行
            # 这是为了允许握手包建立连接，后续请求包会触发连接追踪
            if dport is not None and dport in SERVER_PORTS:
                return True
            if sport is not None and sport in SERVER_PORTS:
                return True
            # 其他无载荷包 → 放行（依赖 BPF IP 过滤）
            return True

        # 有载荷但与目标域名不匹配 → 丢弃
        return False

    # ---- 管理方法 -----------------------------------------------------------

    def shutdown(self) -> None:
        """停止 DNS 刷新线程，清理资源。"""
        if self._refresh_thread is None:
            return
        _logger.debug("正在停止 DNS 刷新线程…")
        self._shutdown_event.set()
        self._refresh_thread.join(timeout=2.0)
        _logger.debug("DNS 刷新线程已停止")
        self._refresh_thread = None

    def ip_count(self) -> int:
        """返回已解析的总 IP 数量。"""
        with self._lock:
            return sum(len(e.ips) for e in self._entries.values())

    def get_statistics(self) -> Dict[str, Any]:
        """返回每域名的解析状态统计 + 连接追踪状态。"""
        with self._lock:
            domains_stat = {}
            for domain, entry in self._entries.items():
                domains_stat[domain] = {
                    "ip_count": len(entry.ips),
                    "ips": sorted(entry.ips)[:20],  # 最多展示 20 个 IP
                    "resolved_at": (
                        time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(entry.resolved_at)
                        )
                        if entry.resolved_at > 0
                        else None
                    ),
                    "error": entry.resolve_error,
                }

        with self._conn_cache_lock:
            conn_count = len(self._conn_cache)
            now = time.time()
            active_conns = sum(1 for v in self._conn_cache.values() if v > now)

        return {
            "enabled": True,
            "total_domains": len(self._domains),
            "total_ips": self.ip_count(),
            "domains": domains_stat,
            "connection_cache": {
                "total": conn_count,
                "active": active_conns,
                "capacity": MAX_CONNECTION_CACHE,
                "ttl_seconds": CONNECTION_CACHE_TTL,
            },
        }
