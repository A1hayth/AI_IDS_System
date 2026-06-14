"""
测试流量生成器 — 向目标网站发送多样化 HTTP 请求，供 traffic_monitor 采集。

产生流量类型:
    - 正常浏览（GET 首页/CSS/JS/图片）
    - POST 表单提交
    - SQL 注入探测
    - XSS 探测
    - 路径扫描
    - 异常 User-Agent

用法:
    python generate_test_traffic.py                          # 默认 www.example.com, 跑 1 轮
    python generate_test_traffic.py --target 192.168.1.100   # 自定义目标
    python generate_test_traffic.py --loop 60                # 每 60 秒循环一轮（后台运行）
    python generate_test_traffic.py --target www.baidu.com --count 5  # 5 轮
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# 请求模板
# ---------------------------------------------------------------------------

# 正常请求
NORMAL_REQUESTS: List[Dict[str, str]] = [
    {"method": "GET",  "path": "/",                        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"},
    {"method": "GET",  "path": "/index.html",               "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"},
    {"method": "GET",  "path": "/style.css",                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"},
    {"method": "GET",  "path": "/script.js",                "ua": "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"},
    {"method": "GET",  "path": "/favicon.ico",              "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"},
    {"method": "GET",  "path": "/images/logo.png",          "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"},
    {"method": "GET",  "path": "/api/status",               "ua": "python-requests/2.31.0"},
    {"method": "HEAD", "path": "/",                         "ua": "curl/8.4.0"},
    {"method": "POST", "path": "/api/login",                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                       "body": "username=testuser&password=testpass123"},
    {"method": "POST", "path": "/search",                   "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
                       "body": "q=hello+world&page=1"},
]

# SQL 注入探测（用于测试 IDS 检测能力）
SQLI_REQUESTS: List[Dict[str, str]] = [
    {"method": "GET",  "path": "/?id=1' OR '1'='1",       "ua": "sqlmap/1.7.10#stable"},
    {"method": "GET",  "path": "/products.php?id=1 UNION SELECT NULL--", "ua": "Mozilla/5.0"},
    {"method": "POST", "path": "/login",                    "ua": "sqlmap/1.7.10#stable",
                       "body": "user=admin'--&pass=xyz"},
    {"method": "GET",  "path": "/?id=1 AND SLEEP(5)",      "ua": "Mozilla/5.0"},
    {"method": "GET",  "path": "/items.php?id=1' AND 1=1--", "ua": "sqlmap/1.7.10#stable"},
]

# XSS 探测
XSS_REQUESTS: List[Dict[str, str]] = [
    {"method": "GET",  "path": "/?q=<script>alert(1)</script>",  "ua": "Mozilla/5.0"},
    {"method": "POST", "path": "/comment",                        "ua": "Mozilla/5.0",
                       "body": "text=<img src=x onerror=alert('XSS')>"},
    {"method": "GET",  "path": "/search?q=<svg/onload=alert(1)>", "ua": "Mozilla/5.0"},
]

# 路径扫描
SCAN_REQUESTS: List[Dict[str, str]] = [
    {"method": "GET", "path": "/admin",              "ua": "dirbuster/1.0"},
    {"method": "GET", "path": "/wp-admin",           "ua": "dirbuster/1.0"},
    {"method": "GET", "path": "/.env",               "ua": "python-requests/2.31.0"},
    {"method": "GET", "path": "/phpmyadmin",         "ua": "dirbuster/1.0"},
    {"method": "GET", "path": "/.git/config",        "ua": "python-requests/2.31.0"},
    {"method": "GET", "path": "/backup.zip",         "ua": "Wget/1.21"},
    {"method": "GET", "path": "/config.php.bak",     "ua": "python-requests/2.31.0"},
]


# ============================================================================
# 请求发送
# ============================================================================

def _build_url(base_url: str, path: str) -> str:
    """拼接 URL，处理首尾斜杠。"""
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    return base + p


def send_request(
    target: str,
    port: int,
    method: str,
    path: str,
    user_agent: str,
    body: Optional[str] = None,
    timeout: float = 5.0,
) -> Tuple[int, float]:
    """发送单个 HTTP 请求。

    Returns:
        (status_code, elapsed_seconds)，失败时状态码为 0。
    """
    url = _build_url(f"http://{target}:{port}", path)
    data = body.encode("utf-8") if body else None

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        },
        method=method,
    )

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read()  # 确保完整读取，触发完整 TCP 会话
            elapsed = time.time() - start
            return (resp.status, round(elapsed, 4))
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        return (e.code, round(elapsed, 4))
    except Exception:
        elapsed = time.time() - start
        return (0, round(elapsed, 4))


# ============================================================================
# 流量生成器
# ============================================================================

class TrafficGenerator:
    """测试流量生成器。

    使用线程池并发发送请求，模拟真实多会话场景。
    """

    def __init__(
        self,
        target: str = "www.example.com",
        port: int = 80,
        concurrency: int = 5,
        request_delay: float = 0.05,
    ) -> None:
        self.target = target
        self.port = port
        self.concurrency = concurrency
        self.request_delay = request_delay

        # 统计
        self.total_sent: int = 0
        self.total_ok: int = 0
        self.total_fail: int = 0

    # ---- 单轮流量 ----------------------------------------------------------

    def run_round(self, include_attacks: bool = True) -> Dict[str, int]:
        """执行一轮完整流量（正常 + 异常混合）。

        Args:
            include_attacks: 是否包含攻击探测流量。

        Returns:
            {sent, ok, fail} 统计字典。
        """
        # 构建请求列表
        all_requests: List[Tuple[str, Dict[str, str]]] = []

        # 正常流量（占多数）
        for req in NORMAL_REQUESTS:
            all_requests.append(("normal", req))

        # 攻击流量（约占 1/3）
        if include_attacks:
            # 随机挑选部分攻击流量，模拟真实场景中攻击占比
            selected_sqli = random.sample(SQLI_REQUESTS, min(3, len(SQLI_REQUESTS)))
            selected_xss = random.sample(XSS_REQUESTS, min(2, len(XSS_REQUESTS)))
            selected_scan = random.sample(SCAN_REQUESTS, min(3, len(SCAN_REQUESTS)))

            for req in selected_sqli:
                all_requests.append(("sqli", req))
            for req in selected_xss:
                all_requests.append(("xss", req))
            for req in selected_scan:
                all_requests.append(("scan", req))

        # 打乱顺序（避免规律性）
        random.shuffle(all_requests)

        round_sent = 0
        round_ok = 0
        round_fail = 0

        print(f"\n{'='*60}")
        print(f"  Traffic Generator — {len(all_requests)} 个请求")
        print(f"  目标: {self.target}:{self.port}")
        print(f"  并发: {self.concurrency} | 含攻击流量: {include_attacks}")
        print(f"{'='*60}\n")

        # 并发发送
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {}
            for idx, (category, req) in enumerate(all_requests):
                # 错开发送时间
                time.sleep(self.request_delay)

                future = executor.submit(
                    send_request,
                    self.target,
                    self.port,
                    req["method"],
                    req["path"],
                    req.get("ua", "Mozilla/5.0"),
                    req.get("body"),
                )
                futures[future] = (idx + 1, category, req)

            # 收集结果
            for future in as_completed(futures):
                idx, cat, req = futures[future]
                try:
                    status, elapsed = future.result()
                except Exception:
                    status, elapsed = 0, 0.0

                round_sent += 1
                if 200 <= status < 500:
                    round_ok += 1
                else:
                    round_fail += 1

                # 标记攻击流量
                attack_marker = {
                    "sqli": " [SQLi]",
                    "xss":  " [XSS]",
                    "scan": " [SCAN]",
                }.get(cat, "")

                print(
                    f"  [{idx:>3}/{len(all_requests)}] "
                    f"{req['method']:<6} {req['path']:<45} "
                    f"→ {status} {elapsed:.3f}s{attack_marker}"
                )

        self.total_sent += round_sent
        self.total_ok += round_ok
        self.total_fail += round_fail

        return {"sent": round_sent, "ok": round_ok, "fail": round_fail}

    # ---- 循环模式 ----------------------------------------------------------

    def run_loop(
        self,
        interval: float = 60.0,
        rounds: int = 0,
        include_attacks: bool = True,
    ) -> None:
        """循环生成流量。

        Args:
            interval: 每轮间隔（秒）。
            rounds: 总轮数，0 表示无限循环。
            include_attacks: 是否包含攻击流量。
        """
        round_num = 0

        print(f"\n  循环模式: 每 {interval:.0f}s 一轮 | 轮数: {'∞' if rounds == 0 else rounds}")
        print(f"  (按 Ctrl+C 停止)\n")

        try:
            while rounds == 0 or round_num < rounds:
                round_num += 1
                print(f"\n  ── 第 {round_num} 轮 ──")

                result = self.run_round(include_attacks=include_attacks)

                print(f"\n  ✅ 第 {round_num} 轮完成: {result['sent']} 请求, "
                      f"{result['ok']} 成功, {result['fail']} 失败")
                print(f"  📊 累计: {self.total_sent} 请求, "
                      f"{self.total_ok} 成功, {self.total_fail} 失败")

                if rounds == 0 or round_num < rounds:
                    print(f"  ⏳ 等待 {interval:.0f}s 进入下一轮...")
                    time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n\n  ⏹  用户中断")
            print(f"  📊 最终统计: {self.total_sent} 请求, "
                  f"{self.total_ok} 成功, {self.total_fail} 失败")


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-IDS 测试流量生成器 — 向目标网站发送多样化请求",
    )
    parser.add_argument(
        "--target", "-t",
        default="www.example.com",
        help="目标主机（默认: www.example.com）",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=80,
        help="目标端口（默认: 80）",
    )
    parser.add_argument(
        "--loop", "-l",
        type=float,
        default=0,
        help="循环模式，N 秒一轮（0=单轮模式）",
    )
    parser.add_argument(
        "--rounds", "-n",
        type=int,
        default=0,
        help="循环轮数（0=无限，仅 --loop >0 时有效）",
    )
    parser.add_argument(
        "--no-attacks",
        action="store_true",
        help="不包含攻击流量（仅正常请求）",
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=5,
        help="并发连接数（默认: 5）",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=0.05,
        help="请求间延迟秒数（默认: 0.05）",
    )

    args = parser.parse_args()

    gen = TrafficGenerator(
        target=args.target,
        port=args.port,
        concurrency=args.concurrency,
        request_delay=args.delay,
    )

    if args.loop > 0:
        gen.run_loop(
            interval=args.loop,
            rounds=args.rounds,
            include_attacks=not args.no_attacks,
        )
    else:
        result = gen.run_round(include_attacks=not args.no_attacks)
        print(f"\n✅ 完成: {result['sent']} 请求, {result['ok']} 成功, {result['fail']} 失败")


if __name__ == "__main__":
    main()
