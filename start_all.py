"""
一键启动 AI-IDS 全部后端服务

启动:
    python start_all.py

会同时启动:
    1. Flask API 后端 (app.py)     → http://localhost:8080
    2. 测试网站服务器 (server.py)   → http://localhost:8081

按 Ctrl+C 停止全部服务。
"""

import subprocess
import sys
import os
import time
import signal
import platform
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
BACKEND_DIR = WEB_DIR / "backend"
TEST_SITE_DIR = WEB_DIR / "test_website"

# 进程列表，用于统一管理
processes: list[subprocess.Popen] = []


def print_banner():
    print("=" * 62)
    print("  🛡️  AI-IDS 一键启动 — 全部后端服务")
    print("=" * 62)
    print(f"  项目目录: {WEB_DIR}")
    print()
    print("  即将启动:")
    print(f"    [1] Flask API 后端     → http://localhost:8080")
    print(f"    [2] 测试网站服务器       → http://localhost:8081")
    print()
    print("  按 Ctrl+C 停止全部服务")
    print("=" * 62)
    print()


def launch(name: str, cwd: Path, script: str, extra_args: list[str] | None = None) -> subprocess.Popen | None:
    """启动一个子进程并返回 Popen 对象。"""
    args = [sys.executable, script] + (extra_args or [])
    try:
        proc = subprocess.Popen(
            args,
            cwd=str(cwd),
            stdout=sys.stdout,
            stderr=sys.stderr,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0,
        )
        print(f"  ✅ [{name}] 已启动 (PID: {proc.pid})")
        return proc
    except Exception as e:
        print(f"  ❌ [{name}] 启动失败: {e}")
        return None


def stop_all():
    """停止所有子进程。"""
    print("\n⏳ 正在停止全部服务...")
    for proc in processes:
        if proc and proc.poll() is None:
            try:
                if platform.system() == "Windows":
                    # Windows: 发送 Ctrl+Break 事件
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.terminate()
            except Exception:
                pass

    # 等待进程退出
    for proc in processes:
        if proc:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    print("🛑 全部服务已停止")


def main():
    print_banner()

    # ── 启动 Flask API 后端 ──────────────────────────
    proc1 = launch(
        name="Flask API",
        cwd=BACKEND_DIR,
        script="app.py",
    )
    if proc1:
        processes.append(proc1)

    # 稍等，避免端口冲突
    time.sleep(0.5)

    # ── 启动测试网站服务器 ────────────────────────────
    proc2 = launch(
        name="测试网站",
        cwd=TEST_SITE_DIR,
        script="server.py",
    )
    if proc2:
        processes.append(proc2)

    if not processes:
        print("\n❌ 没有服务成功启动，退出。")
        sys.exit(1)

    print()
    print("━" * 62)
    print("  🟢 全部服务运行中，按 Ctrl+C 停止")
    print("━" * 62)

    # ── 等待 Ctrl+C ─────────────────────────────────
    try:
        for proc in processes:
            proc.wait()
    except KeyboardInterrupt:
        stop_all()
    except Exception:
        stop_all()


if __name__ == "__main__":
    main()
