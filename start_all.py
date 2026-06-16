"""
一键启动 AI-IDS 全部后端服务

启动:
    python start_all.py

会同时启动:
    1. Flask API 后端 (web/backend/app.py)   → http://localhost:8080
    2. 测试网站服务器 (web/test_website/server.py) → http://localhost:8081

按 Ctrl+C 停止全部服务。
"""

import subprocess
import sys
import os
import time
import platform
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"

# ── 路径：脚本在项目根目录，服务在 web/ 下 ──────────────────
PROJECT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_DIR / "web" / "backend"
TEST_SITE_DIR = PROJECT_DIR / "web" / "test_website"

processes: list[subprocess.Popen] = []


# ============================================================================
# 启动前检查
# ============================================================================

def check_python_version() -> bool:
    """检查 Python 版本 >= 3.8。"""
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 8):
        print(f"❌ Python 版本过低: {major}.{minor}，需要 >= 3.8")
        print("   下载: https://www.python.org/downloads/")
        return False
    return True


def ensure_dependencies() -> bool:
    """检查并自动安装 Flask 后端所需依赖。"""
    required = {
        "flask": "Flask",
        "flask_cors": "flask-cors",
        "pymysql": "PyMySQL",
    }
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if not missing:
        return True

    print(f"⚠️  缺少依赖: {', '.join(missing)}，正在自动安装...")
    print()
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install"] + missing,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        print("\n✅ 依赖安装完成\n")
        return True
    except subprocess.CalledProcessError:
        print(f"\n❌ 自动安装失败，请手动执行:")
        print(f"   pip install {' '.join(missing)}")
        return False


def check_dirs() -> bool:
    """检查子目录是否存在。"""
    ok = True
    for d, name in [(BACKEND_DIR, "web/backend"), (TEST_SITE_DIR, "web/test_website")]:
        if not d.is_dir():
            print(f"❌ 目录不存在: {d}")
            ok = False
    if not ok:
        print("   请确保在项目根目录下运行此脚本")
    return ok


def check_mysql_config() -> bool:
    """检查 MySQL 配置是否可用（只检查 connectivity，不强制要求）。"""
    try:
        import pymysql
        from config import DB_CONFIG

        pymysql.connect(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=DB_CONFIG["database"],
            connect_timeout=3,
        ).close()
        print("✅ MySQL 连接正常")
        return True
    except ImportError:
        print("⚠️  pymysql 未安装，跳过 MySQL 检查")
        return True  # 不阻塞，依赖上一步已安装
    except Exception as e:
        print(f"⚠️  MySQL 连接失败: {e}")
        print(f"   请确保 MySQL 已启动，并检查 web/backend/config.py 中的 DB_CONFIG")
        print(f"   当前配置: host={DB_CONFIG.get('host')}, "
              f"port={DB_CONFIG.get('port')}, "
              f"user={DB_CONFIG.get('user')}")
        print("   (如果暂时没有 MySQL，Falsk API 的数据库相关接口将不可用)")
        print()
        return True  # 不阻塞启动，让用户看到错误但服务仍可启动


# ============================================================================
# 服务启动 / 停止
# ============================================================================

def launch(name: str, cwd: Path, script: str) -> subprocess.Popen | None:
    """启动一个子进程并返回 Popen 对象。"""
    args = [sys.executable, script]
    try:
        creationflags = 0
        if IS_WINDOWS:
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            args,
            cwd=str(cwd),
            stdout=sys.stdout,
            stderr=sys.stderr,
            creationflags=creationflags,
        )
        print(f"  ✅ [{name}] 已启动 (PID: {proc.pid})")
        return proc
    except FileNotFoundError:
        print(f"  ❌ [{name}] 找不到 Python 解释器，请尝试: python3 start_all.py")
        return None
    except Exception as e:
        print(f"  ❌ [{name}] 启动失败: {e}")
        return None


def stop_all():
    """停止所有子进程（跨平台兼容）。"""
    print("\n⏳ 正在停止全部服务...")
    for proc in processes:
        if proc and proc.poll() is None:
            try:
                if IS_WINDOWS:
                    import signal
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.terminate()
            except Exception:
                pass

    for proc in processes:
        if proc:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    print("🛑 全部服务已停止")


# ============================================================================
# 主流程
# ============================================================================

def main():
    # 切换到项目根目录
    os.chdir(str(PROJECT_DIR))

    print("=" * 62)
    print("  🛡️  AI-IDS 一键启动 — 全部后端服务")
    print("=" * 62)
    print(f"  项目目录: {PROJECT_DIR}")
    print(f"  系统平台: {platform.system()} {platform.release()}")
    print(f"  Python:   {sys.version.split()[0]}")
    print()
    print("  即将启动:")
    print(f"    [1] Flask API 后端     → http://localhost:8080")
    print(f"    [2] 测试网站服务器       → http://localhost:8081")
    print()
    print("=" * 62)
    print()

    # ── 前置检查 ──────────────────────────────────────
    print("🔍 环境检查...")
    if not check_python_version():
        sys.exit(1)
    if not check_dirs():
        sys.exit(1)
    if not ensure_dependencies():
        sys.exit(1)

    # MySQL 检查（失败不阻塞）
    sys.path.insert(0, str(BACKEND_DIR))
    check_mysql_config()

    print()
    print("━" * 62)

    # ── 启动 Flask API 后端 ────────────────────────────
    proc1 = launch("Flask API", cwd=BACKEND_DIR, script="app.py")
    if proc1:
        processes.append(proc1)

    time.sleep(1)

    # ── 启动测试网站服务器 ──────────────────────────────
    proc2 = launch("测试网站", cwd=TEST_SITE_DIR, script="server.py")
    if proc2:
        processes.append(proc2)

    if not processes:
        print("\n❌ 没有服务成功启动，退出。")
        sys.exit(1)

    print()
    print("━" * 62)
    print("  🟢 全部服务运行中")
    print(f"     Flask API:      http://localhost:8080")
    print(f"     测试网站:         http://localhost:8081")
    print("     按 Ctrl+C 停止全部服务")
    print("━" * 62)

    try:
        for proc in processes:
            proc.wait()
    except KeyboardInterrupt:
        stop_all()


if __name__ == "__main__":
    main()
