@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ================================================================
echo   AI-IDS 一键启动 — 全部后端服务
echo ================================================================
echo.
echo   项目目录: %~dp0
echo.
echo   即将启动:
echo     [1] Flask API 后端      http://localhost:8080
echo     [2] 测试网站服务器        http://localhost:8081
echo.
echo   关闭那两个服务窗口即可停止服务
echo ================================================================

:: ── 检查 Python ──────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [错误] 未找到 Python！
    echo   请先安装 Python 3.8+: https://www.python.org/downloads/
    echo   安装时勾选 "Add Python to PATH"
    pause
    exit /b 1
)

:: ── 自动安装依赖 ────────────────────────────────
echo.
echo   [检查] 正在检查依赖...
pip show Flask >nul 2>&1
if %errorlevel% neq 0 (
    echo   [安装] 正在安装后端依赖 (Flask, flask-cors, PyMySQL)...
    pip install Flask flask-cors PyMySQL
    if %errorlevel% neq 0 (
        echo   [警告] 依赖安装失败，请手动执行: pip install -r web\backend\requirements.txt
    )
)
echo   [检查] 依赖就绪
echo.

:: ── 启动服务 ────────────────────────────────────
echo   [启动] Flask API 后端 (端口 8080)...
start "AI-IDS Flask API" cmd /c "cd /d "%~dp0web\backend" && title AI-IDS Flask API - :8080 && python app.py"

timeout /t 2 /nobreak >nul

echo   [启动] 测试网站服务器 (端口 8081)...
start "AI-IDS Test Website" cmd /c "cd /d "%~dp0web\test_website" && title AI-IDS Test Website - :8081 && python server.py"

echo.
echo ================================================================
echo   🟢 全部服务已启动！
echo.
echo   Flask API:      http://localhost:8080
echo   测试网站:         http://localhost:8081
echo.
echo   按任意键退出本窗口（服务窗口会保持运行）
echo ================================================================

pause
