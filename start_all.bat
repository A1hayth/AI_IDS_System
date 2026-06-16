@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================================
echo   AI-IDS 一键启动 — 全部后端服务
echo ================================================================
echo.
echo   即将启动:
echo     [1] Flask API 后端      http://localhost:8080
echo     [2] 测试网站服务器        http://localhost:8081
echo.
echo   关闭此窗口即可停止全部服务
echo ================================================================
echo.

:: 启动 Flask API 后端（在 backend 目录下运行）
echo  启动 [1] Flask API 后端...
start "AI-IDS Flask API" cmd /c "cd /d "%~dp0backend" && python app.py"

:: 稍等避免端口冲突
timeout /t 1 /nobreak >nul

:: 启动测试网站服务器（在 test_website 目录下运行）
echo  启动 [2] 测试网站服务器...
start "AI-IDS Test Website" cmd /c "cd /d "%~dp0test_website" && python server.py"

echo.
echo ================================================================
echo   全部服务已启动！
echo.
echo   Flask API:      http://localhost:8080
echo   测试网站:         http://localhost:8081
echo.
echo   关闭那两个窗口或关闭本窗口停止服务
echo ================================================================

pause
