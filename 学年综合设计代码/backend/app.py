"""
Flask 主入口 —— 基于 AI 的网络入侵检测与安全预警系统

启动方式:
    cd backend
    python app.py

服务运行在 http://localhost:8080
"""
import sys
import os
import io

# ===== Windows GBK 编码兼容 =====
# 让控制台支持 emoji 和中文输出
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 确保 backend 目录在 Python 路径中，方便导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from flask_cors import CORS
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

# 导入各蓝图
from routes.auth_bp import auth_bp
from routes.traffic_bp import traffic_bp
from routes.dashboard_bp import dashboard_bp
from routes.firewall_bp import firewall_bp


def create_app():
    app = Flask(__name__)

    # ── CORS 跨域配置 ──────────────────────────────────
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    # ── 注册蓝图 ───────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(firewall_bp)

    # ── 根路径 ─────────────────────────────────────────
    @app.route('/')
    def index():
        return {
            'service': 'AI 网络入侵检测与安全预警系统',
            'version': '1.0.0',
            'docs': '请查看项目 README 获取接口文档',
        }

    # ── 全局错误处理 ───────────────────────────────────
    @app.errorhandler(404)
    def handle_404(e):
        return {'code': 404, 'msg': '接口不存在', 'data': None}, 404

    @app.errorhandler(405)
    def handle_405(e):
        return {'code': 405, 'msg': '请求方法不允许', 'data': None}, 405

    @app.errorhandler(500)
    def handle_500(e):
        return {'code': 500, 'msg': '服务器内部错误', 'data': None}, 500

    return app


if __name__ == '__main__':
    app = create_app()

    print('=' * 60)
    print('  🛡️  AI 网络入侵检测与安全预警系统 - 后端服务')
    print(f'  地址: http://localhost:{FLASK_PORT}')
    print('  接口前缀: /api/v1/')
    print('=' * 60)
    print()
    print('  已注册接口:')
    print('    POST /api/v1/auth/login         用户登录')
    print('    POST /api/v1/auth/register      用户注册')
    print('    POST /api/v1/traffic/save       AI 写入检测日志')
    print('    GET  /api/v1/dashboard/overview 总览统计')
    print('    GET  /api/v1/dashboard/trend    趋势数据')
    print('    GET  /api/v1/dashboard/attack-types  攻击类型分布')
    print('    GET  /api/v1/dashboard/logs     攻击日志分页')
    print('    POST /api/v1/firewall/ban       IP 一键封禁')
    print()
    print('=' * 60)

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
