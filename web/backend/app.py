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

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

# 导入各蓝图
from routes.auth_bp import auth_bp
from routes.traffic_bp import traffic_bp
from routes.dashboard_bp import dashboard_bp
from routes.firewall_bp import firewall_bp


def _check_ip_banned():
    """
    封禁检查 —— 每次请求前从 banned_ips 表查询客户端IP，
    命中则返回 403 阻止访问。
    白名单: 本地地址 127.0.0.1 / localhost / ::1 不检查。
    """
    client_ip = (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        or request.headers.get('X-Real-IP', '').strip()
        or request.remote_addr
        or ''
    )
    # 本地请求放行
    if client_ip in ('127.0.0.1', 'localhost', '::1'):
        return None

    try:
        import pymysql
        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM banned_ips WHERE ip_address = %s", (client_ip,))
                if cur.fetchone():
                    return jsonify({
                        'code': 403,
                        'msg': f'您的IP({client_ip})已被系统封禁，禁止访问',
                        'data': None,
                    }), 403
        finally:
            conn.close()
    except Exception:
        pass  # DB不可用时降级放行，不影响正常服务

    return None


# 数据库配置（与 config.py 一致，供封禁检查使用）
from config import DB_CONFIG


def create_app():
    # ── 静态文件目录 ────────────────────────────────────
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # 管理后台前端页面 (admin.html, login.html, register.html, user.html)
    front_dir = os.path.join(base_dir, '..', 'front')
    # 靶机测试网站 (index.html, style.css, script.js 等)
    target_dir = os.path.join(base_dir, '..', 'test_website')

    app = Flask(__name__)

    # ── CORS 跨域配置 ──────────────────────────────────
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    # ── IP 封禁拦截（每次请求前自动检查 banned_ips 表）────
    @app.before_request
    def ban_check():
        block = _check_ip_banned()
        if block is not None:
            return block

    # ── 注册蓝图 ───────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(firewall_bp)

    # ── 前端页面路由 ───────────────────────────────────
    @app.route('/')
    def index():
        """首页 —— 靶机测试网站"""
        return send_from_directory(target_dir, 'index.html')

    @app.route('/api')
    def api_info():
        return {
            'service': 'AI 网络入侵检测与安全预警系统',
            'version': '1.0.0',
            'docs': '请查看项目 README 获取接口文档',
        }

    # ── 靶机静态文件（CSS/JS/图片等） ──────────────────
    @app.route('/<path:filename>')
    def serve_target_files(filename):
        """优先从管理前端找，找不到再从靶机目录找"""
        # 跳过 API 路由
        if filename.startswith('api/'):
            from flask import abort
            abort(404)

        # 先尝试 front 目录
        front_path = os.path.join(front_dir, filename)
        if os.path.isfile(front_path):
            return send_from_directory(front_dir, filename)

        # 再尝试靶机 test_website 目录
        target_path = os.path.join(target_dir, filename)
        if os.path.isfile(target_path):
            return send_from_directory(target_dir, filename)

        from flask import abort
        abort(404)

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
    print('  🛡️  AI 网络入侵检测与安全预警系统')
    print(f'  地址: http://localhost:{FLASK_PORT}')
    print('=' * 60)
    print()
    print('  前端页面:')
    print('    GET  /                          靶机测试网站首页')
    print('    GET  /login.html                管理后台登录页')
    print('    GET  /admin.html                管理员控制台')
    print('    GET  /register.html             注册页')
    print('    GET  /user.html                 用户仪表板')
    print('    GET  /index.html                靶机静态首页')
    print()
    print('  API 接口 (前缀 /api/v1/):')
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
