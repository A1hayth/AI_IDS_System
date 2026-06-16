#!/usr/bin/env python3
"""
AI-IDS 测试网站服务器 — 纯 Python + stdlib，无需 Apache/PHP/phpStudy。

端点清单（与原 PHP 版完全一致）:
    GET  /                 首页 (index.php)
    GET  /index.html       静态首页
    GET  /style.css        样式表
    GET  /script.js        前端脚本
    GET  /favicon.ico      Favicon
    GET  /images/logo.png  Logo 图片
    GET  /products.php     产品列表
    GET  /items.php?id=N   商品详情
    GET  /search?q=xxx     搜索
    POST /search           搜索 (表单提交)
    GET  /login            登录表单
    POST /login            登录提交
    GET  /comment          评论表单
    POST /comment          评论提交
    GET  /admin            返回 403 Forbidden
    GET  /api/status       JSON 系统状态
    POST /api/login        JSON 登录 API

用法:
    python server.py                        # 默认监听 0.0.0.0:80（需管理员）
    python server.py --port 8080            # 指定其他端口
    python server.py --host 127.0.0.1       # 仅本地回环
    python server.py --port 8080 --no-auth  # 跳过管理员提示

测试:
    curl http://localhost/                  # 首页
    curl http://localhost/api/status        # JSON 状态
    curl -X POST -d "username=admin&password=admin123" http://localhost/api/login
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import secrets
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs


# ============================================================================
# 数据
# ============================================================================

PRODUCTS: List[Dict[str, Any]] = [
    {"id": 1, "name": "企业级防火墙",         "price": 29999, "stock": 15,
     "category": "网络安全", "desc": "下一代防火墙，支持深度包检测、应用识别、入侵防御。"},
    {"id": 2, "name": "入侵检测系统 IDS",      "price": 45999, "stock": 8,
     "category": "威胁检测", "desc": "基于 AI 的实时入侵检测系统，支持 CIC-IDS-2017 特征集。"},
    {"id": 3, "name": "安全审计平台",          "price": 18999, "stock": 22,
     "category": "合规审计", "desc": "全面的日志审计与合规检查平台，支持等保 2.0。"},
    {"id": 4, "name": "漏洞扫描器 Pro",        "price": 12999, "stock": 30,
     "category": "漏洞管理", "desc": "自动化漏洞扫描与风险评估工具，内置 10 万+ 漏洞规则。"},
    {"id": 5, "name": "日志分析引擎",          "price": 8999,  "stock": 0,
     "category": "数据分析", "desc": "海量日志实时分析引擎，支持自定义告警规则。"},
    {"id": 6, "name": "Web 应用防火墙 WAF",    "price": 35999, "stock": 5,
     "category": "Web 安全", "desc": "保护 Web 应用免受 OWASP Top 10 攻击。"},
    {"id": 7, "name": "威胁情报平台 TIP",      "price": 55999, "stock": 3,
     "category": "情报分析", "desc": "汇聚全球威胁情报，实时关联分析。"},
    {"id": 8, "name": "终端检测响应 EDR",      "price": 21999, "stock": 12,
     "category": "终端安全", "desc": "终端行为监控与自动响应。"},
]

PRODUCT_BY_ID: Dict[int, Dict[str, Any]] = {p["id"]: p for p in PRODUCTS}

# 搜索索引
SEARCH_INDEX: Dict[str, Dict[str, str]] = {
    "firewall":   {"title": "企业级防火墙",         "url": "/items.php?id=1", "snippet": "下一代防火墙..."},
    "ids":        {"title": "入侵检测系统 IDS",      "url": "/items.php?id=2", "snippet": "AI 驱动的实时检测..."},
    "audit":      {"title": "安全审计平台",          "url": "/items.php?id=3", "snippet": "等保 2.0 合规审计..."},
    "security":   {"title": "安全解决方案总览",       "url": "/products.php",   "snippet": "全面的安全产品线..."},
    "hello":      {"title": "欢迎页面",              "url": "/",               "snippet": "AI-IDS 测试平台首页..."},
    "admin":      {"title": "管理员入口",            "url": "/admin",          "snippet": "后台管理（需授权）..."},
}

VALID_USERS: Dict[str, str] = {
    "admin":    "admin123",
    "testuser": "testpass123",
}

STATIC_DIR: str = os.path.dirname(os.path.abspath(__file__))
YEAR: str = str(datetime.now().year)


# ============================================================================
# HTML 模板
# ============================================================================

PAGE_HEADER = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title}</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.ico" type="image/x-icon">
</head><body>
<header class="site-header"><div class="container">
<a href="/" class="logo"><img src="/images/logo.png" alt="Logo" width="48" height="48"><span>AI-IDS Test Corporation</span></a>
<nav><ul>
<li><a href="/">首页</a></li><li><a href="/products.php">产品中心</a></li>
<li><a href="/api/status">系统状态</a></li><li><a href="/login">管理员登录</a></li>
</ul></nav>
<form class="search-box" action="/search" method="POST">
<input type="text" name="q" placeholder="搜索内容..." value="{search_value}"><button type="submit">搜索</button>
</form></div></header>
<main class="container">"""

PAGE_FOOTER = """</main>
<footer><div class="container"><p>&copy; {year} AI-IDS Test Corporation. All rights reserved.</p>
<p><small>Server: AI-IDS Test Server (Python) | Python: {python_ver}</small></p>
</div></footer><script src="/script.js"></script></body></html>"""

MINI_HEADER = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>{title}</title><link rel="stylesheet" href="/style.css"></head><body>
<header class="site-header"><div class="container"><a href="/" class="logo"><span>AI-IDS Test Corporation</span></a>
<nav><ul><li><a href="/">首页</a></li><li><a href="/products.php">产品中心</a></li></ul></nav></div></header>
<main class="container">"""

MINI_FOOTER = """</main>
<footer><div class="container"><p>&copy; {year} AI-IDS Test Corporation</p></div></footer></body></html>"""


def _html(text: Any) -> str:
    """HTML 实体转义。"""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_header(title: str, search_value: str = "") -> str:
    return PAGE_HEADER.format(title=title, search_value=_html(search_value))


def _render_mini_header(title: str) -> str:
    return MINI_HEADER.format(title=title)


def _render_footer() -> str:
    return PAGE_FOOTER.format(year=YEAR, python_ver=sys.version.split()[0])


def _render_mini_footer() -> str:
    return MINI_FOOTER.format(year=YEAR)


# ============================================================================
# 页面渲染
# ============================================================================

def render_index(request_uri: str) -> str:
    html = _render_header("AI-IDS Test Site — 首页")
    html += """
<section class="hero">
<h1>欢迎访问 AI-IDS 测试平台</h1>
<p>这是一个用于测试网络入侵检测系统的演示网站。</p>
<p>当前请求路径: <code>{uri}</code></p>
</section>

<section class="features">
<div class="card"><h3>📦 产品中心</h3><p>浏览我们的产品列表。</p>
<a href="/products.php">查看产品 →</a> <a href="/items.php?id=1">查看商品详情 →</a></div>
<div class="card"><h3>🔍 全局搜索</h3><p>搜索站内内容。</p>
<form action="/search" method="POST">
<input type="text" name="q" placeholder="输入关键词..."><button type="submit">搜索</button></form></div>
<div class="card"><h3>💬 用户评论</h3><p>发表您的意见。</p>
<a href="/comment">发表评论 →</a></div>
<div class="card"><h3>🔐 管理员</h3><p>后台管理系统入口。</p>
<a href="/admin">进入后台 →</a></div>
</section>

<section class="status"><h2>系统状态</h2><div id="status-panel">加载中...</div></section>
""".format(uri=_html(request_uri))
    html += _render_footer()
    return html


def render_products() -> str:
    html = _render_mini_header("产品中心 — AI-IDS Test")
    html += f'<div class="product-list"><h2>📦 产品中心</h2><p>共 {len(PRODUCTS)} 款安全产品</p><table>'
    html += "<thead><tr><th>ID</th><th>产品名称</th><th>价格 (¥)</th><th>库存</th><th>操作</th></tr></thead><tbody>"
    for p in PRODUCTS:
        stock_class = "success" if p["stock"] > 0 else "error"
        stock_text = str(p["stock"]) if p["stock"] > 0 else "缺货"
        html += (f'<tr><td>{p["id"]}</td><td>{_html(p["name"])}</td>'
                 f'<td class="price">¥{p["price"]:,}</td>'
                 f'<td class="{stock_class}">{stock_text}</td>'
                 f'<td><a href="/items.php?id={p["id"]}">查看详情</a></td></tr>')
    html += "</tbody></table></div>" + _render_mini_footer()
    return html


def render_item(item_id: Optional[str]) -> Tuple[str, int]:
    item = None
    if item_id:
        try:
            item = PRODUCT_BY_ID.get(int(item_id))
        except ValueError:
            pass

    html = _render_mini_header("商品详情 — AI-IDS Test")
    html += '<div class="item-detail">'
    if item:
        html += (f'<h2>{_html(item["name"])}</h2><table>'
                 f'<tr><th>分类</th><td>{_html(item["category"])}</td></tr>'
                 f'<tr><th>价格</th><td class="price">¥{item["price"]:,}</td></tr>'
                 f'<tr><th>描述</th><td>{_html(item["desc"])}</td></tr>'
                 f'<tr><th>请求参数</th><td><code>id={_html(item_id or "null")}</code></td></tr>'
                 f'</table>')
    else:
        html += (f'<h2>未找到商品</h2>'
                 f'<p>商品 ID <code>{_html(item_id or "null")}</code> 不存在。</p>'
                 f'<p><a href="/products.php">← 返回产品列表</a></p>')
    html += "</div>" + _render_mini_footer()
    return html, 200


def render_search(query: str) -> str:
    results = []
    if query:
        q_lower = query.lower()
        for keyword, data in SEARCH_INDEX.items():
            if q_lower in keyword or q_lower in data["title"].lower():
                results.append(data)

    html = _render_mini_header("搜索结果 — AI-IDS Test")
    html += '<div class="product-list">'
    html += f'<h2>🔍 搜索结果</h2><p>关键词: <strong>{_html(query or "(空)")}</strong></p>'
    html += f'<p>找到 {len(results)} 条结果</p>'

    if results:
        for r in results:
            html += (f'<div class="product-item"><h4><a href="{_html(r["url"])}">{_html(r["title"])}</a></h4>'
                     f'<p>{_html(r["snippet"])}</p></div>')
    elif query:
        html += f'<p>未找到与 "{_html(query)}" 相关的搜索结果。</p>'

    html += "</div>" + _render_mini_footer()
    return html


def render_login_form(error: str = "") -> str:
    html = _render_mini_header("管理员登录 — AI-IDS Test")
    html += '<div class="login-form"><h2>🔐 管理员登录</h2>'
    if error:
        html += f"<p>{error}</p>"
    html += """<form method="POST" action="/login">
<label for="username">用户名</label>
<input type="text" id="username" name="username" placeholder="请输入用户名" required>
<label for="password">密码</label>
<input type="password" id="password" name="password" placeholder="请输入密码" required>
<button type="submit">登录</button></form>
<p style="margin-top:16px;font-size:0.85em;color:#999;">提示: 测试账号 admin / admin123</p>
</div>""" + _render_mini_footer()
    return html


def render_comment_form(submitted: bool = False, comment_text: str = "") -> str:
    html = _render_mini_header("用户评论 — AI-IDS Test")
    html += '<div class="comment-form"><h2>💬 发表评论</h2>'
    if submitted:
        html += '<p class="success">✅ 评论已提交!</p>'
        html += f'<div class="product-item"><p><strong>您的评论:</strong></p><p>{_html(comment_text or "(空)")}</p></div>'
    html += """<form method="POST" action="/comment">
<label for="text">评论内容</label>
<textarea id="text" name="text" placeholder="请输入您的评论..." required></textarea>
<button type="submit">提交评论</button></form></div>""" + _render_mini_footer()
    return html


def render_admin_403() -> Tuple[str, int]:
    html = _render_mini_header("403 Forbidden — AI-IDS Test")
    html += ('<div class="admin-denied"><h1>403</h1>'
             '<p>⛔ 拒绝访问 — 您没有权限访问管理后台。</p>'
             '<p><small>此页面需要管理员凭证，请通过 <a href="/login">/login</a> 登录。</small></p>'
             '<p><small>此页面故意返回 403 用于测试路径扫描检测。</small></p></div>'
             + _render_mini_footer())
    return html, 403


# ============================================================================
# 静态文件
# ============================================================================

# 最小 PNG (1x1 blue pixel) — logo.png
_LOGO_PNG = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02'
    b'\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\x9f\xa1\x1e\x00'
    b'\x07\x82\x02\xfd\xc8H\xef\x0a\x00\x00\x00\x00IEND\xaeB`\x82'
)

_MIME: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".png":  "image/png",
    ".ico":  "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def serve_static(path: str) -> Tuple[Optional[bytes], str, int]:
    """返回 (body, content_type, status)。"""
    if path == "/favicon.ico":
        favicon = os.path.join(STATIC_DIR, "favicon.ico")
        if os.path.exists(favicon):
            with open(favicon, "rb") as f:
                return f.read(), "image/x-icon", 200
        return None, "", 404

    if path == "/images/logo.png":
        return _LOGO_PNG, "image/png", 200

    # 安全移除 URL 参数和路径穿越
    clean = path.split("?")[0].lstrip("/")
    safe = os.path.normpath(clean)
    if safe.startswith("..") or safe.startswith("\\"):
        return None, "", 404

    filepath = os.path.join(STATIC_DIR, safe)
    if not os.path.isfile(filepath):
        return None, "", 404

    _, ext = os.path.splitext(filepath)
    mime = _MIME.get(ext.lower(), "application/octet-stream")
    is_text = ext.lower() in (".html", ".css", ".js")
    mode = "r" if is_text else "rb"
    encoding = "utf-8" if is_text else None

    try:
        with open(filepath, mode, encoding=encoding) as f:
            data = f.read()
        return data.encode("utf-8") if is_text else data, mime, 200
    except OSError:
        return None, "", 404


# ============================================================================
# HTTP Handler
# ============================================================================

class TestSiteHandler(BaseHTTPRequestHandler):
    """AI-IDS 测试网站请求处理器。"""

    server_version = "AI-IDS-Test-Server/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # 去掉标准库日志的时间戳，简洁输出
        now = datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"[{now}] {args[0]}\n")

    # ---- 路由分发 ----------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        # 静态文件
        if any(path.endswith(ext) for ext in (".css", ".js", ".ico", ".png")):
            body, mime, status = serve_static(path)
            if body is not None:
                self._respond(status, mime, body)
                return
        if path.startswith("/images/"):
            body, mime, status = serve_static(path)
            if body is not None:
                self._respond(status, mime, body)
                return

        # 动态路由
        try:
            if path == "/":
                body, code, mime = render_index(self.path), 200, "text/html; charset=utf-8"
            elif path == "/index.html":
                body, mime2, code = serve_static("/index.html")
                if body is None:
                    body, code, mime = "<h1>404 Not Found</h1>", 404, "text/html"
                else:
                    mime = mime2
            elif path == "/products.php":
                body, code, mime = render_products(), 200, "text/html; charset=utf-8"
            elif path == "/items.php":
                item_id = params.get("id", [None])[0]
                body, code = render_item(item_id)
                mime = "text/html; charset=utf-8"
            elif path == "/search":
                q = params.get("q", [""])[0]
                body, code, mime = render_search(q), 200, "text/html; charset=utf-8"
            elif path == "/login":
                body, code, mime = render_login_form(), 200, "text/html; charset=utf-8"
            elif path == "/comment":
                body, code, mime = render_comment_form(), 200, "text/html; charset=utf-8"
            elif path == "/admin":
                body, code = render_admin_403()
                mime = "text/html; charset=utf-8"
            elif path == "/api/status":
                body, code, mime = self._api_status(), 200, "application/json; charset=utf-8"
            elif path == "/api/login":
                body, code, mime = json.dumps(
                    {"status": "error", "message": "Method Not Allowed. Use POST."},
                    ensure_ascii=False,
                ), 405, "application/json; charset=utf-8"
            else:
                body, code, mime = "<h1>404 Not Found</h1>", 404, "text/html; charset=utf-8"

            self._respond(code, mime, body if isinstance(body, bytes) else body.encode("utf-8"))
        except Exception:
            self._respond(500, "text/plain", b"Internal Server Error")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # 读 POST body
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        post_params = parse_qs(post_data.decode("utf-8", errors="replace"))

        def _get(key: str) -> str:
            vals = post_params.get(key, [""])
            return vals[0] if vals else ""

        try:
            if path == "/api/login":
                body, code, mime = self._api_login_post(
                    _get("username"), _get("password")
                )
            elif path == "/login":
                user, pwd = _get("username"), _get("password")
                if user == "admin" and pwd == "admin123":
                    body = render_login_form('<span class="success">✅ 登录成功! (测试凭证有效)</span>')
                else:
                    body = render_login_form('<span class="error">❌ 用户名或密码错误</span>')
                code, mime = 200, "text/html; charset=utf-8"
            elif path == "/comment":
                text = _get("text")
                body = render_comment_form(submitted=True, comment_text=text)
                code, mime = 200, "text/html; charset=utf-8"
            elif path == "/search":
                q = _get("q")
                body = render_search(q)
                code, mime = 200, "text/html; charset=utf-8"
            else:
                body, code, mime = "<h1>404 Not Found</h1>", 404, "text/html; charset=utf-8"

            self._respond(code, mime, body if isinstance(body, bytes) else body.encode("utf-8"))
        except Exception:
            self._respond(500, "text/plain", b"Internal Server Error")

    # ---- 响应工具 ----------------------------------------------------------

    def _respond(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _api_status(self) -> bytes:
        now = datetime.now()
        data = {
            "status": "ok",
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": int(now.timestamp()),
            "python_version": sys.version.split()[0],
            "server": "AI-IDS-Test-Server/1.0 (Python)",
            "host": self.headers.get("Host", "Unknown"),
            "method": self.command,
            "uri": self.path,
        }
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

    def _api_login_post(self, username: str, password: str) -> Tuple[bytes, int, str]:
        mime = "application/json; charset=utf-8"
        if username in VALID_USERS and VALID_USERS[username] == password:
            token = secrets.token_hex(16)
            body = json.dumps({
                "status": "success",
                "message": "登录成功",
                "username": username,
                "token": f"test_token_{token}",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }, ensure_ascii=False)
            return body.encode("utf-8"), 200, mime
        else:
            body = json.dumps({
                "status": "error",
                "message": "用户名或密码错误",
                "username": username,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }, ensure_ascii=False)
            return body.encode("utf-8"), 401, mime


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-IDS 测试网站服务器 — 纯 Python 实现，零依赖"
    )
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8081, help="监听端口 (默认: 8081)")
    args = parser.parse_args()

    print("=" * 56)
    print("  AI-IDS 测试网站服务器")
    print("=" * 56)
    print(f"  监听地址 : http://{args.host}:{args.port}")
    print(f"  静态目录 : {STATIC_DIR}")
    print(f"  Python   : {sys.version}")
    print()
    print("  可访问端点:")
    print(f"    首页:       http://localhost:{args.port}/")
    print(f"    JSON 状态:  http://localhost:{args.port}/api/status")
    print(f"    JSON 登录:  POST http://localhost:{args.port}/api/login")
    print(f"    登录表单:   http://localhost:{args.port}/login")
    print(f"    产品中心:   http://localhost:{args.port}/products.php")
    print(f"    商品详情:   http://localhost:{args.port}/items.php?id=1")
    print(f"    搜索:       http://localhost:{args.port}/search?q=ids")
    print(f"    评论:       http://localhost:{args.port}/comment")
    print(f"    管理后台:   http://localhost:{args.port}/admin  (403)")
    print()
    print("  按 Ctrl+C 停止服务器")
    print("=" * 56)

    # SO_REUSEADDR 允许崩溃后立即重启，不用等 TIME_WAIT
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True

        def server_bind(self) -> None:
            import socket as _socket
            self.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            super().server_bind()

    try:
        server = ReusableHTTPServer((args.host, args.port), TestSiteHandler)
    except PermissionError:
        print(f"\n❌ 端口 {args.port} 被占用或无权限。请尝试：")
        print(f"   python server.py --port 8765")
        print(f"   或先关闭占用进程: netstat -ano | findstr :{args.port}")
        sys.exit(1)
    except OSError as e:
        print(f"\n❌ 启动失败: {e}")
        print(f"   提示: 端口 {args.port} 可能已被占用。试试其他端口:")
        print(f"   python server.py --port 9876")
        sys.exit(1)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        server.server_close()


if __name__ == "__main__":
    main()
