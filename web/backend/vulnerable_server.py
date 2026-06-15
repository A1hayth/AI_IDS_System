"""
DEFCON-X 漏洞测试靶机 —— 运行在端口 5000

启动方式:
    python vulnerable_server.py

包含漏洞:
    /login  - SQL 注入 (万能密码)
    /search - 反射型 XSS
    /user   - GET 型 SQL 注入
"""
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>⚡ DEFCON-X 漏洞测试靶场</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #030712; color: #38bdf8; font-family: 'Microsoft YaHei', monospace; }
        .glitch-title { text-shadow: 3px 3px #ef4444, -3px -3px #06b6d4; }
        .scanline {
            width: 100%; height: 120px; z-index: 9999; position: absolute; pointer-events: none;
            background: linear-gradient(0deg, rgba(0,0,0,0) 0%, rgba(56,189,248,0.1) 50%, rgba(0,0,0,0) 100%);
            animation: scanline 8s linear infinite;
        }
        @keyframes scanline { 0% { top: -120px; } 100% { top: 100%; } }
        .cyber-box {
            border: 2px solid #0284c7;
            background: rgba(15, 23, 42, 0.6);
            box-shadow: 0 0 20px rgba(3, 105, 161, 0.3);
            transition: all 0.3s ease;
        }
        .cyber-box:hover {
            border-color: #38bdf8;
            box-shadow: 0 0 30px rgba(56, 189, 248, 0.5);
        }
    </style>
</head>
<body class="min-h-screen p-12 relative overflow-x-hidden">
    <div class="scanline"></div>
    <div class="max-w-7xl mx-auto relative z-10">
        {content}
    </div>
</body>
</html>
"""


def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    c.execute("INSERT INTO users (username, password) VALUES ('test', '123456')")
    conn.commit()
    return conn


@app.route('/')
def index():
    content = """
    <div class="text-center mb-12">
        <h1 class="text-6xl font-black text-red-500 glitch-title mb-4 tracking-widest">⚠️ 目标系统已被攻破</h1>
        <p class="text-2xl text-slate-400">DEFCON-X 漏洞测试靶机 · 实时流量监测对象中枢</p>
    </div>

    <div class="grid grid-cols-2 gap-10">
        <div class="cyber-box p-8 rounded-xl border-red-500/50">
            <h2 class="text-3xl font-bold text-red-400 border-b border-red-900/50 pb-3 mb-6 flex items-center">
                <span class="mr-3">🚨</span> 级别一：Web 应用层漏洞测试
            </h2>
            <ul class="space-y-4 text-lg">
                <li>
                    <a href="/login" class="border border-slate-800 bg-slate-900/40 hover:bg-red-500/10 p-4 block rounded-lg transition-all hover:translate-x-2">
                        <span class="text-red-400 font-bold">> 01.</span> 后台登录口暴力破解 / SQL万能密码漏洞
                    </a>
                </li>
                <li>
                    <a href="/search?q=AI检测异常" class="border border-slate-800 bg-slate-900/40 hover:bg-red-500/10 p-4 block rounded-lg transition-all hover:translate-x-2">
                        <span class="text-red-400 font-bold">> 02.</span> 反射型跨站脚本攻击 (XSS 漏洞测试)
                    </a>
                </li>
                <li>
                    <a href="/user?id=1" class="border border-slate-800 bg-slate-900/40 hover:bg-red-500/10 p-4 block rounded-lg transition-all hover:translate-x-2">
                        <span class="text-red-400 font-bold">> 03.</span> 显错式 SQL 注入攻击 (URL-GET 参数型)
                    </a>
                </li>
            </ul>
            <p class="mt-6 text-sm text-slate-500">提示：点击上方链接发起模拟攻击，并观察你们的 AI 大屏是否产生报警日志。</p>
        </div>

        <div class="cyber-box p-8 rounded-xl border-yellow-500/50 text-yellow-500">
            <h2 class="text-3xl font-bold border-b border-yellow-900/50 pb-3 mb-6 flex items-center">
                <span class="mr-3">⚔️</span> 级别二：网络与流量型攻击模拟
            </h2>
            <p class="mb-4 text-lg text-slate-300">本板块无需点击链接。请使用外部安全工具（如 Nmap, Python 脚本）直接轰炸本机的 <span class="text-yellow-400 font-bold font-mono text-xl">5000</span> 端口：</p>

            <div class="space-y-4">
                <div class="bg-black/80 p-5 rounded-lg border border-yellow-900/50 font-mono text-base">
                    <p class="text-slate-500">// 模拟 端口扫描 (PortScan) 流量</p>
                    <p class="text-yellow-400 font-bold">> nmap -sS -p 5000 [本机IP]</p>
                </div>

                <div class="bg-black/80 p-5 rounded-lg border border-yellow-900/50 font-mono text-base">
                    <p class="text-slate-500">// 模拟 慢速拒绝服务 (Slowloris DoS) 流量</p>
                    <p class="text-yellow-400 font-bold">> python slowloris.py [本机IP] -p 5000</p>
                </div>
            </div>
        </div>
    </div>
    """
    return BASE_HTML.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = init_db()
        c = conn.cursor()
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            c.execute(sql)
            user = c.fetchone()
            if user:
                message = f"<div class='mt-6 p-4 bg-green-950/80 border border-green-500 text-green-300 rounded text-lg'>🔓 [认证通过] 欢迎回来，核心管理员: {user[1]}。系统最高密钥: {user[2]}</div>"
            else:
                message = "<div class='mt-6 p-4 bg-red-950/80 border border-red-500 text-red-300 rounded text-lg'>🔒 [认证拒绝] 凭证错误，登录失败。密码不匹配。</div>"
        except Exception as e:
            message = f"<div class='mt-6 p-4 bg-amber-950/80 border border-amber-500 text-amber-200 rounded font-mono text-sm'>⚠️ [SQL 语法引发异常]: {str(e)}</div>"

    content = f"""
    <div class="mb-6"><a href="/" class="text-slate-500 hover:text-sky-400 text-lg transition-colors"><< 返回主控制中枢</a></div>
    <div class="cyber-box max-w-xl mx-auto mt-12 p-10 rounded-xl">
        <h2 class="text-3xl font-bold mb-8 text-center text-sky-400 tracking-wider">🔒 安全身份认证网关</h2>
        <form method="post" class="space-y-6 text-black">
            <div>
                <label class="block text-slate-400 text-sm mb-2">管理员账户</label>
                <input type="text" name="username" placeholder="请输入用户名" class="w-full p-3 bg-slate-900 text-sky-400 border border-sky-900 rounded outline-none focus:border-sky-400 text-lg">
            </div>
            <div>
                <label class="block text-slate-400 text-sm mb-2">安全密码密文</label>
                <input type="password" name="password" placeholder="请输入密码" class="w-full p-3 bg-slate-900 text-sky-400 border border-sky-900 rounded outline-none focus:border-sky-400 text-lg">
            </div>
            <button type="submit" class="w-full bg-sky-950 hover:bg-sky-800 text-sky-300 font-bold py-3 rounded border border-sky-500 transition-all text-xl tracking-widest">初始化鉴权登录</button>
        </form>
        {message}
    </div>
    """
    return BASE_HTML.replace('{content}', content)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    content = f"""
    <div class="mb-6"><a href="/" class="text-slate-500 hover:text-sky-400 text-lg transition-colors"><< 返回主控制中枢</a></div>
    <div class="cyber-box mt-12 p-10 rounded-xl">
        <h2 class="text-3xl font-bold mb-6 text-sky-400">🔍 核心数据库特征检索结果</h2>
        <p class="text-xl text-slate-300">当前正在解析过滤的目标特征参数：
            <span class="text-red-400 bg-red-950/50 px-3 py-1 rounded border border-red-900 font-mono font-bold">{query}</span>
        </p>
        <div class="mt-8 p-6 bg-slate-950/80 border border-slate-800 rounded">
            <p class="text-slate-500 text-lg">查询状态：执行完毕。核心结构内未匹配到任何相关联特征记录。</p>
        </div>
    </div>
    """
    return BASE_HTML.replace('{content}', content)


@app.route('/user')
def user_profile():
    user_id = request.args.get('id', '1')
    conn = init_db()
    c = conn.cursor()
    sql = f"SELECT id, username FROM users WHERE id = {user_id}"

    try:
        c.execute(sql)
        result = c.fetchall()
        content = f"""
        <div class="mb-6"><a href="/" class="text-slate-500 hover:text-sky-400 text-lg transition-colors"><< 返回主控制中枢</a></div>
        <div class="cyber-box mt-12 p-10 rounded-xl">
            <h2 class="text-3xl font-bold mb-6 text-sky-400">👤 系统敏感高密数据提取面板</h2>

            <div class="bg-black/80 p-5 rounded-lg border border-sky-900/50 mb-6 font-mono text-base">
                <p class="text-slate-500 mb-2">// 后端正在底层执行的原始 SQL 查询指令：</p>
                <code class="text-amber-400 font-bold">{sql}</code>
            </div>

            <h3 class="text-xl text-slate-300 mb-2">数据载荷输出结果：</h3>
            <pre class="p-4 bg-slate-950 border border-slate-800 rounded text-xl text-yellow-400 font-mono font-bold">{result}</pre>
        </div>
        """
    except Exception as e:
        content = f"""
        <div class="mb-6"><a href="/" class="text-slate-500 hover:text-sky-400 text-lg transition-colors"><< 返回主控制中枢</a></div>
        <div class="cyber-box mt-12 p-10 rounded-xl border-red-500/50">
            <h2 class="text-3xl font-bold mb-6 text-red-500">❌ 核心数据库发生致命解析错误</h2>
            <div class="bg-black/90 p-6 rounded-lg border border-red-900/50">
                <pre class="text-red-400 font-mono text-base whitespace-pre-wrap">{str(e)}</pre>
            </div>
        </div>
        """
    return BASE_HTML.replace('{content}', content)


if __name__ == '__main__':
    print("=" * 60)
    print("🔥 DEFCON-X 超宽中文满血靶机启动成功！端口: 5000")
    print("⚠️ 警告：该系统包含工业级安全缺陷，请勿映射至公网！")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000)
