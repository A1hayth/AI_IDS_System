"""
POST /api/v1/auth/login    —— 用户登录
POST /api/v1/auth/register —— 用户注册

前端提交字段: username, password, identityCode
数据库匹配: sys_users (username, password, identity_code, role)
"""

# 有效授权码 → 角色映射
VALID_IDENTITY_CODES = {
    'admin888': 'admin',
    'user123': 'user',
}
import pymysql
from flask import Blueprint, request
from config import DB_CONFIG
from utils.response import success, fail, bad_request, internal_error

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


def get_db():
    """获取数据库连接"""
    return pymysql.connect(**DB_CONFIG)


@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        body = request.get_json(silent=True)
        if not body:
            return bad_request('请提供 JSON 格式的请求体')

        username = (body.get('username') or '').strip()
        password = (body.get('password') or '').strip()
        identity_code = (body.get('identityCode') or '').strip()

        # 参数校验
        if not username or not password or not identity_code:
            return bad_request('用户名、密码、身份码均不能为空')

        conn = get_db()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT id, username, role
                    FROM sys_users
                    WHERE username = %s
                      AND password = %s
                      AND identity_code = %s
                """
                cur.execute(sql, (username, password, identity_code))
                row = cur.fetchone()

            if row is None:
                return fail(401, '账号、密码或身份码不正确')

            return success({
                'userId': row['id'],
                'username': row['username'],
                'role': row['role'],          # 前端根据 role 做页面跳转
            }, '登录成功')

        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')


@auth_bp.route('/register', methods=['POST'])
def register():
    """用户注册 —— 校验授权码，分配角色，写入 sys_users"""
    try:
        body = request.get_json(silent=True)
        if not body:
            return bad_request('请提供 JSON 格式的请求体')

        username = (body.get('username') or '').strip()
        password = (body.get('password') or '').strip()
        identity_code = (body.get('identityCode') or '').strip()

        # ── 参数校验 ──
        if not username or not password or not identity_code:
            return bad_request('用户名、密码、授权码均不能为空')
        if len(username) < 2:
            return bad_request('用户名至少 2 个字符')
        if len(password) < 6:
            return bad_request('密码至少 6 个字符')

        # ── 授权码校验 ──
        role = VALID_IDENTITY_CODES.get(identity_code)
        if role is None:
            return fail(400, '授权码无效或已被吊销，拒绝写入')

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # 检查用户名是否已存在
                cur.execute("SELECT id FROM sys_users WHERE username = %s", (username,))
                if cur.fetchone():
                    return fail(409, f'用户名 "{username}" 已被占用，请更换')

                # 写入新用户
                cur.execute(
                    "INSERT INTO sys_users (username, password, identity_code, role) VALUES (%s, %s, %s, %s)",
                    (username, password, identity_code, role),
                )
                conn.commit()
                new_id = cur.lastrowid

            return success({
                'userId': new_id,
                'username': username,
                'role': role,
            }, f'身份写入成功！您已被系统接纳，角色: {role}')

        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')
