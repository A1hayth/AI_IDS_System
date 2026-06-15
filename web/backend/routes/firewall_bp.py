"""
POST /api/v1/firewall/ban —— 管理员封禁 IP

将 IP 加入 banned_ips 黑名单表
"""
import pymysql
from flask import Blueprint, request
from config import DB_CONFIG
from utils.response import success, bad_request, internal_error

firewall_bp = Blueprint('firewall', __name__, url_prefix='/api/v1/firewall')


def get_db():
    return pymysql.connect(**DB_CONFIG)


@firewall_bp.route('/ban', methods=['POST'])
def ban():
    try:
        body = request.get_json(silent=True)
        if not body:
            return bad_request('请提供 JSON 格式的请求体')

        ip = (body.get('ip') or body.get('ip_address') or '').strip()
        operator = (body.get('operator') or body.get('username') or 'admin').strip()

        if not ip:
            return bad_request('ip 不能为空')

        # 简单 IP 格式校验
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return bad_request(f'IP 格式不合法: {ip}')

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # 检查是否已存在
                check_sql = "SELECT id FROM banned_ips WHERE ip_address = %s"
                cur.execute(check_sql, (ip,))
                if cur.fetchone():
                    return bad_request(f'IP {ip} 已被封禁，无需重复操作')

                # 插入封禁记录
                insert_sql = """
                    INSERT INTO banned_ips (ip_address, ban_time, operator)
                    VALUES (%s, NOW(), %s)
                """
                cur.execute(insert_sql, (ip, operator))
                conn.commit()
                ban_id = cur.lastrowid

            return success({'id': ban_id, 'ip': ip}, f'IP {ip} 封禁成功')
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')
