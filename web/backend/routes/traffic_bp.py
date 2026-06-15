"""
POST /api/v1/traffic/save —— AI 模块写入检测日志

前端/AI 模块提交字段示例:
{
    "timestamp": "2025-06-08 17:00:00",
    "client_ip": "192.168.1.100",
    "is_attack": true,
    "attack_type": "SQL Injection",
    "severity": "High",
    "ai_reason": "检测到非法SQL闭合符 '--"
}
"""
import pymysql
from flask import Blueprint, request
from config import DB_CONFIG
from utils.response import success, bad_request, internal_error

traffic_bp = Blueprint('traffic', __name__, url_prefix='/api/v1/traffic')


def get_db():
    return pymysql.connect(**DB_CONFIG)


@traffic_bp.route('/save', methods=['POST'])
def save():
    try:
        body = request.get_json(silent=True)
        if not body:
            return bad_request('请提供 JSON 格式的请求体')

        timestamp = body.get('timestamp') or body.get('time')
        client_ip = (body.get('client_ip') or body.get('clientIp') or '').strip()
        is_attack = body.get('is_attack', False)
        attack_type = body.get('attack_type') or body.get('attackType') or 'Normal'
        severity = body.get('severity') or 'Low'
        ai_reason = body.get('ai_reason') or body.get('aiReason') or ''

        if not client_ip:
            return bad_request('client_ip 不能为空')

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # 如果没有提供时间戳，使用 MySQL 的 NOW()
                if timestamp:
                    sql = """
                        INSERT INTO traffic_logs
                            (timestamp, client_ip, is_attack, attack_type, severity, ai_reason)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    cur.execute(sql, (timestamp, client_ip, is_attack, attack_type, severity, ai_reason))
                else:
                    sql = """
                        INSERT INTO traffic_logs
                            (timestamp, client_ip, is_attack, attack_type, severity, ai_reason)
                        VALUES (NOW(), %s, %s, %s, %s, %s)
                    """
                    cur.execute(sql, (client_ip, is_attack, attack_type, severity, ai_reason))

                log_id = cur.lastrowid
                conn.commit()

            return success({'id': log_id}, '日志保存成功')
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')
