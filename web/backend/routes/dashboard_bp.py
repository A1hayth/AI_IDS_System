"""
数据统计接口

GET /api/v1/dashboard/overview      总访问量、总攻击量、高危数、独立攻击IP数
GET /api/v1/dashboard/trend         今日流量与攻击趋势（按小时）
GET /api/v1/dashboard/attack-types  今日攻击类型分布
GET /api/v1/dashboard/logs          分页获取攻击日志列表
"""
import pymysql
from flask import Blueprint, request
from config import DB_CONFIG
from utils.response import success, fail, internal_error

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/v1/dashboard')


def get_db():
    return pymysql.connect(**DB_CONFIG)


@dashboard_bp.route('/overview', methods=['GET'])
def overview():
    """获取今日总览统计"""
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT
                        COUNT(*)                                                  AS total_requests,
                        COALESCE(SUM(is_attack), 0)                               AS total_attacks,
                        COALESCE(SUM(CASE WHEN is_attack = 1 AND severity IN ('High', 'Critical')
                                          THEN 1 ELSE 0 END), 0)                  AS high_risk_attacks,
                        COUNT(DISTINCT CASE WHEN is_attack = 1 THEN client_ip END) AS unique_attack_ips
                    FROM traffic_logs
                    WHERE DATE(timestamp) = CURDATE()
                """
                cur.execute(sql)
                row = cur.fetchone()

            return success({
                'total_requests': int(row['total_requests']),
                'total_attacks': int(row['total_attacks']),
                'high_risk_attacks': int(row['high_risk_attacks']),
                'unique_attack_ips': int(row['unique_attack_ips']),
            })
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')


@dashboard_bp.route('/trend', methods=['GET'])
def trend():
    """获取今日流量与攻击趋势（按小时）"""
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT
                        DATE_FORMAT(timestamp, '%%H:00') AS hour,
                        COUNT(*)                          AS traffic_count,
                        COALESCE(SUM(is_attack), 0)       AS attack_count
                    FROM traffic_logs
                    WHERE DATE(timestamp) = CURDATE()
                    GROUP BY DATE_FORMAT(timestamp, '%%H:00')
                    ORDER BY hour
                """
                cur.execute(sql)
                rows = cur.fetchall()

            hours = [r['hour'] for r in rows]
            traffic = [r['traffic_count'] for r in rows]
            attacks = [r['attack_count'] for r in rows]

            return success({
                'hours': hours,
                'traffic': traffic,
                'attacks': attacks,
            })
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')


@dashboard_bp.route('/attack-types', methods=['GET'])
def attack_types():
    """获取今日攻击类型分布"""
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT
                        attack_type AS name,
                        COUNT(*)    AS value
                    FROM traffic_logs
                    WHERE is_attack = 1
                      AND DATE(timestamp) = CURDATE()
                    GROUP BY attack_type
                    ORDER BY value DESC
                """
                cur.execute(sql)
                rows = cur.fetchall()

            return success(rows)
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')


@dashboard_bp.route('/logs', methods=['GET'])
def logs():
    """分页获取攻击日志列表"""
    try:
        # 分页参数
        page = request.args.get('page', 1, type=int)
        size = request.args.get('size', 20, type=int)

        if page < 1:
            page = 1
        if size < 1 or size > 100:
            size = 20

        offset = (page - 1) * size

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # 查询总数
                count_sql = """
                    SELECT COUNT(*) AS total
                    FROM traffic_logs
                    WHERE is_attack = 1
                """
                cur.execute(count_sql)
                total = cur.fetchone()['total']

                # 查询分页数据
                data_sql = """
                    SELECT
                        id,
                        timestamp,
                        client_ip,
                        attack_type,
                        severity,
                        ai_reason
                    FROM traffic_logs
                    WHERE is_attack = 1
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                """
                cur.execute(data_sql, (size, offset))
                rows = cur.fetchall()

            return success({
                'list': rows,
                'total': total,
                'page': page,
                'size': size,
            })
        finally:
            conn.close()

    except pymysql.Error as e:
        return internal_error(f'数据库异常: {str(e)}')
    except Exception as e:
        return internal_error(f'服务器异常: {str(e)}')
