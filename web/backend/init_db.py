"""
数据库初始化脚本 —— 创建表 + 插入测试数据

使用方式:
    cd backend
    python init_db.py

前提：MySQL 中已存在 ai_monitor_db 数据库，或 MySQL root 用户有 CREATE DATABASE 权限。
"""
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import pymysql
from config import DB_CONFIG

# 不指定 database，先连接 MySQL 服务器建库
ROOT_CONFIG = {
    'host': DB_CONFIG['host'],
    'port': DB_CONFIG['port'],
    'user': DB_CONFIG['user'],
    'password': DB_CONFIG['password'],
    'charset': DB_CONFIG['charset'],
}


def init():
    print('正在连接 MySQL ...')

    # 1. 创建数据库
    try:
        conn = pymysql.connect(**ROOT_CONFIG)
        with conn.cursor() as cur:
            cur.execute(
                "CREATE DATABASE IF NOT EXISTS ai_monitor_db "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        conn.close()
        print('✓ 数据库 ai_monitor_db 已就绪')
    except pymysql.Error as e:
        print(f'✗ 创建数据库失败: {e}')
        print('  请手动在 MySQL 中执行 DB1.db 中的建库语句')
        return

    # 2. 连接目标库，创建表
    try:
        conn = pymysql.connect(**DB_CONFIG)
        cur = conn.cursor()

        # ── 用户表 ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sys_users (
                id INT AUTO_INCREMENT PRIMARY KEY COMMENT '用户唯一ID',
                username VARCHAR(50) NOT NULL COMMENT '登录账号',
                password VARCHAR(255) NOT NULL COMMENT '登录密码',
                identity_code VARCHAR(50) NOT NULL COMMENT '身份授权码',
                role VARCHAR(20) NOT NULL COMMENT '角色(admin/user)'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户表'
        """)

        # ── 流量日志表 ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INT AUTO_INCREMENT PRIMARY KEY COMMENT '日志唯一ID',
                timestamp DATETIME NOT NULL COMMENT '抓包及拦截发生时间',
                client_ip VARCHAR(50) NOT NULL COMMENT '访问者/攻击者IP',
                is_attack BOOLEAN DEFAULT FALSE COMMENT '是否为攻击 (0:否, 1:是)',
                attack_type VARCHAR(50) DEFAULT 'Normal' COMMENT '攻击类型',
                severity VARCHAR(20) DEFAULT 'Low' COMMENT '威胁等级',
                ai_reason TEXT COMMENT 'AI判定理由'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AI流量检测日志表'
        """)

        # ── IP 封禁表 ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INT AUTO_INCREMENT PRIMARY KEY COMMENT '封禁记录ID',
                ip_address VARCHAR(50) NOT NULL COMMENT '被封禁的IP地址',
                ban_time DATETIME NOT NULL COMMENT '执行封禁的时间',
                operator VARCHAR(50) COMMENT '操作人账号'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='全局IP黑名单表'
        """)

        conn.commit()
        print('✓ 三张数据表已就绪')

        # 3. 插入测试用户（先清空再插入，避免重复）
        cur.execute("DELETE FROM sys_users")
        cur.execute("""
            INSERT INTO sys_users (username, password, identity_code, role) VALUES
            ('admin', '123456', 'admin888', 'admin'),
            ('user', '123456', 'user123', 'user')
        """)

        # 4. 插入今日测试攻击日志（方便图表有数据可看）
        cur.execute("DELETE FROM traffic_logs")
        test_logs = [
            ("08:15:00", "114.114.114.114", True, "SQL Injection", "High",
             "检测到非法 SQL 闭合符 '--"),
            ("08:42:00", "8.8.8.8", True, "XSS", "Medium",
             "Payload 包含 <script> 恶意标签"),
            ("09:10:00", "192.168.1.55", True, "Path Traversal", "High",
             "尝试使用 ../../ 跨目录读取 /etc/passwd"),
            ("09:30:00", "47.100.20.33", True, "Command Execution", "Critical",
             "疑似调用系统命令 ping ; ls"),
            ("09:45:00", "10.0.0.1", False, "Normal", "Low", ""),
            ("10:00:00", "114.114.114.114", True, "SQL Injection", "High",
             "UNION SELECT 注入探测"),
            ("10:15:00", "172.16.0.88", False, "Normal", "Low", ""),
            ("10:30:00", "10.0.0.55", True, "XSS", "Low",
             "轻微可疑字符"),
            ("10:52:00", "8.8.8.8", True, "XSS", "Medium",
             "Payload 包含 <script> 恶意标签"),
            ("11:00:00", "47.100.20.33", True, "Command Execution", "Critical",
             "可疑反弹 shell 命令"),
            ("11:20:00", "192.168.1.55", True, "Path Traversal", "High",
             "尝试读取 Windows 系统文件"),
            ("11:45:00", "172.16.0.100", False, "Normal", "Low", ""),
        ]

        today = __import__('datetime').date.today().isoformat()
        for ts, ip, attack, atype, sev, reason in test_logs:
            cur.execute(
                "INSERT INTO traffic_logs (timestamp, client_ip, is_attack, attack_type, severity, ai_reason) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (f"{today} {ts}", ip, attack, atype, sev, reason),
            )

        # 清空封禁表
        cur.execute("DELETE FROM banned_ips")

        conn.commit()
        print('✓ 测试数据已写入')
        print()
        print('  测试账号:')
        print('    管理员  admin / 123456 / admin888  →  admin')
        print('    普通用户 user  / 123456 / user123   →  user')
        print()

        cur.close()
        conn.close()

    except pymysql.Error as e:
        print(f'✗ 初始化失败: {e}')


if __name__ == '__main__':
    init()
