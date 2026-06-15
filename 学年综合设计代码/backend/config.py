# ==========================================
# 数据库与应用配置
# ==========================================

import pymysql.cursors

# MySQL 连接配置 - 请根据你的本地环境修改
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '040810',
    'database': 'ai_monitor_db',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,  # 查询结果自动转为字典
    'autocommit': True,
}

# Flask 配置
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 8080
FLASK_DEBUG = True
