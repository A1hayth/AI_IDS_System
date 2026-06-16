# ==========================================
# 数据库与应用配置
# ==========================================

# MySQL 连接配置 - 请根据你的本地环境修改
# 注意: 如果你还没有安装 PyMySQL，先执行:
#   pip install PyMySQL
try:
    import pymysql.cursors
    _CURSOR = pymysql.cursors.DictCursor
except ImportError:
    _CURSOR = None  # 延迟报错，start_all.py 会自动安装依赖

DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'AIIDS',
    'password': '123456',
    'database': 'ai_ids_system',
    'charset': 'utf8mb4',
    'cursorclass': _CURSOR,  # 查询结果自动转为字典
    'autocommit': True,
}

# Flask 配置
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 8080
FLASK_DEBUG = True
