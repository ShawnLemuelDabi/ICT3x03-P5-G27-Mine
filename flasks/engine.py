import os

# from sqlalchemy import create_engine

DB_PROTO = "mysql+pymysql"
DB_HOST = "db"
DB_PORT = "3306"
DB_USER = os.environ.get("MYSQL_USER") or "root"
DB_PASS = os.environ.get("MYSQL_PASSWORD") or "root"
DB_SCHEMA = os.environ.get("MYSQL_DATABASE") or "ssd"

# engine2 = create_engine(f'{DB_PROTO}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_SCHEMA}')
engine_uri = f'{DB_PROTO}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_SCHEMA}'
