import os

DB_PROTO = "mysql+pymysql"
DB_HOST = os.environ.get("MYSQL_HOST")
DB_PORT = os.environ.get("MYSQL_PORT")
DB_USER = os.environ.get("MYSQL_USER")
DB_PASS = os.environ.get("MYSQL_PASSWORD")
DB_SCHEMA = os.environ.get("MYSQL_DATABASE")

engine_uri = f'{DB_PROTO}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_SCHEMA}'
