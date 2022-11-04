from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Reset_Token(db.Model):
    __tablename__ = "reset_tokens"
    reset_token_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    email = db.Column(sa_mysql.VARCHAR(255))
    reset_token = db.Column(sa_mysql.VARCHAR(255))
    is_used = db.Column(sa_mysql.TINYINT(1))
