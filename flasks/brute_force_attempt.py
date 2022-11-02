from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Brute_Force_Attempt(db.Model):
    __tablename__ = "brute_force_attempts"
    brute_force_attempt_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    email = db.Column(sa_mysql.VARCHAR(255))
    attempted_datetime = db.Column(sa_mysql.DATETIME)
    attempted_category = db.Column(sa_mysql.VARCHAR(255))
