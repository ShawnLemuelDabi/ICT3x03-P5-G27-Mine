from flask_login import UserMixin

from db import db

from sqlalchemy.dialects import mysql as sa_mysql


class User(UserMixin, db.Model):
    __tablename__ = "user_account"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(sa_mysql.VARCHAR(255))
    password = db.Column(sa_mysql.VARCHAR(255))

    def __repr__(self):
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r})"
