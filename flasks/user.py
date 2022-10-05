from flask_login import UserMixin

from db import db


class User(UserMixin, db.Model):
    __tablename__ = "user_account"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    password = db.Column(db.String)

    def __repr__(self):
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r})"
