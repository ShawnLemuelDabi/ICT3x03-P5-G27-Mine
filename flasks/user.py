# from sqlalchemy import Column
# from sqlalchemy import ForeignKey
# from sqlalchemy import Integer
# from sqlalchemy import String
# from sqlalchemy.orm import declarative_base
# from sqlalchemy.orm import relationship

import email
from unicodedata import name
from flask_login import UserMixin

# from flask_sqlalchemy import SQLAlchemy

# Base = declarative_base()

from db import db


ROLE = {
    'guest': 0,
    'user': 1,
    'manager': 2,
    'admin': 3
}


class User(UserMixin, db.Model):
    #__tablename__ = "user_account"
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    password = db.Column(db.String)
    name = db.Column(db.String)
    email = db.Column(db.String)
    phone_number = db.Column(db.Integer)
    license_id = db.Column(db.String)
    role = db.Column(db.Integer)
    bookings = db.relationship('Booking', backref='User', passive_deletes=True)

    def __repr__(self):
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r},name={self.name!r}, email={self.email!r},phone_number={self.phone_number!r}, license_id={self.license_id!r}, role={self.role!r})"

    def get_id(self):
        return self.name

    def get_role(self):
        return self.role

    def allowed(self, role):
        return self.role >= role

