from sqlalchemy.dialects import mysql as sa_mysql
from flask_login import UserMixin

from db import db

import base64


class Role:
    ANONYMOUS_USER = 0
    UNVERIFIED_USER = 1
    VERIFIED_USER = 2
    MANAGER = 3
    ADMIN = 4


ROLE = {
    Role.ANONYMOUS_USER: 'anonymous user',
    Role.UNVERIFIED_USER: 'unverified user',
    Role.VERIFIED_USER: 'verified user',
    Role.MANAGER: 'manager',
    Role.ADMIN: 'admin',
}


class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    email = db.Column(sa_mysql.VARCHAR(255))
    first_name = db.Column(sa_mysql.VARCHAR(255))
    last_name = db.Column(sa_mysql.VARCHAR(255))
    password = db.Column(sa_mysql.VARCHAR(255))
    phone_number = db.Column(sa_mysql.VARCHAR(15))
    license_blob = db.Column(sa_mysql.MEDIUMBLOB)
    license_filename = db.Column(sa_mysql.VARCHAR(255))
    license_mime = db.Column(sa_mysql.VARCHAR(255))
    mfa_secret = db.Column(sa_mysql.VARCHAR(255))
    role = db.Column(sa_mysql.INTEGER(11))

    bookings = db.relationship("Booking", back_populates="user")

    recovery_codes = db.relationship("Recovery_Codes", back_populates="user")

    password_history = db.relationship("Password_History", back_populates="user")

    def __repr__(self):
        return f"User(user_id={self.user_id!r}, email={self.email!r}, first_name={self.first_name!r}, last_name={self.last_name!r}, password={self.password!r}, phone_number={self.phone_number!r}, license_blob={self.license_blob!r}, license_filename={self.license_filename!r}, license_mime={self.license_mime!r}, mfa_secret={self.mfa_secret!r}, role={self.role!r})"

    def get_id(self) -> int:
        return self.user_id

    def get_role(self) -> int:
        return self.role

    def get_role_str(self) -> str:
        return ROLE[self.role]

    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def is_manager(self) -> bool:
        return self.role == Role.MANAGER

    def is_customer(self) -> bool:
        return self.role <= Role.VERIFIED_USER

    def is_verified(self) -> bool:
        return self.role > Role.UNVERIFIED_USER and self.role <= Role.VERIFIED_USER

    # i think its a bad idea to do integer comparison as manager and admin cannot create booking
    # def allowed(self, role):
    #     return self.role >= role

    def get_b64_license(self) -> str:
        return base64.b64encode(self.license_blob).decode('utf8')

    def get_b64_license_data_uri(self) -> str:
        return f"data:{self.license_mime};base64,{self.get_b64_license()}"
