from db import db
from sqlalchemy.dialects import mysql as sa_mysql

HISTORY_LIMIT = 5


class Password_History(db.Model):
    __tablename__ = "password_history"
    password_history_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    user_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    valid_till = db.Column(sa_mysql.DATETIME)
    password = db.Column(sa_mysql.VARCHAR(255))

    user = db.relationship("User", back_populates="password_history")
