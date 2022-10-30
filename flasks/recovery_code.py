from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Recovery_Codes(db.Model):
    __tablename__ = "recovery_codes"
    recovery_code_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    user_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    code = db.Column(sa_mysql.VARCHAR(8))
    is_used = db.Column(sa_mysql.TINYINT(1))

    user = db.relationship("User", back_populates="recovery_codes")
