from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Booking(db.Model):
    __tablename__ = "bookings"
    booking_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    # vehicle_id = db.Column(
    #     db.Integer,
    #     db.ForeignKey("Vehicle.vehicle_id", ondelete="CASCADE", onupdate="CASCADE"),
    #     nullable=False,
    # )
    user_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    start_date = db.Column(sa_mysql.DATETIME)
    end_date = db.Column(sa_mysql.DATETIME)
    units_purchased = db.Column(sa_mysql.INTEGER(11))
    is_paid = db.Column(sa_mysql.TINYINT(1))
