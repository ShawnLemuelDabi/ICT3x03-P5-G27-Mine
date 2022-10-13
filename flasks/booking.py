from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Booking(db.Model):
    __tablename__ = "bookings"
    booking_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    vehicle_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("vehicles.vehicle_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    user_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    start_date = db.Column(sa_mysql.DATETIME)
    end_date = db.Column(sa_mysql.DATETIME)
    units_purchased = db.Column(sa_mysql.INTEGER(11))
    is_paid = db.Column(sa_mysql.TINYINT(1))

    user = db.relationship("User", back_populates="bookings")
    vehicle = db.relationship("vehicle", back_populates="booking")
    fault = db.relationship("Fault", back_populates="booking")
