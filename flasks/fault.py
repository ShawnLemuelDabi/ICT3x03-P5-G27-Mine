from db import db
from sqlalchemy.dialects import mysql as sa_mysql


class Fault(db.Model):
    __tablename__ = "faults"
    fault_id = db.Column(sa_mysql.INTEGER(11), primary_key=True)
    booking_id = db.Column(
        sa_mysql.INTEGER(11),
        db.ForeignKey("bookings.booking_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    reported_date = db.Column(sa_mysql.DATETIME)
    description = db.Column(sa_mysql.VARCHAR(255))

    booking = db.relationship("Booking", back_populates="fault")

    def __repr__(self):
        return {
            'fault_id': self.fault_id,
            'booking_id': self.booking_id,
            'reported_date': self.reported_date,
            'description': self.description,
            'booking': self.booking,
        }
