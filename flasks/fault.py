from db import db
from sqlalchemy.dialects import mysql as sa_mysql

import base64


FAULT_STATUS = [
    'in progress',
    'resolved',
]

FAULT_CATEGORIES = [
    'tyre',
    'battery',
    'windscreen',
    'lights',
    'others',
]


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
    category = db.Column(sa_mysql.VARCHAR(255))
    status = db.Column(sa_mysql.VARCHAR(255))
    fault_image = db.Column(sa_mysql.MEDIUMBLOB)
    fault_filename = db.Column(sa_mysql.VARCHAR(255))
    fault_mime = db.Column(sa_mysql.VARCHAR(255))

    booking = db.relationship("Booking", back_populates="fault")

    def __repr__(self):
        return {
            'fault_id': self.fault_id,
            'booking_id': self.booking_id,
            'reported_date': self.reported_date,
            'description': self.description,
            'booking': self.booking,
        }

    def get_b64_image(self) -> str:
        return base64.b64encode(self.fault_image).decode('utf8')

    def get_b64_image_data_uri(self) -> str:
        return f"data:{self.fault_mime};base64,{self.get_b64_image()}"
