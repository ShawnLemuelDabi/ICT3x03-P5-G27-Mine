# Model for the  table
from db import db

from sqlalchemy.dialects import mysql as sa_mysql

import base64


class Vehicle(db.Model):
    # The table from the db to reference from
    __tablename__ = "vehicles"
    # Expected column and their data type for the vehicle table
    vehicle_id = db.Column(db.Integer, primary_key=True)
    vehicle_model = db.Column(sa_mysql.VARCHAR(255))
    license_plate = db.Column(sa_mysql.VARCHAR(255))
    is_available = db.Column(sa_mysql.TINYINT(255))
    vehicle_type = db.Column(sa_mysql.VARCHAR(255))
    location = db.Column(sa_mysql.VARCHAR(255))
    image = db.Column(sa_mysql.MEDIUMBLOB)
    image_name = db.Column(sa_mysql.VARCHAR(255))
    image_mime = db.Column(sa_mysql.VARCHAR(255))
    price_per_unit = db.Column(sa_mysql.FLOAT)

    booking = db.relationship("Booking", back_populates="vehicle")

    def get_b64_image(self) -> str:
        return base64.b64encode(self.image).decode('utf8')

    def get_b64_image_data_uri(self) -> str:
        return f"data:{self.image_mime};base64,{self.get_b64_image()}"

    def __repr__(self):
        return {
            'vehicle_id': self.vehicle_id,
            'booking_id': self.booking_id,
            'vehicle_model': self.vehicle_model,
            'license_plate': self.license_plate,
            'is_available': self.is_available,
            'vehicle_type': self.vehicle_type,
            'location': self.location,
            'image': self.image,
            'image_name': self.image_name,
            'image_mime': self.image_mime,
            'price_per_unit': self.price_per_unit
        }
