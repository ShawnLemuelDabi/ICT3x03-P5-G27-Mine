# Model for the  table
from db import db

from sqlalchemy.dialects import mysql as sa_mysql

# class for the data structure of the vehicle table


class vehicle(db.Model):
    # The table from the db to reference from
    __tablename__ = "vehicles"
    # Expected column and their data type for the vehicle table
    vehicle_id = db.Column(db.Integer, primary_key=True)
    vehicle_model = db.Column(db.String)
    license_plate = db.Column(db.String)
    is_available = db.Column(db.Boolean)
    vehicle_type = db.Column(db.String)
    location = db.Column(db.String)
    image = db.Column(sa_mysql.MEDIUMBLOB)
    image_name = db.Column(db.String)
    image_mime = db.Column(db.String)
    price_per_unit = db.Column(db.Float)

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
