# Model for the  table
from db import db

# Blob Not recognised bt SQL Alchemy
# image = db.Column(db.BLOB)

# class for the data structure of the vehicle table


class vehicle(db.Model):
    # The table from the db to reference from 
    __tablename__ = "Vehicle"
    # Expectedd column and their data type for the vehicle table
    vehicle_id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer)
    vehicle_model = db.Column(db.String)
    license_plate = db.Column(db.String)
    is_available = db.Column(db.Boolean)
    vehicle_type = db.Column(db.String)
    location = db.Column(db.String)
    image = db.Column(db.String)
    price_per_unit = db.Column(db.Float)

    def __repr__(self):
        return 
        {
            'vehicle id': self.vehicle_id,
            'booking id': self.booking_id,
            'vehicle model': self.vehicle_model,
            'license plate': self.license_plate,
            'availbility': self.is_available,
            'vehicle type': self.vehicle_type,
            'location': self.location,
            'image': self.image,
            'prioce per unit': self.price_per_unit
        }
