from vehicle import vehicle
from db import db

# Need help on how to input Images


def create_vehicle(model: str, license_plate: str, type: str, location: str, price_per_unit: float, image: str):
    # Structure of the data to insert into the db table for vehicle
    new_vehicle = vehicle(
        vehicle_model=model,
        license_plate=license_plate,
        is_available=True,
        vehicle_type=type,
        location=location,
        image="No images",
        price_per_unit=price_per_unit
    )

    # This are the function for creating and inserting a new vehicle into the db using SQLAlchemy
    db.session.add(new_vehicle)
    db.session.commit()
