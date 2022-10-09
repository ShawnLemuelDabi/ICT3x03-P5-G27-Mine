from vehicle import vehicle
from db import db

# Need help on how to input Images


def create_vehicle(vehicle_model: str, license_plate: str, vehicle_type: str, location: str, price_per_unit: float, image: bytes, image_name: str, image_mime: str):
    # Structure of the data to insert into the db table for vehicle
    new_vehicle = vehicle(
        vehicle_model=vehicle_model,
        license_plate=license_plate,
        is_available=True,
        vehicle_type=vehicle_type,
        location=location,
        image=image,
        image_name=image_name,
        image_mime=image_mime,
        price_per_unit=price_per_unit
    )

    # This are the function for creating and inserting a new vehicle into the db using SQLAlchemy
    db.session.add(new_vehicle)
    db.session.commit()
