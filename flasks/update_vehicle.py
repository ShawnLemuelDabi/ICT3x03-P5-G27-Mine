from vehicle import vehicle
from sqlalchemy import update
from db import db


def update_vehicle(find_vehicle_id: str, changed_model: str, changed_license_plate: str, changed_type: str, change_location: str, change_price_per_unit: float, change_image: str):
    # Action mariaDB will have the execute using SQLAlchemy
    stmt = update(vehicle).where(vehicle.vehicle_id == find_vehicle_id).values(vehicle_model=changed_model, license_plate=changed_license_plate, vehicle_type=changed_type, location=change_location, image=change_image, price_per_unit=change_price_per_unit)  
    # This are the function for updating vehicle details from the db using SQLAlchemy
    db.session.execute(stmt)
    db.session.commit()
