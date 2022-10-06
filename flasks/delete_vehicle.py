from vehicle import vehicle
from db import db
from sqlalchemy import delete


def delete_vehicle(find_vehicle_id: str):
    # Action mariaDB will have the execute using SQLAlchemy
    stmt = delete(vehicle).where(vehicle.vehicle_id == find_vehicle_id)
    # This are the function for deleteing a vehicle from the db using SQLAlchemy
    db.session.execute(stmt)
    db.session.commit()
