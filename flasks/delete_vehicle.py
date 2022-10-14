from vehicle import Vehicle
from db import db


def delete_vehicle(find_vehicle_id: str):
    # Action mariaDB will have the execute using SQLAlchemy
    # This are the function for deleting a vehicle from the db using SQLAlchemy
    Vehicle.query.filter_by(vehicle_id=find_vehicle_id).delete()
    db.session.commit()
