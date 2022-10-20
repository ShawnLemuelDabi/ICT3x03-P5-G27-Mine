from db import db

from vehicle import Vehicle


def vehicle_distinct_locations() -> list[str]:
    return [i.location for i in db.session.query(Vehicle.location).distinct()]


def vehicle_distinct_vehicle_types() -> list[str]:
    return [i.vehicle_type for i in db.session.query(Vehicle.vehicle_type).distinct()]
