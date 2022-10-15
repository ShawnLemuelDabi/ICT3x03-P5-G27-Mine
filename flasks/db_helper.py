from db import db

from vehicle import Vehicle


def vehicle_distinct_locations() -> list[str]:
    return [i.location for i in db.session.query(Vehicle.location).distinct()]
