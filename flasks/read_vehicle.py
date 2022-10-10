from vehicle import vehicle
from db import db


def read_vehicle():
    # Return a table details of table vehicle from the db
    return db.session.query(vehicle).all()
