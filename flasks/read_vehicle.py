from vehicle import Vehicle
from db import db


def read_vehicle():
    # Return a table details of table vehicle from the db
    return db.session.query(Vehicle).all()
