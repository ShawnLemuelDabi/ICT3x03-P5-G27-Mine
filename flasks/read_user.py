from db import db
from user import User


def read_user():
    # Return a table details of table User from the db
    return db.session.query(User)
