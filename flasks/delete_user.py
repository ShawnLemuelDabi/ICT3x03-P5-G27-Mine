from user import User
from db import db


def delete_user(find_user_id: str):
    # This are the function for deleting a vehicle from the db using SQLAlchemy
    User.query.filter_by(user_id=find_user_id).delete()
    db.session.commit()
