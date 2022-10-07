from user import User
from db import db
from sqlalchemy import delete


def delete_user(find_user_id: str):
    # Action mariaDB will have the execute using SQLAlchemy
    stmt = delete(User).where(User.id == find_user_id)
    # This are the function for deleteing a vehicle from the db using SQLAlchemy
    db.session.execute(stmt)
    db.session.commit()