from user import User
from sqlalchemy import update
from db import db


def update_user(find_user_id: int, username: str, name: str, email: str, phone_number: int, license_id: str, role: int):
    # Action mariaDB will have the execute using SQLAlchemy
    stmt = update(User).where(User.id == find_user_id).values(username=username, name=name, email=email, phone_number=phone_number, license_id=license_id, role=role)  
    # This are the function for updating vehicle details from the db using SQLAlchemy
    db.session.execute(stmt)
    db.session.commit()