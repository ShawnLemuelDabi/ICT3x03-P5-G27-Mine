from user import User
from db import db
from werkzeug.security import generate_password_hash


def create_user(username: str, password: str, name: str, email: str, phone_number: int, license_id: str, role: int):

    password = generate_password_hash(password, method='sha256')

    new_user = User(
        username=username,
        password=password,
        name=name,
        email=email,
        phone_number=phone_number,
        license_id=license_id,
        role=role
    )
    
    db.session.add(new_user)
    db.session.commit()
