from user import User
from db import db


def create_user(username: str, password: str):

    new_user = User(
        username=username,
        password=password
    )

    db.session.add(new_user)
    db.session.commit()
