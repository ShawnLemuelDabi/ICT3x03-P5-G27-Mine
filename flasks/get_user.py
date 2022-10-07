# from sqlalchemy.orm import Session

# from model.engine.engine import engine2

from user import User


def get_user(username: str, password: str) -> User:
    result = User.query.filter_by(username=username).first()

    if result and result.password == password:
        return result
