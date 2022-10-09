from user import User

from werkzeug.security import check_password_hash


def get_user(email: str, password: str) -> User:
    result = User.query.filter_by(email=email).first()

    if result and check_password_hash(result.password, password):
        return result
