import os
import jwt
import time


def generate_token(email: str, valid_for: int = 500) -> str:
    return jwt.encode({
        'email': email,
        'exp': time.time() + valid_for
    }, key=os.environ.get("RESET_PASSWORD_JWT_KEY"), algorithm="HS256")


def verify_token(token: str) -> str:
    try:
        return jwt.decode(
            jwt=token,
            key=os.environ.get("RESET_PASSWORD_JWT_KEY"),
            algorithms="HS256"
        )['email']
    except Exception as e:
        raise Exception(e)
