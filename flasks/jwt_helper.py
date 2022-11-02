import os
import jwt
import time

from secrets import token_urlsafe

from reset_token import Reset_Token

from db import db

RESET_TOKEN_LENGTH = 32


def generate_token(email: str, valid_for: int = 500) -> str:
    private_key = os.environ.get("PRIVATE_KEY").replace(r'\n', '\n')

    return jwt.encode({
        'email': email,
        'exp': time.time() + valid_for
    }, key=private_key, algorithm="RS256")


def decode_token(token: str) -> dict[str, str]:
    public_key = os.environ.get("PUBLIC_KEY").replace(r'\n', '\n')

    try:
        return jwt.decode(
            jwt=token,
            key=public_key,
            algorithms="RS256"
        )
    except Exception as e:
        raise Exception(e)


def generate_reset_password_token(email: str, valid_for: int = 500) -> str:
    private_key = os.environ.get("PRIVATE_KEY").replace(r'\n', '\n')

    reset_token = token_urlsafe(RESET_TOKEN_LENGTH)

    new_reset_token = Reset_Token(
        email=email,
        reset_token=reset_token,
        is_used=False
    )

    db.session.add(new_reset_token)
    db.session.commit()

    return jwt.encode({
        'email': email,
        'exp': time.time() + valid_for,
        'reset_token': reset_token
    }, key=private_key, algorithm="RS256")


def verify_token(token: str) -> str:
    try:
        return decode_token(token)['email']
    except Exception as e:
        raise Exception(e)


def can_reset_password(token: str) -> bool:
    try:
        token_dict = decode_token(token)

        email = token_dict['email']
        reset_token = token_dict['reset_token']

        reset_entry = Reset_Token.query.filter(
            Reset_Token.email == email,
            Reset_Token.reset_token == reset_token,
            Reset_Token.is_used == False
        ).first()

        if reset_entry:
            return True
        else:
            return False
    except Exception as e:
        raise Exception(e)


def password_resetted(token: str) -> None:
    try:
        token_dict = decode_token(token)

        email = token_dict['email']
        reset_token = token_dict['reset_token']

        update_dict = {
            "is_used": True,
        }

        Reset_Token.query.filter(
            Reset_Token.email == email,
            Reset_Token.reset_token == reset_token,
            Reset_Token.is_used == False
        ).update(update_dict)

        db.session.commit()
    except Exception as e:
        raise Exception(e)
