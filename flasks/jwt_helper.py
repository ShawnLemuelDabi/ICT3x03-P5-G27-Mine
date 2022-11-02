import os
import jwt
import time

def generate_token(email: str, valid_for: int = 500) -> str:
    private_key=os.environ.get("PRIVATE_KEY").replace(r'\n', '\n')
    return jwt.encode({
        'email': email,
        'exp': time.time() + valid_for
    }, key=private_key, algorithm="RS256")

def verify_token(token: str) -> str:
    public_key=os.environ.get("PUBLIC_KEY").replace(r'\n', '\n')
    try:
        return jwt.decode(
            jwt=token,
            key=public_key,
            algorithms="RS256"
        )['email']
    except Exception as e:
        raise Exception(e)