import pyotp

from user import User

from db import db


def enable_mfa(user: User) -> None:
    if user.mfa_secret:
        raise Exception(f"MFA is already enabled for {user.user_id}")
    else:
        new_mfa_secret = generate_mfa(user)
        return new_mfa_secret


def generate_mfa(user: User) -> str:
    new_mfa_secret: str = pyotp.random_base32()

    User.query.filter_by(user_id=user.user_id).update(
        {
            "mfa_secret": new_mfa_secret
        }
    )
    db.session.commit()

    return new_mfa_secret


def generate_mfa_uri(user: User) -> str:
    mfa_secret = generate_mfa(user)

    return pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=user.email, issuer_name='Shallot')


def verify_otp(user: User, otp: str) -> bool:
    if user.mfa_secret:
        return pyotp.TOTP(user.mfa_secret).verify(otp)
    else:
        raise Exception(f"{user.user_id} does not have MFA enabled")
