import pyotp
from secrets import randbelow

from user import User
from recovery_code import Recovery_Codes

from db import db


def enable_mfa(user: User) -> str:
    if user.mfa_secret:
        raise Exception(f"MFA is already enabled for {user.user_id}")
    else:
        new_mfa_secret = generate_mfa(user)
        return new_mfa_secret


def generate_mfa() -> str:
    return pyotp.random_base32()


def generate_mfa_uri(user: User, mfa_secret: str) -> str:
    return pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=user.email, issuer_name='Shallot')


def verify_otp(user: User, otp: str) -> bool:
    if user.mfa_secret:
        return pyotp.TOTP(user.mfa_secret).verify(otp)
    else:
        raise Exception(f"{user.user_id} does not have MFA enabled")


def verify_otp_from_secret(secret: str, otp: str) -> bool:
    return pyotp.TOTP(secret).verify(otp)


def generate_recovery_code() -> str:
    """
    Get 8 random number (base10) from CSRNG as a string
    """
    return ''.join([str(randbelow(10)) for i in range(8)])


def generate_recovery_codes() -> list[str]:
    """
    Get 8 unique recovery codes
    Unique to the current list of recovery codes for the user
    """
    retval: list[str] = []

    while len(retval) < 8:
        recovery_code = generate_recovery_code()

        if recovery_code not in retval:
            retval.append(recovery_code)

    return retval


def confirm_mfa_enabled(user: User, mfa_secret: str, otp: str) -> list[str]:
    try:
        if verify_otp_from_secret(mfa_secret, otp):
            recovery_codes = generate_recovery_codes()

            User.query.filter_by(user_id=user.user_id).update(
                {
                    "mfa_secret": mfa_secret
                }
            )

            recovery_codes_objs = [Recovery_Codes(user_id=user.user_id, code=i, is_used=False) for i in recovery_codes]

            db.session.add_all(recovery_codes_objs)
            db.session.commit()

            return recovery_codes
        else:
            raise Exception("Invalid OTP")
    except Exception as e:
        raise Exception(e)
