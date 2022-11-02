from brute_force_attempt import Brute_Force_Attempt

from db import db

from datetime import datetime, timedelta

"""
LOGIN_LOCK_OUT_THRESHOLD number of attempts in
LOGIN_LOCK_OUT_DURATION amount of seconds will deem the account to be locked
"""
LOGIN_LOCK_OUT_THRESHOLD = 5
LOGIN_LOCK_OUT_DURATION = 300

PASSWORD_RESET_LOCK_OUT_THRESHOLD = 1
PASSWORD_RESET_LOCK_OUT_DURATION = 300


class BruteForceCategory:
    LOGIN = 'login'
    PASSWORD_RESET = 'password_reset'


def login_is_disabled(email: str) -> bool:
    """
    Checks if the user account can be logged into.

    This check should be done before OTP.
    """

    now_datetime = datetime.now()
    lookbehind_datetime = datetime.now() - timedelta(seconds=LOGIN_LOCK_OUT_DURATION)

    result = Brute_Force_Attempt.query.filter(
        Brute_Force_Attempt.attempted_category == BruteForceCategory.LOGIN,
        Brute_Force_Attempt.email == email,
        Brute_Force_Attempt.attempted_datetime.between(lookbehind_datetime, now_datetime)
    )

    return result.count() >= LOGIN_LOCK_OUT_THRESHOLD


def password_reset_is_disabled(email: str) -> bool:
    """
    Checks if the user account can reset password.
    """

    now_datetime = datetime.now()
    lookbehind_datetime = datetime.now() - timedelta(seconds=PASSWORD_RESET_LOCK_OUT_DURATION)

    result = Brute_Force_Attempt.query.filter(
        Brute_Force_Attempt.attempted_category == BruteForceCategory.PASSWORD_RESET,
        Brute_Force_Attempt.email == email,
        Brute_Force_Attempt.attempted_datetime.between(lookbehind_datetime, now_datetime)
    )

    return result.count() >= PASSWORD_RESET_LOCK_OUT_THRESHOLD


def failed_attempt(email: str, category: str) -> None:
    """
    Commits to database the brute force attempt by category
    """
    valid_categories = [BruteForceCategory.LOGIN, BruteForceCategory.PASSWORD_RESET]

    if category in valid_categories:
        new_attempt = Brute_Force_Attempt(
            email=email,
            attempted_datetime=datetime.now(),
            attempted_category=category
        )

        db.session.add(new_attempt)
        db.session.commit()
    else:
        raise ValueError(f"Invalid category '{category}'")
