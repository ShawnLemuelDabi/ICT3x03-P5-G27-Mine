from user import User
from db import db
from werkzeug.security import generate_password_hash


def create_user(email: str, password: str, first_name: str, last_name: str, phone_number: str, license_blob: bytes, license_filename: str, license_mime: str, role: int, mfa_secret: str = ""):

    password = generate_password_hash(password)

    if len(license_blob) == 0 and not license_filename:
        license_blob = r''.encode('utf8')
        license_filename = ""
        license_mime = ""

    new_user = User(
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        phone_number=phone_number,
        license_blob=license_blob,
        license_filename=license_filename,
        license_mime=license_mime,
        mfa_secret=mfa_secret,
        role=role
    )

    db.session.add(new_user)
    db.session.commit()
