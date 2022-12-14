from user import User
from db import db

from input_validation import EMPTY_STRING

from werkzeug.security import generate_password_hash


def update_user(find_user_id: int, email: str, password: str, first_name: str, last_name: str, phone_number: str, license_blob: bytes, license_filename: str, license_mime: str, role: int, mfa_secret: str = EMPTY_STRING):
    # Action mariaDB will have the execute using SQLAlchemy
    # stmt = update(User).where(User.id == find_user_id).values(username=username, name=name, email=email, phone_number=phone_number, license_id=license_id, role=role)
    # This are the function for updating vehicle details from the db using SQLAlchemy
    # db.session.execute(stmt)

    update_dict = {
        "email": email,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
        "phone_number": phone_number,
        "license_blob": license_blob,
        "license_filename": license_filename,
        "license_mime": license_mime,
        "mfa_secret": mfa_secret,
        "role": role
    }

    if len(update_dict['license_blob']) == 0 and not update_dict['license_blob']:
        del update_dict['license_blob']
        del update_dict['license_filename']
        del update_dict['license_mime']

    if password != EMPTY_STRING:
        update_dict['password'] = generate_password_hash(password)

    # remove any key-value pair when value is empty str or none
    update_dict = {k: v for k, v in update_dict.items() if v is not None and v != EMPTY_STRING}

    t = User.query.filter(User.user_id == find_user_id, User.role >= 1, User.role <= 2)
    t.update(update_dict)
    db.session.commit()
