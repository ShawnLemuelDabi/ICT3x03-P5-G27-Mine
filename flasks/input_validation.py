import re
import imghdr
import os

from datetime import datetime


EMPTY_STRING = ""
MEDIUMBLOB_BYTE_SIZE = 16777215

SQL_PRIMARY_KEY_REGEX_PATTERN = r"^[0-9]{1,11}$"
NAME_REGEX_PATTERN = r"^[A-Za-z ,.'-]{1,35}$"
PHONE_NUMBER_REGEX_PATTERN = r"^(8|9){1}[0-9]{7}$"
EMAIL_REGEX_PATTERN = r"^[a-zA-Z0-9.]{1,63}@((gmail|hotmail|yahoo|outlook).com|(?:sit\.)?singaporetech.edu.sg)$"
PAYNOW_REFERENCE_REGEX_PATTERN = r"^PN[0-9]{15}$"
DATE_REGEX_PATTERN = r"^\d{4}-\d{2}-\d{2}$"
PRICE_REGEX_PATTERN = r"^\d{1,5}(\.\d{1,2})?$"
LICENSE_PLATE_REGEX_PATTERN = r"^(S|E)[A-Z]{2}\d{1,4}[A-Z]{1}$"
FAULT_DESCRIPTION_REGEX_PATTERN = r"^[A-Za-z ,.'-]{5,500}$"
OTP_REGEX_PATTERN = r"^[0-9]{6}$"
RECOVERY_CODE_REGEX_PATTERN = r"^[0-9]{8}$"

PASSWORD_REGEX_PATTERN = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

DATE_FORMAT = "%Y-%m-%d"

MIN_PRICE = 0
MAX_PRICE = 100_000

MIN_PK_VAL = 0
MAX_PK_VAL = 100_000_000_000 - 1

ALLOWED_FILETYPE = ["jpg", "jpeg", "png"]


def validate_email(input_str: str) -> bool:
    """
    Validates if the input matches the following email domain:
    1. gmail.com
    2. hotmail.com
    3. yahoo.com
    4. outlook.com
    5. singaporetech.edu.sg

    returns a boolean value whether the input matches the email domain or not
    """

    validity = bool(re.match(EMAIL_REGEX_PATTERN, input_str))
    return validity


def validate_phone_number(input_str: str) -> bool:
    """
    Validates if the input is a singapore number or not.
    Input must start with 8 or 9, followed by 7 numbers.
    Returns a boolean value based on the validity.
    """

    validity = bool(re.match(PHONE_NUMBER_REGEX_PATTERN, input_str))
    return validity


def validate_name(input_str: str) -> bool:
    """
    Validates if the input contains character other than alphabets and space

    Returns a boolean value based on the validity.
    """

    validity = bool(re.match(NAME_REGEX_PATTERN, input_str))
    return validity


def validate_image(image_stream, image_filename, image_size) -> bool:
    """
    Validates if the image input has extension and magic header of either jpg or png,
    and size must be within the blob size.

    Returns a boolean value based on the validity.
    """
    validity = False

    file_format = imghdr.what(None, image_stream)

    if '.' in image_filename:
        image_ext = os.path.splitext(image_filename)[1].split(".")[1].lower()
    else:
        image_ext = ""

    if image_ext in ALLOWED_FILETYPE and image_size <= MEDIUMBLOB_BYTE_SIZE and file_format in ALLOWED_FILETYPE:
        validity = True

    return validity


def validate_date(date_str: str) -> bool:
    if bool(re.match(DATE_REGEX_PATTERN, date_str)):
        try:
            datetime.strptime(date_str, DATE_FORMAT)

            return True
        except ValueError:
            pass
    return False


def validate_sql_pk_int(pk_val: int) -> bool:
    return pk_val >= MIN_PK_VAL and pk_val <= MAX_PK_VAL


def validate_sql_pk_str(pk_str: str) -> bool:
    try:
        pk_val = int(pk_str)

        return validate_sql_pk_int(pk_val)
    except ValueError:
        return False


def validate_price(price_str: str) -> bool:
    if bool(re.match(PRICE_REGEX_PATTERN, price_str)):
        try:
            price = float(price_str)
            return price >= MIN_PRICE and price < MAX_PRICE
        except ValueError:
            pass
    return False


def validate_license_plate(license_plate_str: str) -> bool:
    return bool(re.match(LICENSE_PLATE_REGEX_PATTERN, license_plate_str))


def validate_paynow_reference_number(paynow_reference_number: str) -> bool:
    return bool(re.match(PAYNOW_REFERENCE_REGEX_PATTERN, paynow_reference_number))


def validate_fault_description(description_str: str) -> bool:
    return bool(re.match(FAULT_DESCRIPTION_REGEX_PATTERN, description_str))


def validate_password(password1: str, password2: str) -> bool:
    if password1 != password2:
        return False
    else:
        return bool(re.match(PASSWORD_REGEX_PATTERN, password1))


def validate_otp(otp: str) -> bool:
    return bool(re.match(OTP_REGEX_PATTERN, otp))


def validate_recovery_code(recovery_code: str) -> bool:
    return bool(re.match(RECOVERY_CODE_REGEX_PATTERN, recovery_code.replace(" ", EMPTY_STRING)))


def get_valid_file_types() -> str:
    return ",".join([f".{i}" for i in ALLOWED_FILETYPE])
