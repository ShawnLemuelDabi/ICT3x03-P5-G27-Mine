import re
import imghdr
import os


EMPTY_STRING = ""
MEDIUMBLOB_BYTE_SIZE = 16777215

NAME_REGEX_PATTERN = r"^[A-Za-z\ \,\.\'\-]{1,35}$"
PHONE_NUMBER_REGEX_PATTERN = r"^(8|9){1}[0-9]{7}$"
EMAIL_REGEX_PATTERN = r"^[a-zA-Z0-9\.]{1,63}@((gmail|hotmail|yahoo|outlook).com|singaporetech.edu.sg)$"
PAYNOW_REFERENCE_REGEX_PATTERN = r"^PN[0-9]{15}$"
DATE_REGEX_PATTERN = r"\d{4}\-\d{2}\-\d{2}"

DATE_FORMAT = "%Y-%m-%d"


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
    allowed_filetype = ["jpg", "jpeg", "png"]

    file_format = imghdr.what(None, image_stream)

    if '.' in image_filename:
        image_ext = os.path.splitext(image_filename)[1].split(".")[1].lower()
    else:
        image_ext = ""

    if image_ext in allowed_filetype and image_size <= MEDIUMBLOB_BYTE_SIZE and file_format in allowed_filetype:
        validity = True

    return validity


def validate_date(date_str: str) -> bool:
    return bool(re.match(DATE_REGEX_PATTERN, date_str))
