import re, imghdr, os


EMPTY_STRING = ""
MEDIUMBLOB_BYTE_SIZE = 16777215


def validate_str_input(input_str: list[str], regex: list[bytes], return_stripped: bool) -> list[str]:
    """
    Validates the list of strings against the regex using the index as the mapping.

    Part of the string(s) that matches the regex will be returned if return_stripped is true.
    If return_stripped is false, empty string will be returned even if matches are found.
    """

    if len(input_str) != len(regex):
        raise ValueError(f"Unequal elements length for input arguments. {len(input_str)} - {len(regex)}")

    if type(input_str) != list or any([type(input_str) != str for i in input_str]):
        raise TypeError("input_str should be list[str]!")

    if type(regex) != list or any([type(regex) != bytes for i in regex]):
        raise TypeError("regex should be list[bytes]!")

    if type(return_stripped) != bool:
        raise TypeError("return_stripped should be bool!")

    retval: list[str] = []

    for test_str, regex_pattern in zip(input_str, regex):
        result: list[str] = re.findall(regex_pattern, test_str)

        result_str = "".join(result)

        retval.append(result_str)

    return retval

def validate_email(input_str: str):
    """
    Validates if the input matches the following email domain:
    1. gmail.com
    2. hotmail.com
    3. yahoo.com
    4. outlook.com
    5. singaporetech.edu.sg

    returns a boolean value whether the input matches the email domain or not
    """

    regex_pattern = ".*\@((gmail|hotmail|yahoo|outlook).com|singaporetech.edu.sg)$"
    validity = bool(re.match(regex_pattern, input_str))
    return validity

def validate_phone_number(input_str: str):
    """
    Validates if the input is a singapore number or not.
    Input must start with 8 or 9, followed by 7 numbers. 
    Returns a boolean value based on the validity.
    """

    regex_pattern = "^(8|9){1}[0-9]{7}$"
    validity = bool(re.match(regex_pattern, input_str))
    return validity

def validate_name(input_str: str):
    """
    Validates if the input contains character other than alphabets and space

    Returns a boolean value based on the validity.
    """

    regex_pattern = "^[a-zA-Z ]+$"
    validity = bool(re.match(regex_pattern, input_str))
    return validity

def validate_image(image_stream, image_filename, image_size):
    """
    Validates if the image input has extension and magic header of either jpg or png, 
    and size must be within the blob size.

    Returns a boolean value based on the validity.
    """
    validity = True
    allowed_filetype = ['jpg', 'png']

    format=  imghdr.what(None, image_stream)
    image_ext = os.path.splitext(image_filename)[1].split(".")[1]

    if image_ext not in allowed_filetype or image_size >= MEDIUMBLOB_BYTE_SIZE or format not in allowed_filetype:
        validity = False

    return validity
