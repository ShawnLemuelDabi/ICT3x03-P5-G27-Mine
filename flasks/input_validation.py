import re


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
