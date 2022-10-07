import re


def validate_input(input_str: list[str], regex: list[bytes], return_stripped: bool) -> list[str]:
    """
    Validates the list of strings against the regex using the index as the mapping.

    Part of the string(s) that matches the regex will be returned if return_stripped is true.
    If return_stripped is false, empty string will be returned even if matches are found.
    """

    if len(input_str) != len(regex):
        raise ValueError(f"Unequal elements length for input arguments. {len(input_str)} - {len(regex)}")

    retval: list[str] = []

    for test_str, regex_pattern in zip(input_str, regex):
        result: list[str] = re.findall(regex_pattern, test_str)

        result_str = "".join(result)

        retval.append(result_str)

    return retval
