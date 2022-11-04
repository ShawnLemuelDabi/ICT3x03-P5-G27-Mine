# from logging import INFO
from logging import CRITICAL, ERROR, WARNING, INFO, DEBUG

from flask import Flask


class LogLevel:
    debug = DEBUG
    info = INFO
    warning = WARNING
    error = ERROR
    critical = CRITICAL


class ErrorObject:
    user_message: str
    log_message: str
    log_severity: int

    def __init__(self, user_message: str, log_message: str, log_severity: str, is_error: bool) -> None:
        self.user_message = user_message
        self.log_message = log_message
        self.log_severity = log_severity
        self.is_error = is_error


class ErrorHandler:
    def __init__(self, app: Flask, request: dict) -> None:
        self.__error_list__: list[ErrorObject] = []
        self.__app__ = app
        self.__request__ = request

    def commit_log(self) -> None:
        for i in self.__error_list__:
            self.__app__.logger.log(i.log_severity, i.log_message)

    def push(self, user_message: str, log_message: str, log_severity: int = WARNING, is_error: bool = True) -> None:
        self.__error_list__.append(
            ErrorObject(
                user_message=user_message,
                log_message=f"User-Agent: {self.__request__.get('User-Agent')}, X-Forwarded-For: {self.__request__.get('X-Forwarded-For')}, CF-Connecting-IP: {self.__request__.get('​​CF-Connecting-IP')}, {log_message}",
                log_severity=log_severity,
                is_error=is_error
            )
        )

    def first(self) -> ErrorObject:
        """
        Return the first element of the error list. This does not mutate the error list.
        """
        return self.all(only_errors=True)[0]

    def last(self) -> ErrorObject:
        """
        Return the last element of the error list. This does not mutate the error list.
        """
        return self.all(only_errors=True)[-1]

    def all(self, only_errors: bool = True) -> list[ErrorObject]:
        """
        Return all elements of the error list. This is a shallow copy of the error list.

        only_errors flag will toggle whether non-errors should return as well
        """
        if only_errors:
            return [i for i in self.__error_list__ if i.is_error]
        else:
            return self.__error_list__

    def has_error(self) -> bool:
        """
        Return whether the list has at least 1 error
        """
        return len(self.all(only_errors=True)) > 0
