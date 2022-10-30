from logging import INFO
# from logging import CRITICAL, ERROR, WARNING, INFO, DEBUG


class ErrorObject:
    user_message: str
    log_message: str
    log_severity: int

    def __init__(self, user_message: str, log_message: str, log_severity: str) -> None:
        self.user_message = user_message
        self.log_message = log_message
        self.log_severity = log_severity


class ErrorHandler:
    def __init__(self, app) -> None:
        self.__error_list__: list[ErrorObject] = []
        self.__app__ = app

    def commit_log(self) -> None:
        for i in self.__error_list__:
            self.__app__.logger.log(i.log_severity, i.log_message)

    def push(self, user_message: str, log_message: str, log_severity: int = INFO) -> None:
        self.__error_list__.append(ErrorObject(user_message=user_message, log_message=log_message, log_severity=log_severity))

    def first(self) -> ErrorObject:
        """
        Return the first element of the error list. This does not mutate the error list.
        """
        return self.__error_list__[0]

    def last(self) -> ErrorObject:
        """
        Return the last element of the error list. This does not mutate the error list.
        """
        return self.__error_list__[-1]

    def all(self) -> ErrorObject:
        """
        Return all elements of the error list. This is a shallow copy of the error list.
        """
        return self.__error_list__

    def has_error(self) -> bool:
        """
        Return whether the list has at least 1 error
        """
        return len(self.__error_list__) > 0
