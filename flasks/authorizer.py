from flask import url_for, redirect, abort, Response

from user import User, Role

from flask_login import AnonymousUserMixin


def http_unauthorized(msg: str = "Unauthorized", redirect_to_login: bool = False) -> Response:
    if redirect_to_login:
        return redirect(url_for("login"))
    else:
        return abort(401, msg)


def universal_get_current_user_role(current_user: User | AnonymousUserMixin) -> int:
    if current_user.is_anonymous:
        return Role.ANONYMOUS_USER
    else:
        return current_user.get_role()
