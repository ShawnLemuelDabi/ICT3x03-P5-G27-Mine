from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from db import db

from error_handler import ErrorHandler
from authorizer import universal_get_current_user_role

from booking import Booking, BOOKING_STATUS
from input_validation import validate_sql_pk_int
from user import Role

bp_bcp = Blueprint('bp_bcp', __name__, template_folder='templates')


@bp_bcp.route("/manager/bcp", methods=["GET"])
@flask_login.login_required
def manager_read_bookings() -> str:
    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        bookings = Booking.query.all()

        return render_template("manager_bcp.jinja2", bookings=bookings, valid_status=BOOKING_STATUS)
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))
        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_bcp.route("/manager/bcp/booking/create", methods=["POST"])
@flask_login.login_required
def manager_create_booking() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        err_handler.push(
            user_message="This should never be used?",
            log_message=f"User {user_email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, err_handler.first().user_message)
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email} to a route that is not implemented"
        )

        err_handler.commit_log()

        abort(401)


@bp_bcp.route("/manager/bcp/booking/read/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def manager_read_booking(booking_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        err_handler.push(
            user_message="This should never be used?",
            log_message=f"User {user_email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, err_handler.first().user_message)
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email} to a route that is not implemented"
        )

        err_handler.commit_log()

        abort(401)


@bp_bcp.route("/manager/bcp/booking/update/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def manager_update_booking(booking_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        status = request.form.get("status")

        if not validate_sql_pk_int(booking_id):
            err_handler.push(
                user_message="Invalid booking ID!",
                log_message=f"Invalid booking ID '{booking_id}'! Request made by {user_email}"
            )

        if status in BOOKING_STATUS:
            update_dict = {
                "status": status,
            }

            Booking.query.filter_by(booking_id=booking_id).update(update_dict)
            db.session.commit()

            flash("Booking updated!", category="success")

            err_handler.push(
                user_message="",
                log_message=f"Booking ID '{booking_id}' updated. Request made by user {user_email}",
                is_error=False
            )
        else:
            err_handler.push(
                user_message="Invalid status!",
                log_message=f"Invalid status {status}! Request made by {user_email}"
            )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for("bp_bcp.manager_read_bookings"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_bcp.route("/manager/bcp/booking/delete/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def manager_delete_booking(booking_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        if not validate_sql_pk_int(booking_id):
            err_handler.push(
                user_message="Invalid booking ID!",
                log_message=f"Invalid booking ID '{booking_id}'! Request made by {user_email}"
            )

        if not err_handler.has_error():
            Booking.query.filter_by(booking_id=booking_id).delete()
            db.session.commit()

            flash("Booking deleted!", category="success")
            err_handler.push(
                user_message="",
                log_message=f"Booking ID '{booking_id}' deleted. Request made by user {user_email}",
                is_error=False
            )

        err_handler.commit_log()
        return redirect(url_for("bp_bcp.manager_read_bookings"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)
