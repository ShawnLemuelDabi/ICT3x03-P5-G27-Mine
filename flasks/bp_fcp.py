from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from db import db

from fault import Fault
from booking import Booking
from user import Role

from authorizer import universal_get_current_user_role
from error_handler import ErrorHandler

bp_fcp = Blueprint('bp_fcp', __name__, template_folder='templates')


@bp_fcp.route("/manager/fcp", methods=["GET"])
def manager_read_faults() -> str:
    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        faults = Fault.query.all()
        bookings = Booking.query.all()

        return render_template("manager-faults.html", booking_list=bookings, fault_list=faults)
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))
        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_fcp.route("/manager/fcp/fault/create", methods=["POST"])
def manager_create_fault() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

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
    # booking_id = request.form.get("booking_id")
    # reported_date = request.form.get("reported_date")
    # description = request.form.get("description")

    # new_fault = Fault(
    #     booking_id=booking_id,
    #     reported_date=reported_date,
    #     description=description
    # )

    # db.session.add(new_fault)
    # db.session.commit()

    # flash("Fault created", category="success")

    # return redirect(url_for("bp_fcp.manager_read_faults"))


@bp_fcp.route("/manager/fcp/fault/read/<int:fault_id>", methods=["GET"])
def manager_read_fault(fault_id: int) -> str:
    # faults = Fault.query.filter_by(fault_id=fault_id).first()
    # bookings = Booking.query.all()

    # return redirect(url_for("manager_read_faults"))
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

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


@bp_fcp.route("/manager/fcp/fault/update/<int:fault_id>", methods=["POST"])
def manager_update_fault(fault_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        booking_id = request.form.get("booking_id")
        reported_date = request.form.get("reported_date")
        description = request.form.get("description")

        update_dict = {
            "booking_id": booking_id,
            "reported_date": reported_date,
            "description": description
        }

        update_dict = {k: v for k, v in update_dict.items() if v is not None}

        Fault.query.filter_by(fault_id=fault_id).update(update_dict)
        db.session.commit()

        flash("Fault updated!", category="success")

        err_handler.push(
            user_message="",
            log_message=f"Fault ID '{fault_id}' has been updated. Request made by user {user_email}"
        )

        err_handler.commit_log()
        return redirect(url_for("bp_fcp.manager_read_faults"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_fcp.route("/manager/fcp/fault/delete/<int:fault_id>", methods=["POST"])
def manager_delete_fault(fault_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        Fault.query.filter_by(fault_id=fault_id).delete()
        db.session.commit()

        flash("Fault deleted!", category="success")
        err_handler.push(
            user_message="",
            log_message=f"Fault ID '{fault_id}' has been deleted. Request made by user {user_email}"
        )
        return redirect(url_for("bp_fcp.manager_read_faults"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)
