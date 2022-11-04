from datetime import date
from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from db import db

from input_validation import EMPTY_STRING, DATE_FORMAT, validate_fault_description, validate_image, validate_sql_pk_str
from error_handler import ErrorHandler

from fault import Fault, FAULT_CATEGORIES, FAULT_STATUS
from booking import Booking, BookingStatus
from user import User

bp_faults = Blueprint('bp_faults', __name__, template_folder='templates')


@bp_faults.route("/faults")
@flask_login.login_required
def customer_read_faults() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user: User = flask_login.current_user

    if not user.is_customer():
        err_handler.push(
            user_message="",
            log_message=f"User '{user.email}' of role '{user.get_role_str()}' is not allowed to use this route"
        )
        err_handler.commit_log()

        abort(401)
    else:
        user_id = flask_login.current_user.user_id

        faults = Fault.query.join(Fault.booking, aliased=True).filter_by(user_id=user_id).all()
        bookings = Booking.query.filter_by(user_id=user_id).all()

        return render_template("user-faults.html", booking_list=bookings, fault_list=faults)


@bp_faults.route("/fault/read/<int:fault_id>")
@flask_login.login_required
def customer_read_fault(fault_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user: User = flask_login.current_user

    if user.is_customer():
        err_handler.push(
            user_message="",
            log_message=f"User {user.email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, "This should never be used?")
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user.email} to a route that is not implemented."
        )

        err_handler.commit_log()

        abort(401)


@bp_faults.route("/fault/create", methods=["GET", "POST"])
@bp_faults.route("/fault/create/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def customer_create_fault(booking_id: str = None):
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user: User = flask_login.current_user

    if not user.is_customer():
        err_handler.push(
            user_message="",
            log_message=f"User '{user.email}' of role '{user.get_role_str()}' is not allowed to use this route"
        )

        err_handler.commit_log()

        abort(401)
    else:
        if request.method == "GET":
            faults = db.session.query(Fault.booking_id).join(Fault.booking, aliased=True).filter(Booking.user_id == flask_login.current_user.user_id).subquery()
            bookings = Booking.query.filter(
                Booking.user_id == flask_login.current_user.user_id,
                Booking.status == BookingStatus.BOOKING_CONFIRMED,
                Booking.booking_id.notin_(faults)
            ).all()

            return render_template("fault_create_form.jinja2", booking_id=booking_id, bookings=bookings, valid_categories=FAULT_CATEGORIES)
        elif request.method == "POST":
            uploaded_file = request.files['fault_image']

            booking_id = request.form.get("booking_id")
            reported_date = date.today().strftime(DATE_FORMAT)
            description = request.form.get("description")
            category = request.form.get("category")
            description = request.form.get("description")

            fault_image = uploaded_file.stream.read()
            fault_blob_size = len(fault_image)
            fault_filename = uploaded_file.filename or EMPTY_STRING
            fault_mime = uploaded_file.mimetype

            if booking_id and not validate_sql_pk_str(booking_id):
                err_handler.push(
                    user_message="Invalid booking ID provided.",
                    log_message=f"Invalid booking ID provided. Booking ID '{booking_id}'. Request made by user {user.mail}"
                )

            if category not in FAULT_CATEGORIES:
                err_handler.push(
                    user_message="Invalid category",
                    log_message=f"Invalid category '{category}'. Request made by {user.email}"
                )

            if not validate_image(image_stream=fault_image, image_filename=fault_filename, image_size=fault_blob_size):
                err_handler.push(
                    user_message="Invalid image provided. Only jpg, jpeg & png allowed. Max size of image should be 16M",
                    log_message=f"Invalid image provided. Image name '{fault_filename}' of mime type '{fault_mime}' uploaded. Image size {fault_blob_size} bytes. Request made by user {user.email}"
                )

            if not validate_fault_description(description):
                err_handler.push(
                    user_message="Invalid description",
                    log_message=f"Invalid description. Length: '{len(description)}', description content: '{description}'. Request made by {user.email}"
                )

            if not err_handler.has_error():
                # check if booking exists and is valid to create a fault
                faults = db.session.query(Fault.booking_id).join(Fault.booking, aliased=True).filter(Booking.user_id == flask_login.current_user.user_id, Fault.booking_id == booking_id).subquery()
                booking = Booking.query.filter(
                    Booking.user_id == flask_login.current_user.user_id,
                    Booking.status == BookingStatus.BOOKING_CONFIRMED,
                    Booking.booking_id.notin_(faults)
                )

                if booking.first() is not None:
                    new_fault = Fault(
                        booking_id=booking_id,
                        reported_date=reported_date,
                        description=description,
                        category=category,
                        status=FAULT_STATUS[0],
                        fault_image=fault_image,
                        fault_filename=fault_filename,
                        fault_mime=fault_mime,
                    )

                    db.session.add(new_fault)
                    db.session.commit()

                    flash("Fault created successfully!", category="success")
                    err_handler.push(
                        user_message="",
                        log_message=f"Fault created successfully. Request made by {user.email}",
                        is_error=False
                    )
                else:
                    err_handler.push(
                        user_message="Booking not found",
                        log_message=f"Booking ID '{booking_id}' not found. Request made by {user.email}"
                    )

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")

            return redirect(url_for("bp_faults.customer_read_faults"))


@bp_faults.route("/fault/update/<int:fault_id>", methods=["POST"])
@flask_login.login_required
def customer_update_fault(fault_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user: User = flask_login.current_user

    if user.is_customer():
        err_handler.push(
            user_message="This should never be used?",
            log_message=f"User {user.email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, "This should never be used?")
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user.email} to a route that is not implemented"
        )

        err_handler.commit_log()

        abort(401)
    # booking_id = request.form.get("booking_id")
    # reported_date = request.form.get("reported_date")
    # description = request.form.get("description")

    # update_dict = {
    #     "booking_id": booking_id,
    #     "reported_date": reported_date,
    #     "description": description
    # }

    # update_dict = {k: v for k, v in update_dict.items() if v is not None}

    # Fault.query.filter_by(fault_id=fault_id).update(update_dict)
    # db.session.commit()

    # flash("Fault updated!", category="success")
    # return redirect(url_for("bp_faults.customer_read_faults"))


@bp_faults.route("/fault/delete/<int:fault_id>", methods=["POST"])
@flask_login.login_required
def customer_delete_fault(fault_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user: User = flask_login.current_user

    if user.is_customer():
        err_handler.push(
            user_message="This should never be used?",
            log_message=f"User {user.email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, "This should never be used?")
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user.email} to a route that is not implemented"
        )

        err_handler.commit_log()

        abort(401)
    # Fault.query.filter_by(fault_id=fault_id).delete()
    # db.session.commit()
    # flash("Fault deleted!", category="success")
    # return redirect(url_for("bp_faults.customer_read_faults"))
