from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from db import db
from sqlalchemy import or_, and_

from vehicle import Vehicle
from booking import Booking, BOOKING_STATUS, BookingStatus
from user import User

from create_booking import create_booking

from input_validation import EMPTY_STRING, DATE_FORMAT, validate_date, validate_paynow_reference_number, validate_phone_number, validate_sql_pk_str, validate_sql_pk_int
from error_handler import ErrorHandler

from datetime import datetime

bp_bookings = Blueprint('bp_bookings', __name__, template_folder='templates')


@bp_bookings.route("/bookings")
@flask_login.login_required
def customer_read_bookings() -> str:
    user: User = flask_login.current_user

    if user.is_customer():
        vehicles = Vehicle.query.all()
        bookings = Booking.query.filter_by(user_id=flask_login.current_user.user_id).all()

        return render_template(
            "bookings.html", bookings=bookings, vehicles=vehicles, status=BOOKING_STATUS
        )
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))

        err_handler.push(
            user_message="",
            log_message=f"User '{user.email}' of role '{user.get_role_str()}' is not allowed to use this route"
        )

        err_handler.commit_log()

        abort(401)


@bp_bookings.route("/bookings/create", methods=["GET", "POST"])
@flask_login.login_required
def customer_create_booking() -> str:
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
            return render_template("create_booking.html")
        else:
            start_date = request.form.get("start_date", EMPTY_STRING)
            end_date = request.form.get("end_date", EMPTY_STRING)
            vehicle_id = request.form.get("vehicle_id", EMPTY_STRING)
            paynow_number = request.form.get("paynow_number", EMPTY_STRING)

            if not validate_date(start_date):
                err_handler.push(
                    user_message="Start Date is invalid",
                    log_message=f"Start Date '{start_date}' is invalid. Request made by {user.email}"
                )
            if not validate_date(end_date):
                err_handler.push(
                    user_message="End Date is invalid",
                    log_message=f"End Date '{end_date}' is invalid. Request made by {user.email}"
                )
            if not validate_sql_pk_str(vehicle_id):
                err_handler.push(
                    user_message="Vehicle is invalid",
                    log_message=f"Vehicle ID '{vehicle_id}' is invalid. Request made by {user.email}"
                )
            if not validate_phone_number(paynow_number):
                err_handler.push(
                    user_message="PayNow Number is invalid",
                    log_message=f"PayNow Number is invalid. Request made by {user.email}"
                )
            if not flask_login.current_user.is_verified():
                err_handler.push(
                    user_message="Your account has not been verified yet!",
                    log_message=f"Unverified user tried to perform an action. Request made by {user.email}"
                )
            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")
            else:
                try:
                    start_date_obj = datetime.strptime(start_date, DATE_FORMAT)
                    end_date_obj = datetime.strptime(end_date, DATE_FORMAT)

                    booking_timedelta: datetime = end_date_obj - start_date_obj

                    if booking_timedelta.days <= 0:
                        err_handler.push(
                            user_message="Booking days is negative!",
                            log_message=f"Booking days is negative: {start_date} to {end_date}. Days: '{booking_timedelta.days}'. Request made by {user.email}"
                        )
                    else:
                        vehicle_is_booked = db.session.query(Booking.booking_id).filter(
                            Booking.vehicle_id == vehicle_id,
                            Booking.status != BookingStatus.BOOKING_CANCELLED,
                            or_(
                                and_(Booking.start_date > start_date, Booking.end_date < end_date),
                                and_(Booking.start_date < start_date, Booking.end_date > end_date),
                                and_(Booking.start_date < end_date, Booking.end_date > end_date),
                                and_(Booking.start_date < start_date, Booking.end_date > start_date),
                                and_(Booking.start_date == start_date, Booking.end_date == end_date)
                            )
                        )

                        if vehicle_is_booked.scalar() is None:
                            booking = create_booking(
                                start_date=start_date,
                                end_date=end_date,
                                user_id=flask_login.current_user.user_id,
                                vehicle_id=vehicle_id,
                                units_purchased=booking_timedelta.days,
                                paynow_number=paynow_number,
                                status=BOOKING_STATUS[0]
                            )
                            return render_template("booking_success.jinja2", booking=booking)
                        else:
                            err_handler.push(
                                user_message="Vehicle is already booked!",
                                log_message=f"Vehicle ID '{vehicle_id}' is already booked. Search query: {start_date} to {end_date}. Request made by {user.email}"
                            )
                except ValueError as e:
                    err_handler.push(
                        user_message="Invalid date",
                        log_message=f"Invalid date: {start_date} to {end_date}. {e}. Request made by {user.email}"
                    )

                if err_handler.has_error():
                    for i in err_handler.all():
                        flash(i.user_message, category="danger")

            err_handler.commit_log()

            return redirect(url_for("index"))


@bp_bookings.route("/bookings/read/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def customer_read_booking(booking_id: int) -> str:
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
    # booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id).first()

    # if booking:
    #     return render_template('edit_booking.html', booking=booking)
    # else:
    #     abort(404)


@bp_bookings.route("/bookings/update/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_update_booking(booking_id: int) -> str:
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
    # start_date = request.form.get("start_date")
    # end_date = request.form.get("end_date")

    # update_dict = {
    #     "start_date": start_date,
    #     "end_date": end_date,
    # }

    # booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id)

    # if booking.first():
    #     booking.update(update_dict)
    #     db.session.commit()
    #     flash("Booking updated!", category="success")
    #     return redirect(url_for("bp_bookings.customer_read_bookings"))
    # else:
    #     abort(404)


@bp_bookings.route("/bookings/delete/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_delete_booking(booking_id: int) -> str:
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
        if validate_sql_pk_int(booking_id):
            booking = Booking.query.filter(
                Booking.user_id == flask_login.current_user.user_id,
                Booking.booking_id == booking_id,
                Booking.status.in_(BOOKING_STATUS[:2])
            )

            if booking.first():
                update_dict = {
                    "status": BOOKING_STATUS[-1]
                }
                booking.update(update_dict)
                db.session.commit()
                flash("Booking deleted!", category="success")

                err_handler.push(
                    user_message="",
                    log_message=f"Booking ID '{booking_id}' has been deleted. Request made by '{user.email}'",
                    is_error=False
                )
            else:
                err_handler.push(
                    user_message="Booking cannot be found",
                    log_message=f"Booking ID '{booking_id}' cannot be found. Request made by '{user.email}'",
                )
        else:
            err_handler.push(
                user_message="Booking is invalid",
                log_message=f"Booking ID '{booking_id}' is invalid. Request made by '{user.email}'",
            )
        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i, category="danger")
        return redirect(url_for("bp_bookings.customer_read_bookings"))


@bp_bookings.route("/bookings/payment/<int:vehicle_id>/<string:start_date>/<string:end_date>", methods=["GET"])
@flask_login.login_required
def customer_confirm_booking(vehicle_id: int, start_date: str, end_date: str) -> str:
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
        if not validate_sql_pk_int(vehicle_id):
            err_handler.push(
                user_message="Vehicle is invalid",
                log_message=f"Vehicle ID '{vehicle_id}' is invalid. Request made by {user.email}"
            )

        if not validate_date(start_date):
            err_handler.push(
                user_message="Start Date is invalid",
                log_message=f"Start Date '{start_date}' is invalid. Request made by {user.email}"
            )

        if not validate_date(end_date):
            err_handler.push(
                user_message="End Date is invalid",
                log_message=f"End Date '{end_date}' is invalid. Request made by {user.email}"
            )

        start_date_obj = datetime.strptime(start_date, DATE_FORMAT)
        end_date_obj = datetime.strptime(end_date, DATE_FORMAT)

        booking_timedelta: datetime = end_date_obj - start_date_obj

        if booking_timedelta.days <= 0:
            err_handler.push(
                user_message="Booking days is negative!",
                log_message=f"Booking days is negative: {start_date} to {end_date}. Days: '{booking_timedelta.days}'. Request made by {user.email}"
            )

        if not err_handler.has_error():
            booking_details = {
                "start_date": start_date,
                "end_date": end_date,
                "days": booking_timedelta.days,
            }

            vehicle = Vehicle.query.filter_by(vehicle_id=vehicle_id).first()

            if vehicle:
                return render_template(
                    "booking_payment.jinja2", booking_details=booking_details, vehicle=vehicle
                )
            else:
                err_handler.push(
                    user_message="Invalid vehicle id",
                    log_message=f"Vehicle ID: {vehicle_id} not found on database. Request made by {user.email}"
                )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("index"))


@bp_bookings.route("/bookings/add_paynow_reference/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_add_paynow_reference_number(booking_id: int):
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
        paynow_reference_number = request.form.get("paynow_reference_number", EMPTY_STRING)

        update_dict = {
            "paynow_reference_number": paynow_reference_number,
        }

        if validate_paynow_reference_number(paynow_reference_number):
            booking = Booking.query.filter(Booking.user_id == flask_login.current_user.user_id, Booking.booking_id == booking_id, Booking.paynow_reference_number == None)

            if booking.first():
                booking.update(update_dict)
                db.session.commit()
                flash("Booking updated!", category="success")
                err_handler.push(
                    user_message="",
                    log_message=f"Booking ID '{booking_id}'updated. Request made by {user.email}",
                    is_error=False
                )
                err_handler.commit_log()
                return redirect(url_for("bp_bookings.customer_read_bookings"))
            else:
                abort(404)
        else:
            err_handler.push(
                user_message="Invalid reference number",
                log_message=f"Invalid reference number. Request made by {user.email}",
            )

            err_handler.commit_log()
            flash(err_handler.first().user_message, category="danger")

            return redirect(url_for("bp_bookings.customer_read_bookings"))
