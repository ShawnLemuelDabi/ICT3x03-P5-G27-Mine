from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from db import db

from vehicle import Vehicle
from booking import Booking, BOOKING_STATUS

from create_booking import create_booking

from input_validation import EMPTY_STRING
from error_handler import ErrorHandler

from datetime import datetime

bp_bookings = Blueprint('bp_bookings', __name__, template_folder='templates')


@bp_bookings.route("/bookings")
@flask_login.login_required
def customer_read_bookings() -> str:
    vehicles = Vehicle.query.all()
    bookings = Booking.query.filter_by(user_id=flask_login.current_user.user_id).all()

    return render_template(
        "bookings.html", bookings=bookings, vehicles=vehicles, status=BOOKING_STATUS
    )


@bp_bookings.route("/bookings/create", methods=["GET", "POST"])
@flask_login.login_required
def customer_create_booking() -> str:
    if request.method == "GET":
        return render_template("create_booking.html")
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))

        start_date = request.form.get("start_date", EMPTY_STRING)
        end_date = request.form.get("end_date", EMPTY_STRING)
        vehicle_id = request.form.get("vehicle_id", EMPTY_STRING)
        paynow_number = request.form.get("paynow_number", EMPTY_STRING)

        if not start_date:
            flash("Start Date cannot be empty", category="danger")
        elif not end_date:
            flash("End Date cannot be empty", category="danger")
        elif not paynow_number:
            flash("PayNow Number cannot be empty", category="danger")
        elif not flask_login.current_user.is_verified():
            flash("Your account has not been verified yet!", category="danger")
        else:
            try:
                start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
                end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")

                booking_timedelta: datetime = end_date_obj - start_date_obj

                if booking_timedelta.days <= 0:
                    flash("Booking days is negative!", category="danger")
                else:
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
            except ValueError as e:
                err_handler.push(
                    user_message="Invalid date",
                    log_message=f"Invalid date: {start_date} to {end_date}. {e}"
                )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for("index"))


@bp_bookings.route("/bookings/read/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def customer_read_booking(booking_id: int) -> str:
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id).first()

    if booking:
        return render_template('edit_booking.html', booking=booking)
    else:
        abort(404)


@bp_bookings.route("/bookings/update/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_update_booking(booking_id: int) -> str:
    return abort(501, "This should never be used?")
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
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id)

    if booking.first():
        update_dict = {
            "status": BOOKING_STATUS[-1]
        }
        booking.update(update_dict)
        db.session.commit()
        flash("Booking deleted!", category="success")
        return redirect(url_for("bp_bookings.customer_read_bookings"))
    else:
        abort(404)


@bp_bookings.route("/bookings/payment/<int:vehicle_id>/<string:start_date>/<string:end_date>", methods=["GET"])
@flask_login.login_required
def customer_confirm_booking(vehicle_id: int, start_date: str, end_date: str) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))

    try:
        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")

        booking_timedelta: datetime = end_date_obj - start_date_obj

        if booking_timedelta.days <= 0:
            flash("Booking days is negative!", category="danger")
        else:
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
                flash("Invalid vehicle id", category="danger")
    except ValueError as e:
        err_handler.push(
            user_message="Invalid date",
            log_message=f"Invalid date: {start_date} to {end_date}. {e}"
        )

    err_handler.commit_log()

    if err_handler.has_error():
        for i in err_handler.all():
            flash(i.user_message, category="danger")
    return redirect(url_for("index"))


@bp_bookings.route("/bookings/add_paynow_reference/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_add_paynow_reference_number(booking_id: int):
    paynow_reference_number = request.form.get("paynow_reference_number", EMPTY_STRING)

    update_dict = {
        "paynow_reference_number": paynow_reference_number,
    }

    if paynow_reference_number:
        booking = Booking.query.filter(Booking.user_id == flask_login.current_user.user_id, Booking.booking_id == booking_id, Booking.paynow_reference_number == None)

        if booking.first():
            booking.update(update_dict)
            db.session.commit()
            flash("Booking updated!", category="success")
            return redirect(url_for("bp_bookings.customer_read_bookings"))
        else:
            abort(404)
    else:
        flash("Empty reference number", category="danger")
        flash(paynow_reference_number, category="danger")
        return redirect(url_for("bp_bookings.customer_read_bookings"))
