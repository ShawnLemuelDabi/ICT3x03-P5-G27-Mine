from flask import Blueprint, request, redirect, url_for, render_template, flash, abort
import flask_login

from db import db

from vehicle import Vehicle
from booking import Booking

from create_booking import create_booking

from input_validation import EMPTY_STRING

bp_bookings = Blueprint('bp_bookings', __name__, template_folder='templates')


@bp_bookings.route("/booking")
@flask_login.login_required
def customer_read_bookings() -> str:
    vehicles = Vehicle.query.all()
    bookings = Booking.query.filter_by(user_id=flask_login.current_user.user_id).all()

    return render_template(
        "bookings.html", user=flask_login.current_user, bookings=bookings, vehicles=vehicles
    )


@bp_bookings.route("/booking/create", methods=["GET", "POST"])
@flask_login.login_required
def customer_create_booking() -> str:
    if request.method == "GET":
        return render_template("create_booking.html")
    else:
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        vehicle_id = request.form.get("vehicle_id", EMPTY_STRING)
        paynow_number = request.form.get("paynow_number", EMPTY_STRING)

        if not start_date:
            flash("Start Date cannot be empty", category="error")
        elif not end_date:
            flash("End Date cannot be empty", category="error")
        elif not paynow_number:
            flash("PayNow Number cannot be empty", category="error")
        else:
            booking = create_booking(
                start_date=start_date,
                end_date=end_date,
                user_id=flask_login.current_user.user_id,
                vehicle_id=vehicle_id
            )
            return render_template("booking_success.jinja2", user=flask_login.current_user, booking=booking)
        return "something went wrong"  # redirect(url_for("bp_bookings.customer_create_booking"))


@bp_bookings.route("/booking/read/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def customer_read_booking(booking_id: int) -> str:
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id).first()

    if booking:
        return render_template('edit_booking.html', booking=booking)
    else:
        abort(404)


@bp_bookings.route("/booking/update/<int:booking_id>", methods=["POST"])
@flask_login.login_required
def customer_update_booking(booking_id: int) -> str:
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")

    update_dict = {
        "start_date": start_date,
        "end_date": end_date,
    }

    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id)

    if booking.first():
        booking.update(update_dict)
        db.session.commit()
        flash("Booking updated!", category="success")
        return redirect(url_for("bp_bookings.customer_read_bookings"))
    else:
        abort(404)


@bp_bookings.route("/booking/delete/<int:booking_id>", methods=["GET"])
@flask_login.login_required
def customer_delete_booking(booking_id: int) -> str:
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=booking_id)

    if booking.first():
        booking.delete()
        db.session.commit()
        flash("Booking deleted!", category="success")
        return redirect(url_for("bp_bookings.customer_read_bookings"))
    else:
        abort(404)


@bp_bookings.route("/bookings/payment/<int:vehicle_id>/<string:start_date>/<string:end_date>", methods=["GET"])
@flask_login.login_required
def customer_confirm_booking(vehicle_id: int, start_date: str, end_date: str) -> str:

    # TODO: remove this library :<
    from datetime import datetime

    start_date_obj = datetime.strptime(start_date, "%Y-%M-%d")
    end_date_obj = datetime.strptime(end_date, "%Y-%M-%d")

    booking_timedelta: datetime = end_date_obj - start_date_obj

    booking_details = {
        "start_date": start_date,
        "end_date": end_date,
        "days": booking_timedelta.days,
    }

    vehicle = Vehicle.query.filter_by(vehicle_id=vehicle_id).first()

    if vehicle:
        return render_template(
            "booking_payment.jinja2", user=flask_login.current_user, booking_details=booking_details, vehicle=vehicle
        )
    else:
        abort(400, "Invalid vehicle id")
