from flask import Blueprint, request, redirect, url_for, render_template, flash, abort
import flask_login

from db import db

from vehicle import Vehicle
from booking import Booking, BOOKING_STATUS

from create_booking import create_booking

from input_validation import EMPTY_STRING

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
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
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
            start_date_obj = datetime.strptime(start_date, "%Y-%M-%d")
            end_date_obj = datetime.strptime(end_date, "%Y-%M-%d")

            booking_timedelta: datetime = end_date_obj - start_date_obj

            if booking_timedelta.days <= 0:
                abort(400, "Booking days is negative!")
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
        return redirect(url_for("index"))
        abort(400, "something went wrong")  # redirect(url_for("bp_bookings.customer_create_booking"))


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


@bp_bookings.route("/bookings/delete/<int:booking_id>", methods=["GET"])
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
    start_date_obj = datetime.strptime(start_date, "%Y-%M-%d")
    end_date_obj = datetime.strptime(end_date, "%Y-%M-%d")

    booking_timedelta: datetime = end_date_obj - start_date_obj

    if booking_timedelta.days <= 0:
        abort(400, "Booking days is negative!")
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
            abort(400, "Invalid vehicle id")


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
