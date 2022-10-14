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
def user_read_bookings() -> str:
    vehicles = Vehicle.query.all()
    bookings = Booking.query.filter_by(user_id=flask_login.current_user.user_id).all()

    return render_template(
        "bookings.html", user=flask_login.current_user, bookings=bookings, vehicles=vehicles
    )


@bp_bookings.route("/booking/create", methods=["GET", "POST"])
@flask_login.login_required
def add_booking() -> str:
    if request.method == "GET":
        return render_template("create_booking.html")
    else:
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        vehicle_id = request.form.get("vehicle_id", EMPTY_STRING)

        if not start_date:
            flash("Start Date cannot be empty", category="error")
        elif not end_date:
            flash("End Date cannot be empty", category="error")
        else:
            create_booking(
                start_date=start_date,
                end_date=end_date,
                user_id=flask_login.current_user.user_id,
                vehicle_id=vehicle_id
            )
            flash("Booking created!", category="success")
            return redirect(url_for("create_booking"))


@bp_bookings.route("/booking/read/<int:target_booking_id>", methods=["GET"])
@flask_login.login_required
def read_booking(target_booking_id: int) -> str:
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=target_booking_id).first()

    if booking:
        return render_template('edit_booking.html', booking=booking)
    else:
        abort(404)


@bp_bookings.route("/booking/update/<int:target_booking_id>", methods=["POST"])
@flask_login.login_required
def update_booking(target_booking_id: int) -> str:
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")

    update_dict = {
        "start_date": start_date,
        "end_date": end_date,
    }

    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=target_booking_id)

    if booking.first():
        booking.update(update_dict)
        db.session.commit()
        flash("Booking updated!", category="success")
        return redirect(url_for("bp_bookings.user_read_bookings"))
    else:
        abort(404)


@bp_bookings.route("/booking/delete/<int:target_booking_id>", methods=["GET"])
@flask_login.login_required
def delete_booking(target_booking_id: int) -> str:
    booking = Booking.query.filter_by(user_id=flask_login.current_user.user_id, booking_id=target_booking_id)

    if booking.first():
        booking.delete()
        db.session.commit()
        flash("Booking deleted!", category="success")
        return redirect(url_for("bp_bookings.user_read_bookings"))
    else:
        abort(404)
