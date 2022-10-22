from flask import Blueprint, request, redirect, url_for, render_template, flash, abort

from db import db

from booking import Booking, BOOKING_STATUS

bp_bcp = Blueprint('bp_bcp', __name__, template_folder='templates')


@bp_bcp.route("/manager/bcp", methods=["GET"])
def manager_read_bookings() -> str:
    bookings = Booking.query.all()

    return render_template("manager_bcp.jinja2", bookings=bookings, valid_status=BOOKING_STATUS)


@bp_bcp.route("/manager/bcp/booking/create", methods=["POST"])
def manager_create_booking() -> str:
    return abort(501, "This should never be used?")


@bp_bcp.route("/manager/bcp/booking/read/<int:booking_id>", methods=["GET"])
def manager_read_booking(booking_id: int) -> str:
    return abort(501, "This should never be used?")


@bp_bcp.route("/manager/bcp/booking/update/<int:booking_id>", methods=["POST"])
def manager_update_booking(booking_id: int) -> str:
    status = request.form.get("status")

    if status in BOOKING_STATUS:
        update_dict = {
            "status": status,
        }

        Booking.query.filter_by(booking_id=booking_id).update(update_dict)
        db.session.commit()

        flash("Booking updated!", category="success")
    else:
        flash("Invalid status!", category="danger")
    return redirect(url_for("bp_bcp.manager_read_bookings"))


@bp_bcp.route("/manager/bcp/booking/delete/<int:booking_id>", methods=["GET"])
def manager_delete_booking(booking_id: int) -> str:
    Booking.query.filter_by(booking_id=booking_id).delete()
    db.session.commit()

    flash("Booking deleted!", category="success")
    return redirect(url_for("bp_bcp.manager_read_bookings"))
