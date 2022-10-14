from flask import Blueprint, request, redirect, url_for, render_template, flash, abort
import flask_login

from db import db

from fault import Fault
from booking import Booking

bp_faults = Blueprint('bp_faults', __name__, template_folder='templates')


@bp_faults.route("/faults")
@flask_login.login_required
def customer_read_faults() -> str:
    user_id = flask_login.current_user.user_id

    faults = Fault.query.join(Fault.booking, aliased=True).filter_by(user_id=user_id).all()
    bookings = Booking.query.filter_by(user_id=user_id).all()

    return render_template("user-faults.html", booking_list=bookings, fault_list=faults)


@bp_faults.route("/fault/read/<int:fault_id>")
@flask_login.login_required
def customer_read_fault(fault_id: int) -> str:
    return abort(501, "This should never be used?")


@bp_faults.route("/fault/create", methods=["POST"])
def customer_create_fault():
    booking_id = request.form.get("booking_id")
    reported_date = request.form.get("reported_date")
    description = request.form.get("description")

    new_fault = Fault(
        booking_id=booking_id,
        reported_date=reported_date,
        description=description
    )

    db.session.add(new_fault)
    db.session.commit()

    return redirect(url_for("bp_faults.customer_read_faults"))


@bp_faults.route("/fault/update/<int:target_fault_id>", methods=["POST"])
def customer_update_fault(target_fault_id: int) -> str:
    booking_id = request.form.get("booking_id")
    reported_date = request.form.get("reported_date")
    description = request.form.get("description")

    update_dict = {
        "booking_id": booking_id,
        "reported_date": reported_date,
        "description": description
    }

    update_dict = {k: v for k, v in update_dict.items() if v is not None}

    Fault.query.filter_by(fault_id=target_fault_id).update(update_dict)
    db.session.commit()

    flash("Fault updated!", category="success")
    return redirect(url_for("bp_faults.customer_read_faults"))


@bp_faults.route("/fault/delete/<int:target_fault_id>", methods=["GET"])
def customer_delete_fault(target_fault_id: int) -> str:
    Fault.query.filter_by(fault_id=target_fault_id).delete()
    db.session.commit()
    flash("Fault deleted!", category="success")
    return redirect(url_for("bp_faults.customer_read_faults"))
