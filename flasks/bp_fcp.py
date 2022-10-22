from flask import Blueprint, request, redirect, url_for, render_template, flash, abort

from db import db

from fault import Fault
from booking import Booking

bp_fcp = Blueprint('bp_fcp', __name__, template_folder='templates')


@bp_fcp.route("/manager/fcp", methods=["GET"])
def manager_read_faults() -> str:
    faults = Fault.query.all()
    bookings = Booking.query.all()

    return render_template("manager-faults.html", booking_list=bookings, fault_list=faults)


@bp_fcp.route("/manager/fcp/fault/create", methods=["POST"])
def manager_create_fault() -> str:
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

    flash("Fault created", category="success")

    return redirect(url_for("bp_fcp.manager_read_faults"))


@bp_fcp.route("/manager/fcp/fault/read/<int:fault_id>", methods=["GET"])
def manager_read_fault(fault_id: int) -> str:
    # faults = Fault.query.filter_by(fault_id=fault_id).first()
    # bookings = Booking.query.all()

    # return redirect(url_for("manager_read_faults"))
    return abort(501, "This should never be used?")


@bp_fcp.route("/manager/fcp/fault/update/<int:fault_id>", methods=["POST"])
def manager_update_fault(fault_id: int) -> str:
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
    return redirect(url_for("bp_fcp.manager_read_faults"))


@bp_fcp.route("/manager/fcp/fault/delete/<int:fault_id>", methods=["GET"])
def manager_delete_fault(fault_id: int) -> str:
    Fault.query.filter_by(fault_id=fault_id).delete()
    db.session.commit()

    flash("Fault deleted!", category="success")
    return redirect(url_for("bp_fcp.manager_read_faults"))
