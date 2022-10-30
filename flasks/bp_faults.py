from flask import Blueprint, request, redirect, url_for, render_template, flash, abort
import flask_login

from db import db

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE

from fault import Fault, FAULT_CATEGORIES, FAULT_STATUS
from booking import BOOKING_STATUS, Booking

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


@bp_faults.route("/fault/create", methods=["GET", "POST"])
@bp_faults.route("/fault/create/<int:booking_id>", methods=["GET"])
def customer_create_fault(booking_id: int = None):
    if request.method == "GET":
        bookings = Booking.query.join(Booking.fault, aliased=True).filter(Booking.user_id == flask_login.current_user.user_id, Booking.status == BOOKING_STATUS[2], Fault.booking_id == booking_id).all()

        return render_template("fault_create_form.jinja2", booking_id=booking_id, bookings=bookings, valid_categories=FAULT_CATEGORIES)
    elif request.method == "POST":
        uploaded_file = request.files['fault_image']

        booking_id = request.form.get("booking_id")
        reported_date = request.form.get("reported_date")
        description = request.form.get("description")
        category = request.form.get("category")
        description = request.form.get("description")

        fault_image = uploaded_file.stream.read()
        fault_blob_size = uploaded_file.content_length
        fault_filename = uploaded_file.filename or EMPTY_STRING
        fault_mime = uploaded_file.mimetype

        if category not in FAULT_CATEGORIES:
            flash("invalid category", category="danger")
        elif fault_blob_size >= MEDIUMBLOB_BYTE_SIZE:
            flash("file size too big", category="danger")
        elif not fault_mime.startswith('image'):
            flash("only image files are allowed", category="danger")
        else:
            # check if booking exists and is valid to create a fault
            booking = Booking.query.join(Booking.fault, aliased=True).filter(Booking.user_id == flask_login.current_user.user_id, Booking.status == BOOKING_STATUS[2], Fault.booking_id == booking_id)

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
            else:
                flash("booking not found", category="danger")

        return redirect(url_for("bp_faults.customer_read_faults"))


@bp_faults.route("/fault/update/<int:fault_id>", methods=["POST"])
def customer_update_fault(fault_id: int) -> str:
    return abort(501, "This should never be used?")
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


@bp_faults.route("/fault/delete/<int:fault_id>", methods=["GET"])
def customer_delete_fault(fault_id: int) -> str:
    return abort(501, "This should never be used?")
    # Fault.query.filter_by(fault_id=fault_id).delete()
    # db.session.commit()
    # flash("Fault deleted!", category="success")
    # return redirect(url_for("bp_faults.customer_read_faults"))
