from flask import Blueprint, request, redirect, url_for, render_template, flash, abort

from create_vehicle import create_vehicle
from read_vehicle import read_vehicle
from update_vehicle import update_vehicle
from delete_vehicle import delete_vehicle

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE


bp_vcp = Blueprint('bp_vcp', __name__, template_folder='templates')


@bp_vcp.route('/manager/vcp', methods=["GET"])
def manager_read_vehicles() -> str:
    # Function to read the vehicle db
    data = read_vehicle()

    # return and render the page template
    return render_template('car_manager.html', vehicle_list=data)


@bp_vcp.route('/manager/vcp/vehicle/read/<int:vehicle_id>', methods=["GET"])
def manager_read_vehicle(vehicle_id: int) -> str:
    return abort(501, "This should never be used?")


@bp_vcp.route('/manager/vcp/vehicle/create', methods=['POST'])
def manager_create_vehicle():
    uploaded_file = request.files['image']
    # Save the user input into variables, to use later
    vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
    license_plate = request.form.get('license_plate', EMPTY_STRING)
    vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
    location = request.form.get('location', EMPTY_STRING)
    price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)

    image = uploaded_file.stream.read()
    image_name = uploaded_file.name or EMPTY_STRING
    image_mime = uploaded_file.mimetype

    # Calling the function to insert into the db
    create_vehicle(vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
    # Flash message
    flash("A New Vehicle is now Available for Booking", category="success")
    # return and render the page template
    return redirect(url_for('bp_vcp.manager_read_vehicles'))


@bp_vcp.route('/manager/vcp/vehicle/update/<int:vehicle_id>', methods=['POST'])
def manager_update_vehicle(vehicle_id: int) -> str:
    uploaded_file = request.files['image']
    # Save the user input into variables, to use later
    vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
    license_plate = request.form.get('license_plate', EMPTY_STRING)
    vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
    location = request.form.get('location', EMPTY_STRING)
    price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)

    image = uploaded_file.stream.read()
    image_size = uploaded_file.content_length
    image_name = uploaded_file.filename
    image_mime = uploaded_file.mimetype

    # Function to update the selected vehicle from vehicle db
    if image_size <= MEDIUMBLOB_BYTE_SIZE:
        update_vehicle(vehicle_id, vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
        # Flash message
        flash("The Vehicle was updated", category="success")
    else:
        flash("Something went wrong", category="danger")
    # return and render the page template
    return redirect(url_for('bp_vcp.manager_read_vehicles'))


# The route function to DELETE car data in DB
@bp_vcp.route('/manager/vcp/vehicle/delete/<int:vehicle_id>', methods=["GET"])
def manager_delete_vehicle(vehicle_id: int) -> str:
    # Function to delete the selected vehicle from vehicle db
    delete_vehicle(vehicle_id)
    # Flash message
    flash("The Vehicle was deleted", category="success")
    # return and render the page template
    return redirect(url_for('bp_vcp.manager_read_vehicles'))
