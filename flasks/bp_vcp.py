from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from create_vehicle import create_vehicle
from read_vehicle import read_vehicle
from update_vehicle import update_vehicle
from delete_vehicle import delete_vehicle

from user import Role

from input_validation import validate_image, validate_price, validate_name, validate_license_plate, EMPTY_STRING, validate_sql_pk_int
from error_handler import ErrorHandler
from authorizer import universal_get_current_user_role


bp_vcp = Blueprint('bp_vcp', __name__, template_folder='templates')


@bp_vcp.route('/manager/vcp', methods=["GET"])
@flask_login.login_required
def manager_read_vehicles() -> str:
    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        # Function to read the vehicle db
        data = read_vehicle()

        # return and render the page template
        return render_template('car_manager.html', vehicle_list=data)
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))

        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_vcp.route('/manager/vcp/vehicle/read/<int:vehicle_id>', methods=["GET"])
@flask_login.login_required
def manager_read_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        err_handler.push(
            user_message="This should never be used?",
            log_message=f"User {user_email} accessed a route that is not implemented."
        )

        err_handler.commit_log()

        return abort(501, err_handler.first().user_message)
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email} to a route that is not implemented"
        )

        err_handler.commit_log()

        abort(401)


@bp_vcp.route('/manager/vcp/vehicle/create', methods=['POST'])
@flask_login.login_required
def manager_create_vehicle():
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        uploaded_file = request.files['image']
        # Save the user input into variables, to use later
        vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
        license_plate = request.form.get('license_plate', EMPTY_STRING)
        vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)

        image = uploaded_file.stream.read()
        image_size = len(image)
        image_name = uploaded_file.filename or EMPTY_STRING
        image_mime = uploaded_file.mimetype

        if not validate_name(vehicle_model):
            err_handler.push(
                user_message="Invalid vehicle model provided.",
                log_message=f"Invalid vehicle model provided. Vehicle model '{vehicle_model}'. Request made by user {user_email}"
            )

        if not validate_license_plate(license_plate):
            err_handler.push(
                user_message="Invalid license plate provided.",
                log_message=f"Invalid license plate provided. License plate '{license_plate}'. Request made by user {user_email}"
            )

        if not validate_name(vehicle_type):
            err_handler.push(
                user_message="Invalid vehicle type provided.",
                log_message=f"Invalid vehicle type provided. Vehicle type '{vehicle_type}'. Request made by user {user_email}"
            )

        if not validate_name(location):
            err_handler.push(
                user_message="Invalid location provided.",
                log_message=f"Invalid location provided. Location '{location}'. Request made by user {user_email}"
            )

        if not validate_image(image_stream=image, image_filename=image_name, image_size=image_size):
            err_handler.push(
                user_message="Invalid image provided. Only jpg, jpeg & png allowed. Max size of image should be 16M",
                log_message=f"Invalid image provided. Image name '{image_name}' of mime type '{image_mime}' uploaded. Image size {image_size} bytes. Request made by user {user_email}"
            )

        if not validate_price(price_per_limit):
            err_handler.push(
                user_message="Invalid price.",
                log_message=f"Invalid price. Price given '{price_per_limit}'. Request made by user {user_email}"
            )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        else:
            # Calling the function to insert into the db
            create_vehicle(vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
            # Flash message
            flash("A New Vehicle is now Available for Booking", category="success")
            err_handler.push(
                user_message="",
                log_message=f"A Vehicle has been created. Request made by user {user_email}",
                is_error=False
            )

        err_handler.commit_log()

        # return and render the page template
        return redirect(url_for('bp_vcp.manager_read_vehicles'))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_vcp.route('/manager/vcp/vehicle/update/<int:vehicle_id>', methods=['POST'])
@flask_login.login_required
def manager_update_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        uploaded_file = request.files['image']
        # Save the user input into variables, to use later
        vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
        license_plate = request.form.get('license_plate', EMPTY_STRING)
        vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)

        image = uploaded_file.stream.read()
        image_size = len(image)
        image_name = uploaded_file.filename or EMPTY_STRING
        image_mime = uploaded_file.mimetype

        if not validate_sql_pk_int(vehicle_id):
            err_handler.push(
                user_message="Invalid vehicle ID provided.",
                log_message=f"Invalid vehicle ID provided. Vehicle ID '{vehicle_id}'. Request made by user {user_email}"
            )

        if not validate_name(vehicle_model):
            err_handler.push(
                user_message="Invalid vehicle model provided.",
                log_message=f"Invalid vehicle model provided. Vehicle model '{vehicle_model}'. Request made by user {user_email}"
            )

        if not validate_license_plate(license_plate):
            err_handler.push(
                user_message="Invalid license plate provided.",
                log_message=f"Invalid license plate provided. License plate '{license_plate}'. Request made by user {user_email}"
            )

        if not validate_name(vehicle_type):
            err_handler.push(
                user_message="Invalid vehicle type provided.",
                log_message=f"Invalid vehicle type provided. Vehicle type '{vehicle_type}'. Request made by user {user_email}"
            )

        if not validate_name(location):
            err_handler.push(
                user_message="Invalid location provided.",
                log_message=f"Invalid location provided. Location '{location}'. Request made by user {user_email}"
            )

        if image_size > 0 and not validate_image(image_stream=image, image_filename=image_name, image_size=image_size):
            err_handler.push(
                user_message="Invalid image provided. Only jpg, jpeg & png allowed. Max size of image should be 16M",
                log_message=f"Invalid image provided. Image name '{image_name}' of mime type '{image_mime}' uploaded. Image size {image_size} bytes. Request made by user {user_email}"
            )

        if not validate_price(price_per_limit):
            err_handler.push(
                user_message="Invalid price.",
                log_message=f"Invalid price. Price given '{price_per_limit}'. Request made by user {user_email}"
            )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        else:
            update_vehicle(vehicle_id, vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
            # Flash message
            flash("The Vehicle was updated", category="success")
            err_handler.push(
                user_message="",
                log_message=f"The Vehicle ID '{vehicle_id}' has been updated. Request made by user {user_email}",
                is_error=False
            )

        err_handler.commit_log()

        # return and render the page template
        return redirect(url_for('bp_vcp.manager_read_vehicles'))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


# The route function to DELETE car data in DB
@bp_vcp.route('/manager/vcp/vehicle/delete/<int:vehicle_id>', methods=["POST"])
@flask_login.login_required
def manager_delete_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        if not validate_sql_pk_int(vehicle_id):
            err_handler.push(
                user_message="Invalid vehicle ID provided.",
                log_message=f"Invalid vehicle ID provided. Vehicle ID '{vehicle_id}'. Request made by user {user_email}"
            )

        if not err_handler.has_error():
            # Function to delete the selected vehicle from vehicle db
            delete_vehicle(vehicle_id)
            # Flash message
            flash("The Vehicle was deleted", category="success")
            err_handler.push(
                user_message="",
                log_message=f"The Vehicle ID '{vehicle_id}' has been deleted. Request made by user {user_email}",
                is_error=False
            )
        err_handler.commit_log()
        # return and render the page template
        return redirect(url_for('bp_vcp.manager_read_vehicles'))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)
