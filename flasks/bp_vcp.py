from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, current_app
import flask_login

from create_vehicle import create_vehicle
from read_vehicle import read_vehicle
from update_vehicle import update_vehicle
from delete_vehicle import delete_vehicle

from user import Role

from input_validation import validate_image, EMPTY_STRING
from error_handler import ErrorHandler
from authorizer import universal_get_current_user_role


bp_vcp = Blueprint('bp_vcp', __name__, template_folder='templates')


@bp_vcp.route('/manager/vcp', methods=["GET"])
def manager_read_vehicles() -> str:
    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        # Function to read the vehicle db
        data = read_vehicle()

        # return and render the page template
        return render_template('car_manager.html', vehicle_list=data)
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))

        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_vcp.route('/manager/vcp/vehicle/read/<int:vehicle_id>', methods=["GET"])
def manager_read_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

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
def manager_create_vehicle():
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

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

        if not validate_image(image_stream=image, image_filename=image_name, image_size=image_size):
            err_handler.push(
                user_message="Invalid image provided. Only jpg, jpeg & png allowed. Max size of image should be 16M",
                log_message=f"Invalid image provided. Image name '{image_name}' of mime type '{image_mime}' uploaded. Image size {image_size} bytes. Request made by user {user_email}"
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
def manager_update_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

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

        if image_size > 0 and not validate_image(image_stream=image, image_filename=image_name, image_size=image_size):
            err_handler.push(
                user_message="Invalid image provided. Only jpg, jpeg & png allowed. Max size of image should be 16M",
                log_message=f"Invalid image provided. Image name '{image_name}' of mime type '{image_mime}' uploaded. Image size {image_size} bytes. Request made by user {user_email}"
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
def manager_delete_vehicle(vehicle_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
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
