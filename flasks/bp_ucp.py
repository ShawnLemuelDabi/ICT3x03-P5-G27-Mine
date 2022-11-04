from typing import NoReturn
from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app, abort, Response

from db import db

from user import User, ROLE, Role
import flask_login

# from read_user import read_user
from create_user import create_user
from update_user import update_user
# from delete_user import delete_user

from input_validation import EMPTY_STRING, validate_email, validate_image, validate_name, validate_password, validate_phone_number, validate_sql_pk_str
from error_handler import ErrorHandler
from authorizer import universal_get_current_user_role


bp_ucp = Blueprint('bp_ucp', __name__, template_folder='templates')


@bp_ucp.route("/admin/ucp", methods=["GET"])
@flask_login.login_required
def admin_read_users() -> str | Response:
    if universal_get_current_user_role(flask_login.current_user) == Role.ADMIN:
        users_list = User.query.filter(User.role >= 3)
        data = users_list.all()

        valid_roles = {k: v for k, v in ROLE.items() if k in range(3, len(ROLE))}

        return render_template("user_manager.html", user_list=data, valid_roles=valid_roles, roles=ROLE)
    else:
        err_handler = ErrorHandler(current_app, dict(request.headers))

        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_ucp.route("/admin/ucp/user/<int:user_id>", methods=["GET"])
@flask_login.login_required
def admin_read_user(user_id: int) -> str | NoReturn:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.ADMIN:
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


# The route function to insert new car data into DB
@bp_ucp.route("/admin/ucp/user/create", methods=["POST"])
@flask_login.login_required
def admin_create_user() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.ADMIN:
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = len(license_blob)
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if not validate_email(email):
            err_handler.push(
                user_message="Invalid email provided.",
                log_message=f"Invalid email provided. Request made by user {user_email}"
            )

        if not validate_name(first_name):
            err_handler.push(
                user_message="Invalid first name provided.",
                log_message=f"Invalid first name provided. Request made by user {user_email}"
            )

        if not validate_name(last_name):
            err_handler.push(
                user_message="Invalid last name provided.",
                log_message=f"Invalid last name provided. Request made by user {user_email}"
            )

        if not validate_password(password, password):
            err_handler.push(
                user_message="Invalid password provided.",
                log_message=f"Invalid password provided. Request made by user {user_email}"
            )

        if not validate_phone_number(phone_number):
            err_handler.push(
                user_message="Invalid phone number provided.",
                log_message=f"Invalid phone number provided. Request made by user {user_email}"
            )

        if not validate_image(image_stream=license_blob, image_filename=license_filename, image_size=license_blob_size):
            err_handler.push(
                user_message="Invalid image provided.",
                log_message=f"Invalid image provided. Request made by user {user_email}"
            )
        try:
            role_int = int(role)

            if role_int not in [Role.MANAGER, Role.ADMIN]:
                err_handler.push(
                    user_message="Invalid role",
                    log_message=f"Role ID out of valid range. Invalid role ID: {role} request made by user {user_email}"
                )
        except ValueError:
            err_handler.push(
                user_message="Invalid role",
                log_message=f"Role ID is not a number. Invalid role ID: {role} request made by user {user_email}"
            )

            if not err_handler.has_error():
                user_exists = User.query.filter(User.email == email).first()

                if user_exists is not None:
                    err_handler.push(
                        user_message="User already exists",
                        log_message=f"User with email '{email}' already exists. Request made by user {user_email}"
                    )
                else:
                    # Calling the function to insert into the db
                    create_user(
                        email=email,
                        password=password,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        license_blob=license_blob,
                        license_filename=license_filename,
                        license_mime=license_mime,
                        mfa_secret=EMPTY_STRING,
                        role=role,
                    )
                    # Flash message
                    flash("A User has been created", category="success")

                    err_handler.push(
                        user_message="",
                        log_message=f"User '{email}' with role '{ROLE[role_int]}' created. Request made by user {user_email}",
                        is_error=False
                    )
        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        # return and render the page template
        return redirect(url_for("bp_ucp.admin_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


# The route function to update car data into DB
@bp_ucp.route("/admin/ucp/user/update/<int:user_id>", methods=["POST"])
@flask_login.login_required
def admin_update_user(user_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.ADMIN:
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        # mfa_secret = request.form.get("mfa_secret", EMPTY_STRING)  # TODO: should the admin be able to re-create 2fa?
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = len(license_blob)
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if not validate_sql_pk_str(user_id):
            err_handler.push(
                user_message="Invalid user ID provided.",
                log_message=f"Invalid user ID '{user_id}'. Request made by user {user_email}"
            )

        if not validate_email(email):
            err_handler.push(
                user_message="Invalid email provided.",
                log_message=f"Invalid email provided. Request made by user {user_email}"
            )

        if not validate_name(first_name):
            err_handler.push(
                user_message="Invalid first name provided.",
                log_message=f"Invalid first name provided. Request made by user {user_email}"
            )

        if not validate_name(last_name):
            err_handler.push(
                user_message="Invalid last name provided.",
                log_message=f"Invalid last name provided. Request made by user {user_email}"
            )

        if not validate_password(password, password):
            err_handler.push(
                user_message="Invalid password provided.",
                log_message=f"Invalid password provided. Request made by user {user_email}"
            )

        if not validate_phone_number(phone_number):
            err_handler.push(
                user_message="Invalid phone number provided.",
                log_message=f"Invalid phone number provided. Request made by user {user_email}"
            )

        if not validate_image(image_stream=license_blob, image_filename=license_filename, image_size=license_blob_size):
            err_handler.push(
                user_message="Invalid image provided.",
                log_message=f"Invalid image provided. Request made by user {user_email}"
            )

        try:
            role_int = int(role)

            if role_int not in [Role.MANAGER, Role.ADMIN]:
                err_handler.push(
                    user_message="Invalid role",
                    log_message=f"Role ID out of valid range. Invalid role ID: {role} request made by user {user_email}"
                )
        except ValueError:
            err_handler.push(
                user_message="Invalid role",
                log_message=f"Role ID is not a number. Invalid role ID: {role} request made by user {user_email}"
            )

        update_dict = {
            "email": email,
            "password": password,
            "first_name": first_name,
            "last_name": last_name,
            "phone_number": phone_number,
            "license_blob": license_blob,
            "license_filename": license_filename,
            "license_mime": license_mime,
            "role": role
        }

        if len(update_dict['license_blob']) == 0 and not update_dict['license_blob']:
            del update_dict['license_blob']
            del update_dict['license_filename']
            del update_dict['license_mime']

        # remove any key-value pair when value is empty str or none
        update_dict = {k: v for k, v in update_dict.items() if v is not None and v != EMPTY_STRING}

        if not err_handler.has_error():
            target_user = User.query.filter(User.user_id == int(user_id), User.role >= 3, User.role <= 4)

            if target_user.first() is not None:
                target_user.update(update_dict)
                db.session.commit()
                # Flash message
                flash("The User was updated", category="success")

                err_handler.push(
                    user_message="",
                    log_message=f"User '{email}' updated. Request made by user {user_email}",
                    is_error=False
                )
            else:
                err_handler.push(
                    user_message="The User was not found",
                    log_message=f"User ID {user_id} does not exist. Request made by user {user_email}",
                )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        # return and render the page template
        return redirect(url_for("bp_ucp.admin_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


# The route function to delete car data in DB
@bp_ucp.route("/admin/ucp/user/delete/<int:user_id>", methods=["POST"])
@flask_login.login_required
def admin_delete_user(user_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.ADMIN:
        if not validate_sql_pk_str(user_id):
            err_handler.push(
                user_message="Invalid user ID provided.",
                log_message=f"Invalid user ID '{user_id}'. Request made by user {user_email}"
            )

        if not err_handler.has_error():
            # Function to delete the selected vehicle from vehicle db
            target_user = User.query.filter(User.user_id == user_id, User.role >= 3)

            if target_user.first() is not None:
                target_user.delete()
                db.session.commit()
                # Flash message
                flash("The User was deleted", category="success")
                err_handler.push(
                    user_message="",
                    log_message=f"User ID {user_id} has been deleted. Request made by user {user_email}",
                    is_error=False
                )
            else:
                err_handler.push(
                    user_message="The User was not found",
                    log_message=f"User ID {user_id} does not exist. Request made by user {user_email}",
                )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        # return and render the page template
        return redirect(url_for("bp_ucp.admin_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_ucp.route("/manager/ucp", methods=["GET"])
@flask_login.login_required
def manager_read_users() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        users_list = User.query.filter(User.role < 3)
        data = users_list.all()

        valid_roles = {k: v for k, v in ROLE.items() if k in range(1, 3)}

        return render_template("manager_ucp.jinja2", user_list=data, valid_roles=valid_roles, roles=ROLE)
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


@bp_ucp.route("/manager/ucp/user/<int:user_id>", methods=["GET"])
@flask_login.login_required
def manager_read_user(user_id: int) -> str:
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


# The route function to insert new car data into DB
@bp_ucp.route("/manager/ucp/user/create", methods=["POST"])
@flask_login.login_required
def manager_create_user() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = len(license_blob)
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if not validate_email(email):
            err_handler.push(
                user_message="Invalid email provided.",
                log_message=f"Invalid email provided. Request made by user {user_email}"
            )

        if not validate_name(first_name):
            err_handler.push(
                user_message="Invalid first name provided.",
                log_message=f"Invalid first name provided. Request made by user {user_email}"
            )

        if not validate_name(last_name):
            err_handler.push(
                user_message="Invalid last name provided.",
                log_message=f"Invalid last name provided. Request made by user {user_email}"
            )

        if not validate_password(password, password):
            err_handler.push(
                user_message="Invalid password provided.",
                log_message=f"Invalid password provided. Request made by user {user_email}"
            )

        if not validate_phone_number(phone_number):
            err_handler.push(
                user_message="Invalid phone number provided.",
                log_message=f"Invalid phone number provided. Request made by user {user_email}"
            )

        if not validate_image(image_stream=license_blob, image_filename=license_filename, image_size=license_blob_size):
            err_handler.push(
                user_message="Invalid image provided.",
                log_message=f"Invalid image provided. Request made by user {user_email}"
            )

        try:
            role_int = int(role)

            if role_int not in [Role.UNVERIFIED_USER, Role.VERIFIED_USER]:
                err_handler.push(
                    user_message="Invalid role",
                    log_message=f"Role ID out of valid range. Invalid role ID: {role} request made by user {user_email}"
                )
        except ValueError:
            err_handler.push(
                user_message="Invalid role",
                log_message=f"Role ID is not a number. Invalid role ID: {role} request made by user {user_email}"
            )

        if not err_handler.has_error():
            user_exists = User.query.filter_by(email=email).first()

            if user_exists:
                err_handler.push(
                    user_message="User already exists",
                    log_message=f"User with email '{email}' already exists. Request made by user {user_email}"
                )
            else:
                # Calling the function to insert into the db
                create_user(
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    phone_number=phone_number,
                    license_blob=license_blob,
                    license_filename=license_filename,
                    license_mime=license_mime,
                    mfa_secret=EMPTY_STRING,
                    role=role,
                )
                # Flash message
                flash("A User has been created", category="success")

                err_handler.push(
                    user_message="",
                    log_message=f"User '{email}' with role '{ROLE[role]}' created. Request made by user {user_email}",
                    is_error=False
                )
            err_handler.commit_log()

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")
            # return and render the page template
            return redirect(url_for("bp_ucp.manager_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


# The route function to update car data into DB
@bp_ucp.route("/manager/ucp/user/update/<int:user_id>", methods=["POST"])
@flask_login.login_required
def manager_update_user(user_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = len(license_blob)
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if not validate_sql_pk_str(user_id):
            err_handler.push(
                user_message="Invalid user ID provided.",
                log_message=f"Invalid user ID '{user_id}'. Request made by user {user_email}"
            )

        if not validate_email(email):
            err_handler.push(
                user_message="Invalid email provided.",
                log_message=f"Invalid email provided. Request made by user {user_email}"
            )

        if not validate_name(first_name):
            err_handler.push(
                user_message="Invalid first name provided.",
                log_message=f"Invalid first name provided. Request made by user {user_email}"
            )

        if not validate_name(last_name):
            err_handler.push(
                user_message="Invalid last name provided.",
                log_message=f"Invalid last name provided. Request made by user {user_email}"
            )

        if not validate_password(password, password):
            err_handler.push(
                user_message="Invalid password provided.",
                log_message=f"Invalid password provided. Request made by user {user_email}"
            )

        if not validate_phone_number(phone_number):
            err_handler.push(
                user_message="Invalid phone number provided.",
                log_message=f"Invalid phone number provided. Request made by user {user_email}"
            )

        if not validate_image(image_stream=license_blob, image_filename=license_filename, image_size=license_blob_size):
            err_handler.push(
                user_message="Invalid image provided.",
                log_message=f"Invalid image provided. Request made by user {user_email}"
            )

        try:
            role_int = int(role)

            if role_int not in [Role.MANAGER, Role.ADMIN]:
                err_handler.push(
                    user_message="Invalid role",
                    log_message=f"Role ID out of valid range. Invalid role ID: {role} request made by user {user_email}"
                )
        except ValueError:
            err_handler.push(
                user_message="Invalid role",
                log_message=f"Role ID is not a number. Invalid role ID: {role} request made by user {user_email}"
            )

        if not err_handler.has_error():
            update_user(
                find_user_id=int(user_id),
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=password,
                phone_number=phone_number,
                license_blob=license_blob,
                license_filename=license_filename,
                license_mime=license_mime,
                # mfa_secret=mfa_secret,
                role=role,
            )
            # Flash message
            flash("The User was updated", category="success")

            err_handler.push(
                user_message="",
                log_message=f"User '{email}' updated. Request made by user {user_email}",
                is_error=False
            )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        # return and render the page template
        return redirect(url_for("bp_ucp.manager_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)


# The route function to delete car data in DB
@bp_ucp.route("/manager/ucp/user/delete/<int:user_id>", methods=["POST"])
@flask_login.login_required
def manager_delete_user(user_id: int) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))
    user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == Role.ANONYMOUS_USER else flask_login.current_user.email

    if universal_get_current_user_role(flask_login.current_user) == Role.MANAGER:

        if not validate_sql_pk_str(user_id):
            err_handler.push(
                user_message="Invalid user ID provided.",
                log_message=f"Invalid user ID '{user_id}'. Request made by user {user_email}"
            )

        if not err_handler.has_error():
            # Function to delete the selected vehicle from vehicle db
            target_user = User.query.filter(User.user_id == user_id, User.role >= Role.UNVERIFIED_USER, User.role <= Role.VERIFIED_USER)

            if target_user.first():
                target_user.delete()
                db.session.commit()
                # Flash message
                flash("The User was deleted", category="success")
                err_handler.push(
                    user_message="",
                    log_message=f"User ID {user_id} has been deleted. Request made by user {user_email}",
                    is_error=False
                )
            else:
                err_handler.push(
                    user_message="The User was not found",
                    log_message=f"User ID {user_id} is not found. Request made by user {user_email}",
                )

            err_handler.commit_log()

            # return and render the page template
            return redirect(url_for("bp_ucp.manager_read_users"))
        else:
            err_handler.push(
                user_message="The User was not found",
                log_message=f"User ID {user_id} is invalid. Request made by user {user_email}",
            )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("bp_ucp.manager_read_users"))
    else:
        err_handler.push(
            user_message="",
            log_message=f"Unauthorized access from user {user_email}"
        )

        err_handler.commit_log()

        abort(401)
