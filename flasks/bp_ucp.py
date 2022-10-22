from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app, abort
import flask_login

from db import db

from user import User, ROLE

# from read_user import read_user
from create_user import create_user
from update_user import update_user
# from delete_user import delete_user

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE


bp_ucp = Blueprint('bp_ucp', __name__, template_folder='templates')


@bp_ucp.route("/admin/ucp", methods=["GET", "POST"])
def admin_read_users() -> str:
    users_list = User.query.filter(User.role >= 3)
    data = users_list.all()

    valid_roles = {k: v for k, v in ROLE.items() if k in range(3, len(ROLE))}

    return render_template("user_manager.html", user_list=data, valid_roles=valid_roles, roles=ROLE, user=flask_login.current_user)


@bp_ucp.route("/admin/ucp/user/<int:user_id>", methods=["GET", "POST"])
def admin_read_user(user_id: int) -> str:
    return abort(501, "This should never be used?")


# The route function to insert new car data into DB
@bp_ucp.route("/admin/ucp/user/create", methods=["POST"])
def admin_create_user() -> str:
    uploaded_file = request.files['license_blob']

    # Save the user input into variables, to use later
    email = request.form.get("email", EMPTY_STRING)
    first_name = request.form.get("first_name", EMPTY_STRING)
    last_name = request.form.get("last_name", EMPTY_STRING)
    password = request.form.get("password", EMPTY_STRING)
    phone_number = request.form.get("phone_number", EMPTY_STRING)
    role = request.form.get("role", EMPTY_STRING)

    license_blob = uploaded_file.stream.read()
    license_blob_size = uploaded_file.content_length
    license_filename = uploaded_file.filename or EMPTY_STRING
    license_mime = uploaded_file.mimetype

    if license_blob_size <= MEDIUMBLOB_BYTE_SIZE:
        # validate if role is int
        try:
            role = int(role)

            if role not in [i for i in range(3, len(ROLE))]:
                current_app.logger.info(f"Role ID out of valid range. Invalid role ID: {role}")
                flash("Invalid role", category="danger")
            else:
                user_exists = User.query.filter(User.email == email, User.role >= 3).first()

                if user_exists is not None:
                    flash("something went wrong", category="danger")
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
                    # return and render the page template
            return redirect(url_for("bp_ucp.admin_read_users"))
        except ValueError:
            current_app.logger.info(f"Role ID not an int. Invalid role ID: {role}")
            return "something went wrong"


# The route function to update car data into DB
@bp_ucp.route("/admin/ucp/user/update/<int:user_id>", methods=["POST"])
def admin_update_user(user_id: int) -> str:
    if user_id != EMPTY_STRING:
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
        license_blob_size = uploaded_file.content_length
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if license_blob_size <= MEDIUMBLOB_BYTE_SIZE:
            # Function to update the selected vehicle from vehicle db

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

            target_user = User.query.filter(User.user_id == int(user_id), User.role >= 3, User.role <= 4)

            if target_user.first() is not None:
                target_user.update(update_dict)
                db.session.commit()
                # Flash message
                flash("The User was updated", category="success")
            else:
                flash("The User was not found", category="danger")
            # return and render the page template
            return redirect(url_for("bp_ucp.admin_read_users"))
    else:
        return "Something went wrong"


# The route function to delete car data in DB
@bp_ucp.route("/admin/ucp/user/delete/<int:user_id>", methods=["GET"])
def admin_delete_user(user_id: int) -> str:
    # Function to delete the selected vehicle from vehicle db
    target_user = User.query.filter(User.user_id == user_id, User.role >= 3)

    if target_user.first() is not None:
        target_user.delete()
        db.session.commit()
        # Flash message
        flash("The User was deleted", category="success")
        # return and render the page template
    else:
        flash("The User was not found", category="danger")
    return redirect(url_for("bp_ucp.admin_read_users"))


@bp_ucp.route("/manager/ucp", methods=["GET", "POST"])
def manager_read_users() -> str:
    users_list = User.query.filter(User.role < 3)
    data = users_list.all()

    valid_roles = {k: v for k, v in ROLE.items() if k in range(1, 3)}

    return render_template("manager_ucp.jinja2", user_list=data, valid_roles=valid_roles, roles=ROLE, user=flask_login.current_user)


@bp_ucp.route("/manager/ucp/user/<int:user_id>", methods=["GET", "POST"])
def manager_read_user(user_id: int) -> str:
    return abort(501, "This should never be used?")


# The route function to insert new car data into DB
@bp_ucp.route("/manager/ucp/user/create", methods=["POST"])
def manager_create_user() -> str:
    uploaded_file = request.files['license_blob']

    # Save the user input into variables, to use later
    email = request.form.get("email", EMPTY_STRING)
    first_name = request.form.get("first_name", EMPTY_STRING)
    last_name = request.form.get("last_name", EMPTY_STRING)
    password = request.form.get("password", EMPTY_STRING)
    phone_number = request.form.get("phone_number", EMPTY_STRING)
    role = request.form.get("role", EMPTY_STRING)

    license_blob = uploaded_file.stream.read()
    license_blob_size = uploaded_file.content_length
    license_filename = uploaded_file.filename or EMPTY_STRING
    license_mime = uploaded_file.mimetype

    if license_blob_size <= MEDIUMBLOB_BYTE_SIZE:
        # validate if role is int
        try:
            role = int(role)

            if role not in [i for i in range(1, 3)]:
                current_app.logger.info(f"Role ID out of valid range. Invalid role ID: {role}")
                flash("Invalid role", category="danger")
            else:
                user_exists = User.query.filter_by(email=email).first()

                if user_exists:
                    flash("something went wrong", category="danger")
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
                    # return and render the page template
                    return redirect(url_for("bp_ucp.manager_read_users"))
        except ValueError:
            current_app.logger.info(f"Role ID not an int. Invalid role ID: {role}")
            return "something went wrong"


# The route function to update car data into DB
@bp_ucp.route("/manager/ucp/user/update/<int:user_id>", methods=["POST"])
def manager_update_user(user_id: int) -> str:
    if user_id != EMPTY_STRING:
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = uploaded_file.content_length
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if license_blob_size <= MEDIUMBLOB_BYTE_SIZE:
            # Function to update the selected vehicle from vehicle db

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
            # return and render the page template
            return redirect(url_for("bp_ucp.manager_read_users"))
    else:
        return "Something went wrong"


# The route function to delete car data in DB
@bp_ucp.route("/manager/ucp/user/delete/<int:user_id>", methods=["GET"])
def manager_delete_user(user_id: int) -> str:
    # Function to delete the selected vehicle from vehicle db
    target_user = User.query.filter(User.user_id == user_id, User.role >= 1, User.role <= 2)

    if target_user.first():
        target_user.delete()
        db.session.commit()
        # Flash message
        flash("The User was deleted", category="success")
        # return and render the page template
        return redirect(url_for("bp_ucp.manager_read_users"))
    else:
        flash("The User was not found", category="danger")
        return redirect(url_for("bp_ucp.manager_read_users"))
