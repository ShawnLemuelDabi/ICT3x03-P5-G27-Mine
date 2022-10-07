from functools import wraps
from flask import Flask, request, render_template, url_for, redirect, flash, abort

# User imports
from create_user import create_user
from read_user import read_user
from get_user import get_user
from update_user import update_user
from delete_user import delete_user

# Booking imports
from booking import Booking
from create_booking import create_booking

import flask_login

from user import User, ROLE
from engine import engine_uri

from db import db

import os

EMPTY_STRING = ""

# Initialize Flask
app = Flask(__name__)

# These config should be stored in a file in the future
app.config["SQLALCHEMY_DATABASE_URI"] = engine_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # to suppress the warning

# should be safe enough. generated using:
# openssl rand -base64 48
app.secret_key = os.environ.get("FLASK_LOGIN_SECRET")

# Initialize the SQLAlchemy middleware
db.init_app(app)

# Initialize the login manager for Flask
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def check_access(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not flask_login.current_user.is_authenticated:
                return abort(401)

            if not flask_login.current_user.allowed(access_level):
                return abort(401)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


""" AUTHENTICATION """


@app.route("/")
def index() -> str:
    return render_template("index.html", user_profile=flask_login.current_user)


@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    error_list = []

    if request.method == "POST":
        MAX_FILE_SIZE_LIMIT = 16777215  # as defined by MEDIUMBLOB
        uploaded_file = request.files['license_blob']

        email = request.form.get("email")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        password = request.form.get("password")
        phone_number = request.form.get("phone_number")

        license_blob = uploaded_file.stream.read()
        license_blob_size = uploaded_file.content_length
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if len(password) < 7:
            flash("Password must be at least 7 characters.", category="error")

        user_exists = User.query.filter_by(email=email).first()

        if user_exists:
            flash("Username exists.", category="error")
            error_list.append(
                {
                    'message': "Username exists.",
                    'log': 'Something something'
                }
            )

        if license_blob_size <= MAX_FILE_SIZE_LIMIT:
            error_list.append(
                {
                    'message': "Maximize size exceeded.",
                    'log': 'Something something'
                }
            )

        if not error_list:
            create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                license_blob=license_blob.encode("utf8"),
                license_filename=license_filename,
                license_mime=license_mime,
                mfa_secret="",
                role=0,
            )
            return render_template("login.html")
    elif request.method == "GET":
        return render_template("register.html", user_profile=flask_login.current_user)


@app.route("/login", methods=["POST", "GET"])
def login() -> str:
    if request.method == "POST":
        email = request.form.get("email", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)

        if all([i != EMPTY_STRING for i in [email, password]]):
            user = get_user(email, password)

            if user:
                # if successfully authenticated
                flask_login.login_user(user)
                return render_template(
                    "home.html", user_profile=flask_login.current_user
                )
            else:
                return "NOT OK"
        else:
            return "Something was empty"
    else:
        return render_template("login.html")


@flask_login.login_required
@app.route("/logout")
def logout() -> str:
    flask_login.logout_user()
    return "OK"


# PROFILE
@flask_login.login_required
@app.route("/profile", methods=["GET"])
def profile() -> str:
    return render_template("profile.html", user_profile=flask_login.current_user)


# BOOKING
@flask_login.login_required
@app.route("/bookings")
def booking() -> str:
    bookings = Booking.query.all()
    return render_template(
        "bookings.html", user=flask_login.current_user, booking=bookings
    )


@app.route("/create-booking", methods=["GET", "POST"])
@flask_login.login_required
def add_booking():
    if request.method == "POST":
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")

        if not start_date:
            flash("Start Date cannot be empty", category="error")
        elif not end_date:
            flash("End Date cannot be empty", category="error")
        else:
            create_booking(
                start_date=start_date,
                end_date=end_date,
                user_id=flask_login.current_user.user_id,
            )
            flash("Booking created!", category="success")
            return redirect(url_for("profile"))
    elif request.method == "GET":
        return render_template(
            "create_booking.html", user_profile=flask_login.current_user
        )


# USER CRUD
@app.route("/user-list", methods=["GET", "POST"])
def user_manager() -> str:
    # Function to read the vehicle db
    data = read_user()
    # return and render the page template

    return render_template("user_manager.html", user_list=data, roles=ROLE)


# The route function to insert new car data into DB
@app.route("/user_create", methods=["POST"])
def user_create():
    if request.method == "POST":
        MAX_FILE_SIZE_LIMIT = 16777215  # as defined by MEDIUMBLOB
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

        if license_blob_size <= MAX_FILE_SIZE_LIMIT:
            # validate if role is int
            try:
                role = int(role)

                if role not in ROLE:
                    app.logger.info(f"Role ID out of valid range. Invalid role ID: {role}")
                    flash("Invalid role")
                else:
                    user_exists = User.query.filter_by(email=email).first()
                    if user_exists:
                        flash("something went wrong")
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
                            mfa_secret="",
                            role=role,
                        )
                        # Flash message
                        flash("A User has been created")
                        # return and render the page template
                        return redirect(url_for("user_manager"))
            except ValueError:
                app.logger.info(f"Role ID not an int. Invalid role ID: {role}")
                return "something went wrong"


# The route function to update car data into DB
@app.route("/user_update", methods=["POST"])
def user_update():
    if request.method == "POST":
        MAX_FILE_SIZE_LIMIT = 16777215  # as defined by MEDIUMBLOB
        uploaded_file = request.files['license_blob']

        # Save the user input into variables, to use later
        user_id = request.form.get("user_id", EMPTY_STRING)
        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)
        mfa_secret = request.form.get("phone_number", EMPTY_STRING)
        role = request.form.get("role", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = uploaded_file.content_length
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if license_blob_size <= MAX_FILE_SIZE_LIMIT:
            # Function to update the selected vehicle from vehicle db
            if user_id != EMPTY_STRING:
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
                    mfa_secret=mfa_secret,
                    role=role,
                )
                # Flash message
                flash("The User was updated")
                # return and render the page template
                return redirect(url_for("user_manager"))
            else:
                return "Something went wrong"


# The route function to delete car data in DB
@app.route("/user_delete/<int:id>", methods=["GET"])
def user_delete(id):
    # Function to delete the selected vehicle from vehicle db
    delete_user(id)
    # Flash message
    flash("The User was deleted")
    # return and render the page template
    return redirect(url_for("user_manager"))


@flask_login.login_required
@app.route("/admin", methods=["GET"])
def admin() -> str:
    if ROLE[flask_login.current_user.role] == "admin":
        return render_template("admin.html", user_profile=flask_login.current_user)
    else:
        return render_template("home.html", user_profile=flask_login.current_user)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
