from distutils.util import strtobool
from functools import wraps
from flask import Flask, request, render_template, url_for, redirect, flash, abort, Response

# User imports
from create_user import create_user
from get_user import get_user

import flask_login

from user import User, ROLE
from engine import engine_uri

import mfa
from flask_qrcode import QRcode

from db import db

import os

from bp_fcp import bp_fcp
from bp_ucp import bp_ucp
from bp_vcp import bp_vcp
from bp_faults import bp_faults
from bp_bookings import bp_bookings
from bp_forgot_password import bp_forgot_password

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE

# Initialize Flask
app = Flask(__name__)

# These config should be stored in a file in the future
app.config["SQLALCHEMY_DATABASE_URI"] = engine_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # to suppress the warning

app.secret_key = os.environ.get("FLASK_LOGIN_SECRET")

# Initialize the SQLAlchemy middleware
db.init_app(app)

# Initialize the login manager for Flask
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

QRcode(app)

app.config['MAIL_SERVER'] = os.environ.get("SMTP_SERVER_HOST")
app.config['MAIL_PORT'] = os.environ.get("SMTP_SERVER_PORT")
app.config['MAIL_USE_TLS'] = strtobool(os.environ.get("SMTP_USE_TLS")) == 1
app.config['MAIL_USE_SSL'] = strtobool(os.environ.get("SMTP_USE_SSL")) == 1
app.config['MAIL_USERNAME'] = os.environ.get("SMTP_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("SMTP_PASSWORD")

app.register_blueprint(bp_fcp)
app.register_blueprint(bp_ucp)
app.register_blueprint(bp_vcp)
app.register_blueprint(bp_faults)
app.register_blueprint(bp_bookings)
app.register_blueprint(bp_forgot_password)


@login_manager.user_loader
def load_user(user_id: int) -> User:
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


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("landing_page.html", user_profile=flask_login.current_user)


@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    # TODO: typing
    error_list = []

    if request.method == "POST":
        uploaded_file = request.files['license_blob']

        email = request.form.get("email", EMPTY_STRING)
        first_name = request.form.get("first_name", EMPTY_STRING)
        last_name = request.form.get("last_name", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        phone_number = request.form.get("phone_number", EMPTY_STRING)

        license_blob = uploaded_file.stream.read()
        license_blob_size = uploaded_file.content_length
        license_filename = uploaded_file.filename or EMPTY_STRING
        license_mime = uploaded_file.mimetype

        if len(password) < 7:
            error_list.append(
                {
                    'message': "Password length too short",
                    'log': 'Something something'
                }
            )

        user_exists: User = User.query.filter_by(email=email).first()

        if user_exists:
            error_list.append(
                {
                    'message': "Username exists.",
                    'log': 'Something something'
                }
            )

        if license_blob_size >= MEDIUMBLOB_BYTE_SIZE:
            error_list.append(
                {
                    'message': "Maximize size exceeded.",
                    'log': 'Something something'
                }
            )

        if error_list:
            flash(error_list[0], category="error")
        else:
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
                role=0,
            )
            return redirect(url_for('login'))
    return render_template("register.html", user_profile=flask_login.current_user)


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    def login_error() -> str:
        flash("Incorrect credentials")
        return redirect(url_for("login"))

    def login_success() -> Response:
        # if successfully authenticated
        flask_login.login_user(user)
        return redirect(url_for('profile'))

    if request.method == "POST":
        email = request.form.get("email", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        otp = request.form.get("otp", EMPTY_STRING)

        if all([i != EMPTY_STRING for i in [email, password]]):
            user = get_user(email, password)

            if user:
                if user.mfa_secret != EMPTY_STRING and mfa.verify_otp(user, otp):
                    return login_success()
                elif user.mfa_secret == EMPTY_STRING:
                    return login_success()
                else:
                    return login_error()
            else:
                return login_error()
        else:
            return login_error()
    elif request.method == "GET":
        if not flask_login.current_user.is_anonymous:
            return redirect(url_for('profile'))
        else:
            return render_template("login.html")


@app.route("/logout", methods=["GET"])
@flask_login.login_required
def logout() -> str:
    flask_login.logout_user()
    # redirect to login for now
    return redirect(url_for('login'))


@app.route("/profile", methods=["GET"])
@flask_login.login_required
def profile() -> str:
    return render_template("profile.html", user_profile=flask_login.current_user)


@app.route("/admin", methods=["GET"])
@flask_login.login_required
def admin() -> str:
    # TODO: use a privilege function then to perform this check every time
    if not flask_login.current_user.is_anonymous and ROLE[flask_login.current_user.role] == "admin":
        return render_template("admin.html", user_profile=flask_login.current_user)
    else:
        abort(401)


@login_manager.unauthorized_handler
def unauthorized() -> None:
    abort(401, "Unauthorized")


@app.route("/profile/enable_mfa", methods=["GET"])
@flask_login.login_required
def route_enable_mfa() -> str:
    try:
        flash(mfa.generate_mfa_uri(flask_login.current_user), "mfa_secret_uri")

        return redirect(url_for("profile"))
    except Exception as e:
        app.logger.fatal(e)
        return "Something went wrong"


@app.route("/dev/init", methods=["GET"])
def init() -> str:
    db.drop_all()
    db.create_all()
    return "OK"


if __name__ == "__main__":
    app.run(host="0.0.0.0")
