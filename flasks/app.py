from distutils.command import upload
from distutils.util import strtobool
# from functools import wraps
from flask import Flask, request, render_template, url_for, redirect, flash, abort, Response, session, g
# from flask_session import Session

# User imports
from create_user import create_user
from recaptcha import recaptchaForm
from get_user import get_user

import flask_login

from user import User
from vehicle import Vehicle
from booking import Booking
from recovery_code import Recovery_Codes

from engine import engine_uri

import mfa
from flask_qrcode import QRcode

from db import db

from db_helper import vehicle_distinct_locations, vehicle_distinct_vehicle_types

import os

from bp_fcp import bp_fcp
from bp_ucp import bp_ucp
from bp_vcp import bp_vcp
from bp_faults import bp_faults
from bp_bookings import bp_bookings
from bp_forgot_password import bp_forgot_password

from authorizer import http_unauthorized
from error_handler import ErrorHandler

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE, validate_email, validate_image, validate_name, validate_phone_number

from flask_wtf.csrf import CSRFProtect

# Initialize Flask
app = Flask(__name__)

# These config should be stored in a file in the future
app.config["SQLALCHEMY_DATABASE_URI"] = engine_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # to suppress the warning

app.secret_key = os.environ.get("FLASK_LOGIN_SECRET")

# Initialize the SQLAlchemy middleware
db.init_app(app)

# Initialize CSRF Protection globally
csrf = CSRFProtect()
csrf.init_app(app)

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

app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get("RC_SITE_KEY")
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get("RC_SECRET_KEY")

app.register_blueprint(bp_fcp)
app.register_blueprint(bp_ucp)
app.register_blueprint(bp_vcp)
app.register_blueprint(bp_faults)
app.register_blueprint(bp_bookings)
app.register_blueprint(bp_forgot_password)


@login_manager.user_loader
def load_user(user_id: int) -> User:
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized() -> Response:
    return http_unauthorized(redirect_to_login=True)

# is this even used?
# def check_access(access_level):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if not flask_login.current_user.is_authenticated:
#                 return abort(401)

#             if not flask_login.current_user.allowed(access_level):
#                 return abort(401)
#             return f(*args, **kwargs)

#         return decorated_function

#     return decorator


@app.before_request
def before_request_func():
    g.distinct_vehicle_types = vehicle_distinct_vehicle_types()


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("landing_page.html", user=flask_login.current_user, distinct_locations=vehicle_distinct_locations())


@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    # TODO: typing
    # error_list = []
    err_handler = ErrorHandler(app)
    form = recaptchaForm()
    if request.method == "POST" and form.validate_on_submit():
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

        if not validate_email(email):
            err_handler.push(
                user_message="Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg",
                log_message='Something something'
            )

        if not validate_name(first_name) or not validate_name(last_name) or not validate_phone_number(phone_number):
            err_handler.push(
                user_message="Illegal character caught",
                log_message='Something something'
            )
        
        if not validate_image(license_blob, license_filename, license_blob_size):
            err_handler.push(
                user_message="Invalid image format",
                log_message='Something something'
            )

        if len(password) < 7:
            # error_list.append(
            #     {
            #         'message': "Password length too short",
            #         'log': 'Something something'
            #     }
            # )
            err_handler.push(
                user_message="Password length too short",
                log_message="Password length too short"
            )

        user_exists: User = User.query.filter_by(email=email).first()

        if user_exists:
            # error_list.append(
            #     {
            #         'message': "Username exists.",
            #         'log': 'Something something'
            #     }
            # )
            err_handler.push(
                user_message="Username exists.",
                log_message="Username exists"
            )

        if license_blob_size >= MEDIUMBLOB_BYTE_SIZE:
            # error_list.append(
            #     {
            #         'message': "Maximize size exceeded.",
            #         'log': 'Something something'
            #     }
            # )
            err_handler.push(
                user_message="Maximize size exceeded.",
                log_message="Maximize size exceeded for license blob"
            )

        # if error_list:
        #     flash(error_list[0], category="error")

        err_handler.commit_log()

        if err_handler.has_error():
            flash(err_handler.first().user_message, category="error")
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
                role=1,
            )
            return redirect(url_for('login'))

    return render_template("register.html", user=flask_login.current_user, form=form)


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    def login_error(msg="Incorrect credentials") -> str:
        flash(msg)
        return redirect(url_for("login"))

    def login_success() -> Response:
        # if successfully authenticated
        flask_login.login_user(user)
        return redirect(url_for('profile'))

    if request.method == "POST":
        email = request.form.get("email", EMPTY_STRING)
        password = request.form.get("password", EMPTY_STRING)
        otp = request.form.get("otp", EMPTY_STRING)
        recovery_code = request.form.get("recovery_code", EMPTY_STRING)

        if all([i != EMPTY_STRING for i in [email, password]]):
            user = get_user(email, password)

            if user:
                """
                email and password matches
                """
                if user.mfa_secret != EMPTY_STRING and mfa.verify_otp(user, otp):
                    """
                    If mfa is enabled and otp is correct
                    """
                    return login_success()
                elif user.mfa_secret == EMPTY_STRING:
                    """
                    If mfa is not enabled
                    """
                    return login_success()
                elif user.mfa_secret != EMPTY_STRING and recovery_code != EMPTY_STRING:
                    """
                    If mfa is enabled and recovery_code is entered
                    """
                    matched_code: Recovery_Codes = Recovery_Codes.query.join(Recovery_Codes.user, aliased=True).filter(Recovery_Codes.code == recovery_code, Recovery_Codes.is_used is False).first()

                    if matched_code:
                        matched_code.is_used = True
                        db.session.commit()
                        return login_success()
                    else:
                        return login_error()
                else:
                    """
                    None of the above
                    """
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
    # redirect to login page for now
    return redirect(url_for('login'))


@app.route("/profile", methods=["GET"])
@flask_login.login_required
def profile() -> str:
    return render_template("profile.html", user=flask_login.current_user)


# @app.route("/admin", methods=["GET"])
# @flask_login.login_required
# def admin() -> str:
#     # TODO: use a privilege function then to perform this check every time
#     # if not flask_login.current_user.is_anonymous and ROLE[flask_login.current_user.role] == "admin":
#     if universal_get_current_user_role(flask_login.current_user) > 0 and flask_login.current_user.is_admin():
#         return render_template("admin.html", user=flask_login.current_user)
#     else:
#         abort(401)


@app.route("/profile/enable_mfa", methods=["GET"])
@flask_login.login_required
def route_enable_mfa() -> str:
    if flask_login.current_user.mfa_secret:
        abort(400)
    else:
        try:
            mfa_secret = mfa.generate_mfa()
            mfa_secret_uri = mfa.generate_mfa_uri(flask_login.current_user, mfa_secret)

            session['mfa_secret'] = mfa_secret

            flash(mfa_secret_uri, "mfa_secret_uri")
            # flash(mfa.generate_mfa_uri(flask_login.current_user), "mfa_recovery_codes")

            return render_template("mfa_confirm.html")
        except Exception as e:
            app.logger.fatal(e)
            return "Something went wrong"


@app.route("/profile/confirm_mfa_enabled", methods=["POST"])
@flask_login.login_required
def route_confirm_mfa_enabled() -> str:
    if flask_login.current_user.mfa_secret:
        abort(400)
    else:
        otp = request.form.get("otp", EMPTY_STRING)

        try:
            mfa_secret = session.get("mfa_secret")

            if otp:
                try:
                    recovery_codes = mfa.confirm_mfa_enabled(flask_login.current_user, mfa_secret, otp)

                    return ", ".join(recovery_codes)
                except Exception as e2:
                    app.logger.fatal(e2)
                    return "something went wrong?2"
            else:
                return "No OTP entered"
        except Exception as e:
            app.logger.fatal(e)
            return "something went wrong?1"


@app.route("/search", methods=["POST"])
def search() -> str:
    location = request.form.get("location", EMPTY_STRING)
    start_date = request.form.get("start_date", EMPTY_STRING)
    end_date = request.form.get("end_date", EMPTY_STRING)

    if all([i != "" for i in [location, start_date, end_date]]):
        search_term = {
            "location": location,
            "start_date": start_date,
            "end_date": end_date,
        }

        booking_result = Booking.query.join(Booking.vehicle, aliased=True).filter(Vehicle.location == location, Booking.start_date <= start_date, Booking.end_date >= end_date).all()

        reject_vehicle_id: list[int] = [i.vehicle_id for i in booking_result]

        search_result = Vehicle.query.filter(Vehicle.location == location).filter(Vehicle.vehicle_id.notin_(reject_vehicle_id))

        search_result = search_result or []

        return render_template("landing_page.html", user=flask_login.current_user, distinct_locations=vehicle_distinct_locations(), search_term=search_term, search_result=search_result)
    else:
        abort(400)


@app.route("/dev/init", methods=["GET"])
def init() -> str:
    if app.debug:
        db.drop_all()
        db.create_all()
        return "OK"
    else:
        abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
