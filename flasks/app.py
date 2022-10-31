from distutils.util import strtobool
# from functools import wraps
from flask import Flask, request, render_template, url_for, redirect, flash, abort, Response, session, g

# User imports
from create_user import create_user
from get_user import get_user

import flask_login

from user import User
from vehicle import Vehicle
from booking import Booking, BOOKING_STATUS
from recovery_code import Recovery_Codes

from engine import engine_uri

import mfa
from flask_qrcode import QRcode

from db import db
from sqlalchemy import or_, and_

from db_helper import vehicle_distinct_locations, vehicle_distinct_vehicle_types
from jwt_helper import generate_token, verify_token
from email_helper import send_mail

import os
from datetime import datetime

from bp_fcp import bp_fcp
from bp_ucp import bp_ucp
from bp_vcp import bp_vcp
from bp_bcp import bp_bcp
from bp_faults import bp_faults
from bp_bookings import bp_bookings
from bp_forgot_password import bp_forgot_password

from authorizer import http_unauthorized
from error_handler import ErrorHandler

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE, validate_email, validate_image, validate_name, validate_phone_number

from flask_wtf.csrf import CSRFProtect

from google_recaptcha import ReCaptcha

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

# recaptcha v2 tickbox
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get("RC_SITE_KEY_V2")
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get("RC_SECRET_KEY_V2")

# recaptcha v3
recaptchav3 = ReCaptcha(
    app,
    site_key=os.environ.get("RC_SITE_KEY_V3"),
    site_secret=os.environ.get("RC_SECRET_KEY_V3")
)

app.config['MAX_CONTENT_LENGTH'] = MEDIUMBLOB_BYTE_SIZE


app.register_blueprint(bp_fcp)
app.register_blueprint(bp_ucp)
app.register_blueprint(bp_vcp)
app.register_blueprint(bp_bcp)
app.register_blueprint(bp_faults)
app.register_blueprint(bp_bookings)
app.register_blueprint(bp_forgot_password)


@login_manager.user_loader
def load_user(user_id: int) -> User:
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized() -> Response:
    return http_unauthorized(redirect_to_login=True)


@app.before_request
def before_request_func() -> None:
    try:
        g.distinct_vehicle_types = vehicle_distinct_vehicle_types()
    except Exception as e:
        app.logger.fatal(e)


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("landing_page.html", distinct_locations=vehicle_distinct_locations())


@app.route("/register", methods=["GET", "POST"])
def register() -> str | Response:
    if request.method == "POST":
        if recaptchav3.verify():
            err_handler = ErrorHandler(app, dict(request.headers))

            email = request.form.get("email", EMPTY_STRING)

            if not validate_email(email):
                err_handler.push(
                    user_message="Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg",
                    log_message=f"Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg. Email given: {email}"
                )

            # check if user already exist
            if User.query.filter(User.email == email).first() is not None:
                err_handler.push(
                    user_message="An account with this email exists",
                    log_message=f"An account with this email exists. Email given: {email}"
                )

            err_handler.commit_log()

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")
            else:
                token = generate_token(email)

                send_mail(
                    app_context=app,
                    subject="Registration",
                    recipients=[email],
                    email_body=render_template("register_email_body.jinja2", token=token)
                )

                return render_template("register_email_sent.jinja2")
        else:
            flash("Bot activity detected", category="danger")
    return render_template("register.html")


@app.route("/register/<string:token>", methods=["GET", "POST"])
def register_verified(token: str) -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    if request.method == "POST":
        if recaptchav3.verify():
            uploaded_file = request.files['license_blob']

            first_name = request.form.get("first_name", EMPTY_STRING)
            last_name = request.form.get("last_name", EMPTY_STRING)
            password = request.form.get("password", EMPTY_STRING)
            phone_number = request.form.get("phone_number", EMPTY_STRING)

            license_blob = uploaded_file.stream.read()
            license_blob_size = len(license_blob)
            license_filename = uploaded_file.filename or EMPTY_STRING
            license_mime = uploaded_file.mimetype

            try:
                email = verify_token(token)

                if not validate_email(email):
                    err_handler.push(
                        user_message="Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg",
                        log_message=f"Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg. Email given: {email}"
                    )

                if not validate_name(first_name) or not validate_name(last_name) or not validate_phone_number(phone_number):
                    err_handler.push(
                        user_message="Illegal character caught",
                        log_message='Illegal character caught in either name or phone number'
                    )

                if not validate_image(license_blob, license_filename, license_blob_size):
                    err_handler.push(
                        user_message="Invalid image format",
                        log_message='Invalid image format'
                    )

                if len(password) < 7:
                    err_handler.push(
                        user_message="Password length too short",
                        log_message="Password length too short"
                    )

                user_exists: User = User.query.filter_by(email=email).first()

                if user_exists:
                    err_handler.push(
                        user_message="Username exists.",
                        log_message="Username exists"
                    )

                if license_blob_size >= MEDIUMBLOB_BYTE_SIZE:
                    err_handler.push(
                        user_message="Maximize size exceeded.",
                        log_message="Maximize size exceeded for license blob"
                    )

                err_handler.commit_log()

                if not err_handler.has_error():
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
                    flash("Account created successfully!", category="success")
                    return redirect(url_for('login'))
            except Exception as e:
                err_handler.push(
                    user_message="Invalid token",
                    log_message=f"Invalid token. Token given: {e}"
                )

            err_handler.commit_log()

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")
            return redirect(url_for('register_verified', token=token))
        else:
            err_handler.push(
                user_message="Invalid reCAPTCHA",
                log_message="Invalid reCAPTCHA."
            )

            err_handler.commit_log()

            if err_handler.has_error():
                flash(err_handler.first().user_message, category="danger")
                return redirect(url_for("register_verified", token=token))
    elif request.method == "GET":
        try:
            email = verify_token(token)
            return render_template("register_verified.jinja2", token=token, email=email)
        except Exception as e:
            err_handler.push(
                user_message="Invalid token",
                log_message=f"Invalid token. {e}"
            )

        err_handler.commit_log()

        if err_handler.has_error():
            flash(err_handler.first().user_message, category="danger")

        return render_template("register_verified.jinja2", token=token)


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    def login_error(msg="Incorrect credentials") -> str:
        err_handler.push(
            user_message=msg,
            log_message=msg
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("login"))

    def login_success() -> Response:
        # if successfully authenticated
        flask_login.login_user(user)
        return redirect(url_for('profile'))

    if request.method == "POST":
        if recaptchav3.verify():
            app.logger.debug("recaptcha verified!")
            email = request.form.get("email", EMPTY_STRING)
            password = request.form.get("password", EMPTY_STRING)
            # otp = request.form.get("otp", EMPTY_STRING)
            # recovery_code = request.form.get("recovery_code", EMPTY_STRING)

            if all([i != EMPTY_STRING for i in [email, password]]):
                user = get_user(email, password)

            if user:
                """
                email and password matches
                """
                # if user.mfa_secret != EMPTY_STRING and mfa.verify_otp(user, otp):
                #     """
                #     If mfa is enabled and otp is correct
                #     """
                #     return login_success()
                if user.mfa_secret == EMPTY_STRING:
                    """
                    If mfa is not enabled
                    """
                    return login_success()
                elif user.mfa_secret != EMPTY_STRING:
                    session["otp_user_id"] = user.user_id
                    return redirect(url_for("otp_login"))
                else:
                    """
                    None of the above
                    """
                    return login_error()
            else:
                return login_error()
        else:
            flash("Bot activity detected", category="danger")
            return login_error()
    elif request.method == "GET":
        if not flask_login.current_user.is_anonymous:
            return redirect(url_for('profile'))
        else:
            return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_login() -> str | Response:
    def login_success() -> Response:
        # if successfully authenticated
        flask_login.login_user(user)
        return redirect(url_for('profile'))

    if request.method == "GET":
        try:
            if "otp_user_id" in session:
                return render_template("otp_prompt.jinja2")
            else:
                flash("Invalid session", category="danger")
                return redirect(url_for("login"))
        except KeyError:
            flash("Invalid session", category="danger")
            return redirect(url_for("login"))
    else:
        try:
            user_id = session.pop("otp_user_id")

            user = User.query.filter(User.user_id == user_id).first()

            if user is not None:
                otp = request.form.get("otp", EMPTY_STRING)
                recovery_code = request.form.get("recovery_code", EMPTY_STRING)

                if user.mfa_secret != EMPTY_STRING:
                    if otp != EMPTY_STRING and mfa.verify_otp(user, otp):
                        return login_success()
                    elif recovery_code != EMPTY_STRING:
                        matched_code: Recovery_Codes = Recovery_Codes.query.join(Recovery_Codes.user, aliased=True).filter(
                            User.user_id == user_id,
                            Recovery_Codes.code == recovery_code,
                            Recovery_Codes.is_used == False
                        ).first()

                        if matched_code is not None:
                            matched_code.is_used = True
                            db.session.commit()
                            return login_success()
                        else:
                            flash("Invalid code", category="danger")
                            return redirect(url_for("login"))
                    else:
                        flash("Incorrect OTP", category="danger")
                        return redirect(url_for("login"))
                else:
                    flash("MFA is not enabled", category="danger")
                    return redirect(url_for("profile"))
        except KeyError:
            flash("Invalid session", category="danger")
            return redirect(url_for("login"))
        return ""


@app.route("/logout", methods=["GET"])
@flask_login.login_required
def logout() -> str:
    flask_login.logout_user()
    # redirect to login page for now
    return redirect(url_for('login'))


@app.route("/profile", methods=["GET"])
@flask_login.login_required
def profile() -> str:
    return render_template("profile.html")


# @app.route("/admin", methods=["GET"])
# @flask_login.login_required
# def admin() -> str:
#     # TODO: use a privilege function then to perform this check every time
#     # if not flask_login.current_user.is_anonymous and ROLE[flask_login.current_user.role] == "admin":
#     if universal_get_current_user_role(flask_login.current_user) > 0 and flask_login.current_user.is_admin():
#         return render_template("admin.html")
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

            return render_template("mfa_confirm.html", mfa_secret_uri=mfa_secret_uri, mfa_secret=mfa_secret)
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
            mfa_secret = session.pop("mfa_secret")

            if otp:
                try:
                    recovery_codes = mfa.confirm_mfa_enabled(flask_login.current_user, mfa_secret, otp)

                    return render_template("mfa_recovery_codes.jinja2", recovery_codes=recovery_codes)
                except Exception as e2:
                    app.logger.fatal(f"Unknown key {e2} in sessions")
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

    if all([i != EMPTY_STRING for i in [location, start_date, end_date]]):
        search_term = {
            "location": location,
            "start_date": start_date,
            "end_date": end_date,
        }

        err_handler = ErrorHandler(app, dict(request.headers))

        try:
            start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
            end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")

            booking_timedelta: datetime = end_date_obj - start_date_obj

            if booking_timedelta.days <= 0:
                flash("End date cannot be earlier than start date!", category="danger")
            else:
                vehicles_with_booking = db.session.query(Booking.vehicle_id).join(Booking.vehicle, aliased=True).filter(
                    Vehicle.location == location,
                    Booking.status != BOOKING_STATUS[-1],
                    or_(
                        and_(Booking.start_date > start_date, Booking.end_date < end_date),
                        and_(Booking.start_date < start_date, Booking.end_date > end_date),
                        and_(Booking.start_date < end_date, Booking.end_date > end_date),
                        and_(Booking.start_date < start_date, Booking.end_date > start_date),
                        and_(Booking.start_date == start_date, Booking.end_date == end_date)
                    )
                ).subquery()

                vehicles_without_booking = Vehicle.query.filter(Vehicle.location == location, Vehicle.vehicle_id.notin_(vehicles_with_booking))

                search_result = vehicles_without_booking.all() or []

                return render_template("landing_page.html", distinct_locations=vehicle_distinct_locations(), search_term=search_term, search_result=search_result)
        except ValueError as e:
            err_handler.push(
                user_message="Invalid date",
                log_message=f"Invalid date: {start_date} to {end_date}. {e}"
            )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("index"))

    else:
        abort(400)


@app.route("/vehicles/<string:vehicle_type>", methods=["GET"])
def vehicles_by_type(vehicle_type: str) -> str:
    if vehicle_type not in vehicle_distinct_vehicle_types():
        flash("Invalid vehicle type", category="danger")
    else:
        vehicles = Vehicle.query.filter(Vehicle.vehicle_type == vehicle_type).all()

        return render_template("vehicle_type.jinja2", vehicles=vehicles, vehicle_type=vehicle_type)
    return render_template("vehicle_type.jinja2")


@app.route("/about-us", methods=["GET"])
def about_us() -> str:
    return render_template("aboutus.html")


@app.route("/locate-us", methods=["GET"])
def locate_us() -> str:
    return render_template("locateus.html")


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
