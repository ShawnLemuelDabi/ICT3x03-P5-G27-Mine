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

from authorizer import http_unauthorized, universal_get_current_user_role
from error_handler import ErrorHandler

from input_validation import EMPTY_STRING, MEDIUMBLOB_BYTE_SIZE, DATE_FORMAT, validate_email, validate_image, validate_name, validate_phone_number

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
    err_handler = ErrorHandler(app, dict(request.headers))

    if universal_get_current_user_role(flask_login.current_user) != 0:
        err_handler.push(
            user_message="You already have an account!",
            log_message="You already have an account!"
        )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for("profile"))

    if request.method == "POST":
        if recaptchav3.verify():
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
                return redirect(url_for('register'))
            else:
                token = generate_token(email)

                err_handler.push(
                    user_message="",
                    log_message=f"Email registration link requested for email '{email}'",
                    is_error=False
                )

                err_handler.commit_log()

                send_mail(
                    app_context=app,
                    subject="Registration",
                    recipients=[email],
                    email_body=render_template("register_email_body.jinja2", token=token)
                )

                return render_template("register_email_sent.jinja2")
        else:
            err_handler.push(
                user_message="Bot activity detected",
                log_message="Bot activity detected. Recaptchav3 cannot be verified"
            )

            err_handler.commit_log()

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")

            return redirect(url_for('register'))
    else:
        return render_template("register.html")


@app.route("/register/<string:token>", methods=["GET", "POST"])
def register_verified(token: str) -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    if universal_get_current_user_role(flask_login.current_user) != 0:
        err_handler.push(
            user_message="You already have an account!",
            log_message="You already have an account!"
        )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for("profile"))

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

                    err_handler.push(
                        user_message="",
                        log_message=f"Account with email '{email}' created successfully!",
                        is_error=False
                    )

                    err_handler.commit_log()
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

    if universal_get_current_user_role(flask_login.current_user) != 0:
        err_handler.push(
            user_message="You are already logged in!",
            log_message="You are already logged in!"
        )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for("profile"))

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

    def login_success(user_obj: User) -> Response:
        # if successfully authenticated
        err_handler.push(
            user_message="",
            log_message=f"{user.email} logged in successfully without MFA!",
            is_error=False
        )

        err_handler.commit_log()

        flask_login.login_user(user_obj)
        return redirect(url_for('profile'))

    if request.method == "POST":
        if recaptchav3.verify():
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
                        return login_success(user)
                    elif user.mfa_secret != EMPTY_STRING:
                        session["otp_user_id"] = user.user_id

                        err_handler.push(
                            user_message="",
                            log_message=f"{user.email} credentials verified! MFA required to complete the login!",
                            is_error=False
                        )

                        err_handler.commit_log()
                        return redirect(url_for("otp_login"))
                    else:
                        """
                        None of the above
                        """
                        return login_error()
                else:
                    return login_error()
            else:
                return login_error()
        else:
            err_handler.push(
                user_message="Bot activity detected",
                log_message="Bot activity detected"
            )
            return login_error()
    elif request.method == "GET":
        return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_login() -> str | Response:
    err_handler = ErrorHandler(app, (request.headers))

    def login_success(user_obj: User, code_type: str) -> Response:
        err_handler.push(
            user_message="",
            log_message=f"{user.email} logged in successfully with {code_type}!",
            is_error=False
        )

        err_handler.commit_log()

        flask_login.login_user(user_obj)
        return redirect(url_for('profile'))

    def login_error(user_message: str, log_message: str, return_method: str) -> Response:
        err_handler.push(
            user_message=user_message,
            log_message=log_message
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")

        return redirect(url_for(return_method))

    if universal_get_current_user_role(flask_login.current_user) != 0:
        return login_error(
            user_message="You are already logged in!",
            log_message="You are already logged in!",
            return_method="profile"
        )

    if request.method == "GET":
        try:
            if "otp_user_id" in session:
                return render_template("otp_prompt.jinja2")
            else:
                return login_error(
                    user_message="Invalid session",
                    log_message="Invalid session",
                    return_method="login"
                )
        except KeyError:
            return login_error(
                user_message="Invalid session",
                log_message="Invalid session",
                return_method="login"
            )
    else:
        try:
            user_id = session.pop("otp_user_id")

            user: User = User.query.filter(User.user_id == user_id).first()

            if user is not None:
                otp = request.form.get("otp", EMPTY_STRING)
                recovery_code = request.form.get("recovery_code", EMPTY_STRING)

                if user.mfa_secret != EMPTY_STRING:
                    if otp != EMPTY_STRING and mfa.verify_otp(user, otp):
                        return login_success(user, code_type="OTP")
                    elif recovery_code != EMPTY_STRING:
                        matched_code: Recovery_Codes = Recovery_Codes.query.join(Recovery_Codes.user, aliased=True).filter(
                            User.user_id == user_id,
                            Recovery_Codes.code == recovery_code,
                            Recovery_Codes.is_used == False
                        ).first()

                        if matched_code is not None:
                            matched_code.is_used = True
                            db.session.commit()
                            return login_success(user, code_type="recovery code")
                        else:
                            return login_error(
                                user_message="Invalid code",
                                log_message="Invalid code",
                                return_method="login"
                            )
                    else:
                        return login_error(
                            user_message="Incorrect OTP",
                            log_message="Incorrect OTP",
                            return_method="login"
                        )
                else:
                    return login_error(
                        user_message="MFA is not enabled",
                        log_message="MFA is not enabled",
                        return_method="profile"
                    )
        except KeyError:
            return login_error(
                user_message="Invalid session",
                log_message="Invalid session",
                return_method="login"
            )


@app.route("/logout", methods=["GET"])
@flask_login.login_required
def logout() -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    err_handler.push(
        user_message="",
        log_message=f"{flask_login.current_user.email} has logged out",
        is_error=False
    )

    err_handler.commit_log()

    flask_login.logout_user()
    # redirect to login page for now
    return redirect(url_for('login'))


@app.route("/profile", methods=["GET"])
@flask_login.login_required
def profile() -> str:
    return render_template("profile.html")


@app.route("/profile/enable_mfa", methods=["GET"])
@flask_login.login_required
def route_enable_mfa() -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    if flask_login.current_user.mfa_secret:
        err_handler.push(
            user_message="MFA is already enabled!",
            log_message=f"MFA is already enabled for {flask_login.current_user.email}!"
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("profile"))
    else:
        try:
            mfa_secret = mfa.generate_mfa()
            mfa_secret_uri = mfa.generate_mfa_uri(flask_login.current_user, mfa_secret)

            session['mfa_secret'] = mfa_secret

            err_handler.push(
                user_message="",
                log_message=f"Attempting to enable MFA for {flask_login.current_user.email}",
                is_error=False
            )

            err_handler.commit_log()

            return render_template("mfa_confirm.html", mfa_secret_uri=mfa_secret_uri, mfa_secret=mfa_secret)
        except Exception as e:
            err_handler.push(
                user_message="Error encountered when trying to enable 2FA",
                log_message=f"Error encountered when trying to enable 2FA for {flask_login.current_user.email}: {e}",
                is_error=False
            )

            err_handler.commit_log()

            return redirect(url_for("profile"))


@app.route("/profile/confirm_mfa_enabled", methods=["POST"])
@flask_login.login_required
def route_confirm_mfa_enabled() -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    if flask_login.current_user.mfa_secret:
        err_handler.push(
            user_message="MFA is already enabled!",
            log_message=f"MFA is already enabled for {flask_login.current_user.email}!"
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("profile"))
    else:
        otp = request.form.get("otp", EMPTY_STRING)

        try:
            mfa_secret = session.pop("mfa_secret")

            if otp:
                try:
                    recovery_codes = mfa.confirm_mfa_enabled(flask_login.current_user, mfa_secret, otp)

                    err_handler.push(
                        user_message="",
                        log_message=f"Successfully enabled MFA for {flask_login.current_user.email}!",
                        is_error=False
                    )

                    err_handler.commit_log()

                    return render_template("mfa_recovery_codes.jinja2", recovery_codes=recovery_codes)
                except Exception as e2:
                    err_handler.push(
                        user_message="Something went wrong",
                        log_message=f"Unknown key {e2} in sessions for user {flask_login.current_user.email}",
                    )

                    err_handler.commit_log()

                    if err_handler.has_error():
                        for i in err_handler.all():
                            flash(i.user_message, category="danger")

                    return redirect(url_for("profile"))
            else:
                err_handler.push(
                    user_message="No OTP entered",
                    log_message=f"No OTP entered when trying confirm MFA enablement for user {flask_login.current_user.email}",
                )

                err_handler.commit_log()

                if err_handler.has_error():
                    for i in err_handler.all():
                        flash(i.user_message, category="danger")

                return redirect(url_for("route_enable_mfa"))
        except Exception as e:
            err_handler.push(
                user_message="Something went wrong",
                log_message=f"Something went wrong: {e} for user {flask_login.current_user.email}",
            )

            err_handler.commit_log()

            if err_handler.has_error():
                for i in err_handler.all():
                    flash(i.user_message, category="danger")

            return redirect(url_for("route_enable_mfa"))


@app.route("/search", methods=["GET"])
def search() -> str | Response:
    location = request.args.get("location", EMPTY_STRING, str)
    start_date = request.args.get("start_date", EMPTY_STRING, str)
    end_date = request.args.get("end_date", EMPTY_STRING, str)

    if all([i != EMPTY_STRING for i in [location, start_date, end_date]]):
        search_term = {
            "location": location,
            "start_date": start_date,
            "end_date": end_date,
        }

        err_handler = ErrorHandler(app, dict(request.headers))

        try:
            start_date_obj = datetime.strptime(start_date, DATE_FORMAT)
            end_date_obj = datetime.strptime(end_date, DATE_FORMAT)

            booking_timedelta: datetime = end_date_obj - start_date_obj

            if booking_timedelta.days <= 0:
                user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

                err_handler.push(
                    user_message="End date cannot be earlier than start date!",
                    log_message=f"date cannot be earlier than start date: {start_date} to {end_date}. Searched by {user_email}"
                )
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
            user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

            err_handler.push(
                user_message="Invalid date",
                log_message=f"Invalid date: {start_date} to {end_date}. {e}. Searched by {user_email}"
            )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("index"))
    else:
        err_handler.push(
            user_message="Some mandatory params is empty",
            log_message=f"Some mandatory params is empty: at '{location}' between '{start_date}' to '{end_date}'. Searched by {user_email}"
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("index"))


@app.route("/vehicles/<string:vehicle_type>", methods=["GET"])
def vehicles_by_type(vehicle_type: str) -> str:
    err_handler = ErrorHandler(app, dict(request.headers))

    if vehicle_type not in vehicle_distinct_vehicle_types():
        user_email = "Anonymous" if universal_get_current_user_role(flask_login.current_user) == 0 else flask_login.current_user.email

        err_handler.push(
            user_message="Invalid vehicle type",
            log_message=f"Invalid vehicle type: '{vehicle_type}'. Searched by {user_email}"
        )

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
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


@app.route("/terms-of-use", methods=["GET"])
def terms_of_use() -> str:
    return render_template("termsofuse.html")


@app.route("/privacy-policy", methods=["GET"])
def privacy_policy() -> str:
    return render_template("privacypolicy.html")


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
