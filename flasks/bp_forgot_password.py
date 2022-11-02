from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app

from db import db

from user import User

from input_validation import EMPTY_STRING, validate_email
from jwt_helper import generate_token, verify_token
import os
import jwt
import time
from email_helper_async import send_mail_async
from werkzeug.security import generate_password_hash
from datetime import datetime
from error_handler import ErrorHandler

bp_forgot_password = Blueprint('bp_forgot_password', __name__, template_folder='templates')


def get_reset_token(email: str, expires: int = 500) -> str:
    return jwt.encode({
        'reset_password': email,
        'exp': time.time() + expires
    }, key=os.environ.get("RESET_PASSWORD_JWT_KEY"), algorithm="HS256")


def verify_reset_token(token: str) -> str:
    try:
        email = jwt.decode(token, key=os.environ.get("RESET_PASSWORD_JWT_KEY"), algorithms="HS256")['reset_password']
        return email
    except Exception as e:
        current_app.logger.fatal(e)


@bp_forgot_password.route("/forgot_password", methods=["GET", "POST"])
def forgot_password() -> str:
    from app import recaptchav3

    if request.method == "POST":
        err_handler = ErrorHandler(current_app, dict(request.headers))
        if recaptchav3.verify():
            email = request.form.get("email", EMPTY_STRING)

            if not validate_email(email):
                err_handler.push(
                    user_message="Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg",
                    log_message=f"Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg. Email given: {email}"
                )

            err_handler.commit_log()
            if err_handler.has_error():
                flash(err_handler.first().user_message, category="danger")
                return render_template("forget_password.html")
            else:
                user: User = User.query.filter_by(email=email).first()

                if user:
                    token = generate_token(email)

                    with current_app.app_context():
                        send_mail_async(
                            app_context=current_app,
                            subject="Reset password",
                            recipients=[email],
                            email_body=render_template('reset_email_msgbody.html', user=email, token=token)
                        )

                return render_template("forget_password_sent.html")
                # TODO: Kill all existing sessions (to be implemented after session management code)
    else:
        return render_template("forget_password.html")


@bp_forgot_password.route("/verify_reset/<string:token>", methods=["GET", "POST"])
def verify_reset(token: str) -> str:
    from app import recaptchav3

    if request.method == "GET":
        # returns email if reset token verified
        email = verify_token(token)
        if email:
            return render_template("reset_password.html", email=email, token=token)
        else:
            flash("Invalid token", category="danger")
            return redirect(url_for('bp_forgot_password.verify_reset'))
    else:
        if recaptchav3.verify():
            # returns email if reset token verified
            email = verify_token(token)
            if email:
                password_1 = request.form.get("password", EMPTY_STRING)
                password_2 = request.form.get("confirm_password", EMPTY_STRING)

                if password_1 == password_2 and password_1 != EMPTY_STRING:
                    password = generate_password_hash(password_1)

                    update_dict = {
                        "password": password
                    }

                    t = User.query.filter_by(email=email)
                    t.update(update_dict)
                    db.session.commit()
                    with current_app.app_context():
                        send_mail_async(
                            app_context=current_app,
                            subject="Reset Password Activity detected",
                            recipients=[email],
                            email_body=render_template('reset_successful.html', datetime=datetime.now())
                        )

                    flash('Login with your newly resetted password!', category="success")
                    return redirect(url_for('login'))
                else:
                    flash('The passwords does not match!', category="danger")
                    return redirect(url_for("bp_forgot_password.verify_reset", token=token))
            else:
                return url_for("bp_forgot_password.verify_reset", token=token)
