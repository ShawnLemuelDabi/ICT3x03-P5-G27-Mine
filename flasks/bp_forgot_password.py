from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app

from db import db

from user import User

from input_validation import EMPTY_STRING

import os
import jwt
import time
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash


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
    if request.method == "POST":
        email = request.form.get("email", EMPTY_STRING)

        user: User = User.query.filter_by(email=email).first()

        if user:
            token = get_reset_token(email)

            with current_app.app_context():
                mail = Mail(current_app)

                msg = Message()
                msg.subject = "Reset Password"
                msg.recipients = [email]
                msg.sender = os.environ.get("SMTP_USERNAME")
                msg.html = render_template('reset_email_msgbody.html', user=email, token=token)

                mail.send(msg)

        return render_template("forget_password_sent.html")

        # TODO: Kill all existing sessions (to be implemented after session management code)
    else:
        return render_template("forget_password.html")


@bp_forgot_password.route("/verify_reset/<string:token>", methods=["GET", "POST"])
def verify_reset(token: str) -> str:
    if request.method == "GET":
        # returns email if reset token verified
        email = verify_reset_token(token)
        if email:
            return render_template("reset_password.html", email=email, token=token)
        else:
            return "Invalid token"
    else:
        # returns email if reset token verified
        email = verify_reset_token(token)
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
                flash('Login with your newly resetted password!')
                return redirect(url_for('login'))
            else:
                flash('The passwords does not match!', category="error")
                return redirect(url_for("bp_forgot_password.verify_reset", token=token))
        else:
            return url_for("bp_forgot_password.verify_reset", token=token)
