from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app
import flask_login

from db import db
from brute_force_helper import failed_attempt, password_reset_is_disabled, BruteForceCategory
from password_history import Password_History, HISTORY_LIMIT

from user import User, Role

from input_validation import EMPTY_STRING, validate_email, validate_password
from jwt_helper import can_reset_password, verify_token, generate_reset_password_token, password_resetted
from email_helper_async import send_mail_async
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from error_handler import ErrorHandler
from authorizer import universal_get_current_user_role


def can_change_password(email: str, password: str) -> bool:
    user = User.query.filter(User.email == email).first()

    if user:
        """
        current password
        """
        if check_password_hash(user.password, password):
            return False

        """
        old passwords
        """
        password_histories = Password_History.query.join(Password_History.user, aliased=True).filter(
            Password_History.user_id == user.user_id,
        ).order_by(Password_History.password_history_id.desc()).limit(HISTORY_LIMIT)

        for i in password_histories.all():
            if check_password_hash(i.password, password):
                return False
        return True
    return False


bp_forgot_password = Blueprint('bp_forgot_password', __name__, template_folder='templates')


@bp_forgot_password.route("/forgot_password", methods=["GET", "POST"])
def forgot_password() -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))

    if universal_get_current_user_role(flask_login.current_user) != Role.ANONYMOUS_USER:
        user_email = flask_login.current_user.email
        err_handler.push(
            user_message="You are already logged in!",
            log_message=f"Logged in user {user_email} tried to access forgot password"
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("profile"))
    else:
        from app import recaptchav3

        if request.method == "POST":
            if request.form.get("g-recaptcha-response", False) and recaptchav3.verify() or current_app.debug:
                email = request.form.get("email", EMPTY_STRING)

                if not validate_email(email):
                    err_handler.push(
                        user_message="Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg",
                        log_message=f"Email provider must be from Gmail, Hotmail, Yahoo or singaporetech.edu.sg. Email given: {email}"
                    )

                if password_reset_is_disabled(email):
                    err_handler.push(
                        user_message="Password reset has already been requested. Please check your junk or spam folder of your email or try again later.",
                        log_message=f"Repeated request for password reset. Requested by: {email}"
                    )

                if err_handler.has_error():
                    err_handler.commit_log()
                    flash(err_handler.first().user_message, category="danger")
                    return render_template("forget_password.html")
                else:
                    user: User = User.query.filter_by(email=email).first()

                    if user:
                        token = generate_reset_password_token(email)

                        with current_app.app_context():
                            send_mail_async(
                                app_context=current_app,
                                subject="Reset password",
                                recipients=[email],
                                email_body=render_template('reset_email_msgbody.html', user=email, token=token)
                            )

                        err_handler.push(
                            user_message="",
                            log_message=f"Password reset link requested for a known email: {email}",
                            is_error=False
                        )
                    else:
                        err_handler.push(
                            user_message="",
                            log_message=f"Password reset link requested for non-existent email: {email}",
                            is_error=False
                        )

                    try:
                        failed_attempt(email=email, category=BruteForceCategory.PASSWORD_RESET)
                    except ValueError as e:
                        err_handler.push(
                            user_message="",
                            log_message=f"Failed to commit brute force attempt to database due to bad category '{BruteForceCategory.PASSWORD_RESET}'. {e}. Requested by email '{email}'"
                        )
                    err_handler.commit_log()

                    return render_template("forget_password_sent.html")
                    # TODO: Kill all existing sessions (to be implemented after session management code)
        else:
            return render_template("forget_password.html")


@bp_forgot_password.route("/verify_reset/<string:token>", methods=["GET", "POST"])
def verify_reset(token: str) -> str:
    err_handler = ErrorHandler(current_app, dict(request.headers))

    if universal_get_current_user_role(flask_login.current_user) != Role.ANONYMOUS_USER:
        user_email = flask_login.current_user.email
        err_handler.push(
            user_message="You are already logged in!",
            log_message=f"Logged in user {user_email} tried to access forgot password"
        )

        err_handler.commit_log()

        if err_handler.has_error():
            for i in err_handler.all():
                flash(i.user_message, category="danger")
        return redirect(url_for("profile"))
    else:
        from app import recaptchav3

        if request.method == "GET":
            # returns email if reset token verified
            try:
                email = verify_token(token)

                if email:
                    if not can_reset_password(token):
                        err_handler.push(
                            user_message="You have already resetted your password! Please make another password reset request instead!",
                            log_message=f"Repeated use of reset token for password reset. Requested by: {email}"
                        )
                        flash(err_handler.first().user_message, category="danger")
                        return redirect(url_for("bp_forgot_password.forgot_password"))
                    else:
                        return render_template("reset_password.html", email=email, token=token)
                else:
                    err_handler.push(
                        user_message="Invalid token",
                        log_message="Invalid token submitted. The token either has no email attribute or has expired."
                    )
                    err_handler.commit_log()
                    flash(err_handler.first().user_message, category="danger")
                    return redirect(url_for('bp_forgot_password.forgot_password'))
            except Exception:
                err_handler.push(
                    user_message="Invalid token",
                    log_message="Invalid token submitted. The token either has no email attribute or has expired."
                )
                err_handler.commit_log()
                flash(err_handler.first().user_message, category="danger")
                return redirect(url_for('bp_forgot_password.forgot_password'))
        else:
            if request.form.get("g-recaptcha-response", False) and recaptchav3.verify() or current_app.debug:
                # returns email if reset token verified
                email = verify_token(token)

                if email:
                    if not can_reset_password(token):
                        err_handler.push(
                            user_message="You have already resetted your password! Please make another password reset request instead!",
                            log_message=f"Repeated use of reset token for password reset. Requested by: {email}"
                        )
                        err_handler.commit_log()
                        flash(err_handler.first().user_message, category="danger")
                        return redirect(url_for('bp_forgot_password.verify_reset'))
                    else:
                        password_1 = request.form.get("password", EMPTY_STRING)
                        password_2 = request.form.get("confirm_password", EMPTY_STRING)

                        if validate_password(password_1, password_2):
                            if not can_change_password(email, password_1):
                                err_handler.push(
                                    user_message="Please do not reuse an old password!",
                                    log_message=f"Attempted to reset password to an old password. Requested by {email}"
                                )
                            else:
                                password = generate_password_hash(password_1)

                                update_dict = {
                                    "password": password
                                }

                                t = User.query.filter_by(email=email)
                                user = t.first()
                                old_password = user.password
                                t.update(update_dict)

                                new_password_history = Password_History(
                                    user_id=user.user_id,
                                    password=old_password,
                                    valid_till=datetime.now()
                                )

                                db.session.add(new_password_history)

                                db.session.commit()
                                with current_app.app_context():
                                    send_mail_async(
                                        app_context=current_app,
                                        subject="Reset Password Activity detected",
                                        recipients=[email],
                                        email_body=render_template('reset_successful.html', datetime=datetime.now())
                                    )

                                flash('Login with your newly resetted password!', category="success")
                                err_handler.push(
                                    user_message="",
                                    log_message=f"Password resetted successful for {email}",
                                    is_error=False
                                )
                                try:
                                    password_resetted(token)
                                except Exception as e:
                                    err_handler.push(
                                        user_message="",
                                        log_message=f"Failed to consume reset token due to {e}. Request made by {email}",
                                    )
                                err_handler.commit_log()

                                return redirect(url_for('login'))
                        else:
                            err_handler.push(
                                user_message="The passwords does not match!",
                                log_message=f"The passwords does not match for '{email}'"
                            )
                        err_handler.commit_log()
                        flash(err_handler.first().user_message, category="danger")

                        return redirect(url_for("bp_forgot_password.verify_reset", token=token))
                else:
                    err_handler.push(
                        user_message="Invalid token",
                        log_message="Invalid token submitted. The token either has no email attribute or has expired."
                    )
                    err_handler.commit_log()
                    flash(err_handler.first().user_message, category="danger")

                    return url_for("bp_forgot_password.verify_reset", token=token)
            else:
                err_handler.push(
                    user_message="CSRF token expired",
                    log_message="CSRF token expired."
                )

                err_handler.commit_log()
                flash(err_handler.first().user_message, category="danger")
                return redirect(url_for('bp_forgot_password.verify_reset', token=token))
