from flask_wtf import FlaskForm, RecaptchaField
from flask import Flask

from google_recaptcha import ReCaptcha

import os


class recaptchaForm(FlaskForm):
    recaptcha = RecaptchaField()


def recaptchav3(app: Flask):
    return ReCaptcha(
        app,
        site_key=os.environ.get("RC_SITE_KEY_V3"),
        site_secret=os.environ.get("RC_SECRET_KEY_V3")
    )
