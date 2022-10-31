from flask_wtf import FlaskForm, RecaptchaField


class recaptchaForm(FlaskForm):
    recaptcha = RecaptchaField()
