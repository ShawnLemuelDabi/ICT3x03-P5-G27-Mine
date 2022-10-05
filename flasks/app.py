from flask import Flask, request, render_template

from create_user import create_user
from get_user import get_user

import flask_login

from user import User
from engine import engine_uri

from db import db

import os

EMPTY_STRING = ""

# Initialize Flask
app = Flask(__name__)

# These config should be stored in a file in the future
app.config['SQLALCHEMY_DATABASE_URI'] = engine_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # to suppress the warning

app.secret_key = os.environ.get("FLASK_LOGIN_SECRET")

# Initialize the SQLAlchemy middleware
db.init_app(app)

# Initialize the login manager for Flask
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index() -> str:
    return render_template('register.html', user_profile=flask_login.current_user)


@app.route('/login2', methods=["GET"])
def login2() -> str:
    return render_template('login.html')


@app.route('/login', methods=["POST"])
def login() -> str:
    username = request.form.get('username', EMPTY_STRING)
    password = request.form.get('password', EMPTY_STRING)

    if all([i != EMPTY_STRING for i in [username, password]]):
        user = get_user(username, password)

        if user:
            # if successfully authenticated
            flask_login.login_user(user)

            return "OK"
        else:
            return "NOT OK"
    else:
        return "Something was empty"


@flask_login.login_required
@app.route('/logout')
def logout() -> str:
    flask_login.logout_user()
    return "OK"


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', EMPTY_STRING)
    password = request.form.get('password', EMPTY_STRING)

    if all([i != EMPTY_STRING for i in [username, password]]):
        create_user(username, password)

        return "OK"
    else:
        return "Something was empty"


if __name__ == "__main__":
    app.run(host='0.0.0.0')
