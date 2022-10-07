from crypt import methods
from curses import flash
import email
from functools import wraps
from os import abort
from flask import Flask, request, render_template, url_for, redirect, Response, session

from werkzeug.security import generate_password_hash, check_password_hash


# User imports
from create_user import create_user
from read_user import read_user
from get_user import get_user
from update_user import update_user
from delete_user import delete_user
# Booking imports
from booking import Booking
from create_booking import create_booking

import flask_login

from user import User, ROLE
from engine import engine_uri

from db import db

EMPTY_STRING = ""

# Initialize Flask
app = Flask(__name__)

# These config should be stored in a file in the future
app.config['SQLALCHEMY_DATABASE_URI'] = engine_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # to suppress the warning

# should be safe enough. generated using:
# openssl rand -base64 48
app.secret_key = "rCXueppKaN22oh3zEiXFa9h48GOJY/h8byn0BqdNJm1C9jfz1Qqb4sv6p8oLcikK"

# Initialize the SQLAlchemy middleware
db.init_app(app)

# Initialize the login manager for Flask
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
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

############################### AUTHENTICATION ##############################################
@app.route('/')
def index() -> str:
    return render_template('register.html', user_profile=flask_login.current_user)


@app.route('/register', methods=["GET", "POST"])
def register() -> str:
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        license_id = request.form.get('license_id')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username exists.', category='error')
        elif len(password) < 0:
            flash('Password must be at least 7 characters.', category='error')
        else:
            create_user(username=username, password=password, name=name, email=email, phone_number=phone_number, license_id=license_id, role=0)
            return render_template("login.html")
    return render_template("register.html", user_profile=flask_login.current_user)


@app.route('/login2', methods=["GET"])
def login2() -> str:
    return render_template('login.html')


@app.route('/login', methods=["POST", "GET"])
def login() -> str:
    if request.method == "POST":
        username = request.form.get('username', EMPTY_STRING)
        password = request.form.get('password', EMPTY_STRING)

        if all([i != EMPTY_STRING for i in [username, password]]):
            user = get_user(username, password)
            
            if user:
                # if successfully authenticated
                if check_password_hash(user.password, password):
                    flask_login.login_user(user)

                #return "OK"
                    return render_template('home.html', user_profile=flask_login.current_user)
            else:
                return "NOT OK"
        else:
            return "Something was empty"
    else:
        return render_template('login.html')


@flask_login.login_required
@app.route('/logout')
def logout() -> str:
    flask_login.logout_user()
    return "OK"


# PROFILE
@flask_login.login_required
@app.route('/profile', methods=["GET"])
def profile() -> str:
    return render_template('profile.html', user_profile=flask_login.current_user)


# BOOKING
@flask_login.login_required
@app.route('/bookings')
def booking() -> str:
    bookings = Booking.query.all()
    return render_template("bookings.html", user=flask_login.current_user, booking=bookings)


@app.route("/create-booking", methods=['GET', 'POST'])
@flask_login.login_required
def add_booking():
    if request.method == "POST":
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if not start_date:
            flash('Start Date cannot be empty', category='error')
        elif not end_date:
            flash('End Date cannot be empty', category='error')
        else:
            create_booking(start_date=start_date, end_date=end_date, id=flask_login.current_user.id)
            flash('Booking created!', category='success')
            return redirect(url_for('home'))

    return render_template('create_booking.html', user_profile=flask_login.current_user)

#### USER CRUD #####
@app.route('/user-list', methods=["GET", "POST"])
def user_manager() -> str:
    # Function to read the vahicle db
    data = read_user()
    # return and render the page template
    return render_template('user_manager.html', user_list=data)


# The route function to insert new car data into DB
@app.route('/user_create', methods=['POST'])
def user_create():
    if request.method == "POST":
        # Save the user input into variables, to use later
        username = request.form.get('username', EMPTY_STRING)
        name = request.form.get('name', EMPTY_STRING)
        password = request.form.get('password', EMPTY_STRING)
        email = request.form.get('email', EMPTY_STRING)
        phone_number = request.form.get('phone_number', EMPTY_STRING)
        license_id = request.form.get('license_id', EMPTY_STRING)
        role = request.form.get('role', EMPTY_STRING)
        # Calling the function to insert into the db
        create_user(username=username, name=name, password=password, email=email, phone_number=phone_number, license_id=license_id, role=role)
        # Flash message
        flash("A User has been created")
        # return and render the page template
        return redirect(url_for('user_manager'))


# The route function to update car data into DB
@app.route('/user_update', methods=['POST'])
def user_update():
    if request.method == "POST":
        # Save the user input into variables, to use later
        id = request.form.get('id', EMPTY_STRING)
        username = request.form.get('username', EMPTY_STRING)
        name = request.form.get('name', EMPTY_STRING)
        email = request.form.get('email', EMPTY_STRING)
        phone_number = request.form.get('phone_number', EMPTY_STRING)
        license_id = request.form.get('license_id', EMPTY_STRING)
        role = request.form.get('role', EMPTY_STRING)
        # Function to update the selected vehicle from vehicle db
        update_user(id, username, name, email, phone_number, license_id, role)
        # Flash message
        flash("The User was updated")
        # return and render the page template
        return redirect(url_for('user_manager'))


# The route function to delete car data in DB
@app.route('/user_delete/<int:id>', methods=["GET"])
def user_delete(id):
    # Function to delete the selected vehicle from vehicle db
    delete_user(id)
    # Flash message
    flash("The User was deleted")
    # return and render the page template
    return redirect(url_for('user_manager'))

@flask_login.login_required
@app.route('/admin', methods=["GET"])
def admin() -> str:
    if flask_login.current_user.role == ROLE['admin']:
        return render_template('admin.html', user_profile=flask_login.current_user)
    else:
        return render_template('home.html', user_profile=flask_login.current_user)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
