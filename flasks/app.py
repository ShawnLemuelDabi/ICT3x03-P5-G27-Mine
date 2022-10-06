from flask import Flask, request, render_template, flash, redirect, url_for

from create_user import create_user
from get_user import get_user
# Vehicle CRUD Function Files
from create_vehicle import create_vehicle
from read_vehicle import read_vehicle
from update_vehicle import update_vehicle
from delete_vehicle import delete_vehicle

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


# The route function to render the car managment page
@app.route('/car_managment', methods=["GET", "POST"])
def car_manager() -> str:
    # Function to read the vahicle db
    data = read_vehicle()
    # return and render the page template
    return render_template('car_manager.html', vehicle_list=data)


# The route function to insert new car data into DB
@app.route('/car_create', methods=['POST'])
def car_create():
    if request.method == "POST":
        # Save the user input into variables, to use later
        model = request.form.get('model', EMPTY_STRING)
        license_plate = request.form.get('plate', EMPTY_STRING)
        type = request.form.get('type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        Price_Per_Limit = request.form.get('Price_Per_Limit', EMPTY_STRING)
        image = request.form.get('image', EMPTY_STRING)
        # Calling the function to insert into the db
        create_vehicle(model, license_plate, type, location, Price_Per_Limit, image)
        # Flash message
        flash("A New Vehicle is now Available for Booking")
        # return and render the page template
        return redirect(url_for('car_manager'))


# The route function to update car data into DB
@app.route('/car_update', methods=['POST'])
def car_update():
    if request.method == "POST":
        # Save the user input into variables, to use later
        id = request.form.get('car_id', EMPTY_STRING)
        model = request.form.get('model', EMPTY_STRING)
        license_plate = request.form.get('plate', EMPTY_STRING)
        type = request.form.get('type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        Price_Per_Limit = request.form.get('Price_Per_Limit', EMPTY_STRING)
        image = request.form.get('image', EMPTY_STRING)
        # Function to update the selected vehicle from vehicle db
        update_vehicle(id, model, license_plate, type, location, Price_Per_Limit, image)
        # Flash message
        flash("The Vehicle was updated")
        # return and render the page template
        return redirect(url_for('car_manager'))


# The route function to delete car data in DB
@app.route('/car_delete/<int:id>', methods=["GET"])
def car_delete(id):
    # Function to delete the selected vehicle from vehicle db
    delete_vehicle(id)
    # Flash message
    flash("The Vehicle was deleted")
    # return and render the page template
    return redirect(url_for('car_manager'))


if __name__ == "__main__":
    app.run(host='0.0.0.0')
