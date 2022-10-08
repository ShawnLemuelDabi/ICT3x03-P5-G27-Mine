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
import base64

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


# The route function to CREATE/INSERT new car data into DB
@app.route('/car_create', methods=['POST'])
def car_create():
    if request.method == "POST":
        uploaded_file = request.files['image']
        # Save the user input into variables, to use later
        vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
        license_plate = request.form.get('license_plate', EMPTY_STRING)
        vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)
        image = uploaded_file.stream.read()
        image_name = uploaded_file.name or EMPTY_STRING
        image_mime = uploaded_file.mimetype
        # Calling the function to insert into the db
        create_vehicle(vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
        # Flash message
        flash("A New Vehicle is now Available for Booking")
        # return and render the page template
        return redirect(url_for('car_manager'))


# The route function to RENDER/READ the car managment page
@app.route('/car_management', methods=["GET", "POST"])
def car_manager() -> str:
    # Function to read the vahicle db
    data = read_vehicle()
    for i in data:
        if i.image:
            i.image_b64 = base64.b64encode(i.image).decode('utf8')
    # return and render the page template
    return render_template('car_manager.html', vehicle_list=data)
        


# The route function to UPDATE car data into DB
@app.route('/car_update', methods=['POST'])
def car_update():
    if request.method == "POST":
        MAX_FILE_SIZE_LIMIT = 16777215  # as defined by MEDIUMBLOB

        uploaded_file = request.files['image']
        # Save the user input into variables, to use later
        vehicle_id = request.form.get('vehicle_id', EMPTY_STRING)
        vehicle_model = request.form.get('vehicle_model', EMPTY_STRING)
        license_plate = request.form.get('license_plate', EMPTY_STRING)
        vehicle_type = request.form.get('vehicle_type', EMPTY_STRING)
        location = request.form.get('location', EMPTY_STRING)
        price_per_limit = request.form.get('price_per_limit', EMPTY_STRING)
        image = uploaded_file.stream.read()
        image_size = uploaded_file.content_length
        image_name = uploaded_file.filename
        image_mime = uploaded_file.mimetype

        # Function to update the selected vehicle from vehicle db
        if image_size <= MAX_FILE_SIZE_LIMIT:
            update_vehicle(vehicle_id, vehicle_model, license_plate, vehicle_type, location, price_per_limit, image, image_name, image_mime)
            # Flash message
            flash("The Vehicle was updated")
        else:
            flash("Something went wrong")
        # return and render the page template
        return redirect(url_for('car_manager'))


# The route function to DELETE car data in DB
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
