from vehicle import vehicle
from db import db


def update_vehicle(find_vehicle_id: int, changed_model: str, changed_license_plate: str, changed_type: str, change_location: str, change_price_per_unit: float, change_image: bytes, change_image_name: str, change_image_mime: str):
    update_dict = {
        "vehicle_model": changed_model,
        "license_plate": changed_license_plate,
        "vehicle_type": changed_type,
        "location": change_location,
        "image": change_image,
        "image_name": change_image_name,
        "image_mime": change_image_mime,
        "price_per_unit": change_price_per_unit
    }

    if len(update_dict['image']) == 0 and not update_dict['image_name']:
        del update_dict['image']
        del update_dict['image_name']
        del update_dict['image_mime']

    # Action mariaDB will have the execute using SQLAlchemy
    vehicle.query.filter_by(vehicle_id=find_vehicle_id).update(update_dict)
    # This are the function for updating vehicle details from the db using SQLAlchemy
    db.session.commit()
