from datetime import date
from booking import Booking
from db import db


def create_booking(start_date: date, end_date: date, user_id: int, vehicle_id: int, units_purchased: int = 1, is_paid: bool = False) -> Booking:

    new_booking = Booking(
        start_date=start_date,
        end_date=end_date,
        user_id=user_id,
        vehicle_id=vehicle_id,
        is_paid=is_paid,
        units_purchased=units_purchased
    )

    db.session.add(new_booking)
    db.session.commit()

    return new_booking
