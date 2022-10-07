from datetime import date
from booking import Booking
from db import db


def create_booking(start_date: date, end_date: date, id: int):

    new_booking = Booking(
        start_date=start_date,
        end_date=end_date,
        id=id
    )

    db.session.add(new_booking)
    db.session.commit()
