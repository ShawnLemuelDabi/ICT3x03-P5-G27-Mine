from db import db
from sqlalchemy.sql import func

class Booking(db.Model):
    __tablename__ = "Booking"
    booking_id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date())
    end_date = db.Column(db.Date())
    user = db.Column(db.Integer, db.ForeignKey(
        'User.id', ondelete="CASCADE"), nullable=False)
    