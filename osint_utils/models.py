from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    agent_id = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    subscription_expires = db.Column(db.DateTime)


    def is_active(self):
        return datetime.utcnow() < self.subscription_expires
