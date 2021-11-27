from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000))
    username = db.Column(db.String(1000))


class Tokenlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(1000), nullable=False)
    refresh_token = db.Column(db.String(1000), nullable=False)
    used = db.Column(db.BOOLEAN, nullable=False)