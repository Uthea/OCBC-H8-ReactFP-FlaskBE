import os
from datetime import timedelta

basedir = os.path.dirname(os.path.realpath(__file__))


class BaseConfig(object):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'flask_be_jwt.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    JWT_TOKEN_LOCATION = ['headers']
    JWT_SECRET_KEY = "super-secret"  # Change this!
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=20)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=1)
