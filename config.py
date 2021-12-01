import os
from datetime import timedelta

basedir = os.path.dirname(os.path.realpath(__file__))


def get_db_url():
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        return db_url.replace("postgres", "postgresql")  # heroku prefix db url with postgres instead of postgresql

    return db_url


class BaseConfig(object):
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'flask_be_jwt.db')
    SQLALCHEMY_DATABASE_URI = get_db_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    JWT_TOKEN_LOCATION = ['headers']
    JWT_SECRET_KEY = "super-secret"  # Change this!
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=20)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=1)
