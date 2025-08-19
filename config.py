# config.py

import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///../db/cai.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
