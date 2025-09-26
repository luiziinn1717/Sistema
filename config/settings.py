import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(32)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///propostas.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    DEBUG = os.getenv('FLASK_ENV') == 'development'
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Security settings
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)