from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from app.email_service import configure_email

app = Flask(__name__)
app.config.from_object("app.config.Config")

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
lm = LoginManager()
lm.login_view = "login"
lm.init_app(app)

configure_email(app)

from app import models, views  # noqa: E402,F401

with app.app_context():
    db.create_all()
