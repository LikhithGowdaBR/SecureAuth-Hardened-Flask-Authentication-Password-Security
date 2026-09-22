import time

import bcrypt
from flask import current_app, redirect, render_template, request, session, url_for
from flask_login import login_user, logout_user
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError

from app import app, db, lm
from app.email_service import send_password_reset_email
from app.forms import LoginForm, RegisterForm
from app.ml.password_strength import assess_password
from app.models import Users
from app.reset_code_service import PasswordResetCodeService
from app.security import get_failed_attempts_count, get_lockout_remaining_time, is_ip_locked, record_failed_attempt, reset_failed_attempts

reset_code_service = PasswordResetCodeService()
RESET_SESSION_TTL_SECONDS = 15 * 60


def _password_hash(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=13)).decode("utf-8")


def _password_matches(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _csrf_is_valid():
    try:
        validate_csrf(request.form.get("csrf_token", ""))
        return True
    except ValidationError:
        return False


@lm.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))


@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().casefold()
        assessment = assess_password(form.password.data, username, email)
        if not assessment.accepted:
            return render_template("register.html", form=form, msg=assessment.feedback)
        if Users.query.filter((Users.user == username) | (Users.email == email)).first():
            return render_template("register.html", form=form, msg="An account with those details already exists.")

        Users(username, email, _password_hash(form.password.data)).save()
        return render_template("register.html", form=form, msg='Account created. Please <a href="/login">sign in</a>.', success=True)
    if request.method == "POST":
        return render_template("register.html", form=form, msg="Please correct the highlighted fields.")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    ip_address = request.remote_addr or "unknown"
    if is_ip_locked(ip_address):
        return render_template("login.html", form=form, is_locked=True, lockout_time=get_lockout_remaining_time(ip_address))

    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data.strip()
        user = Users.query.filter_by(user=username).first()
        if user and _password_matches(form.password.data, user.password):
            reset_failed_attempts(ip_address)
            login_user(user)
            return redirect(url_for("index"))

        record_failed_attempt(ip_address)
        count = get_failed_attempts_count(ip_address)
        return render_template(
            "login.html", form=form, msg="Invalid username or password.",
            is_locked=is_ip_locked(ip_address), lockout_time=get_lockout_remaining_time(ip_address),
            attempt_count=count, max_attempts_warning=is_ip_locked(ip_address),
        )
    if request.method == "POST":
        return render_template("login.html", form=form, msg="Invalid username or password.")
    return render_template("login.html", form=form)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        if not _csrf_is_valid():
            return render_template("forgot_password_otp.html", msg="Your form expired. Please try again.")
        email = request.form.get("email", "", type=str).strip().casefold()
        if not current_app.config["MAIL_ENABLED"]:
            message = "Password-reset email is not configured. Set valid SMTP credentials in .env and restart the application."
            if current_app.config["ENV"] == "production":
                message = "Password-reset email is temporarily unavailable. Please contact support."
            return render_template("forgot_password_otp.html", msg=message)
        user = Users.query.filter_by(email=email).first()
        if user:
            code = reset_code_service.generate_code(email)
            if not send_password_reset_email(email, code):
                reset_code_service.discard_code(email)
                return render_template("forgot_password_otp.html", msg="We could not send a reset email. Please try again later.")
        # The response is intentionally identical whether an account exists.
        return render_template("forgot_password_otp.html", success=True, msg="If the address belongs to an account, a verification code has been sent.")
    return render_template("forgot_password_otp.html")


@app.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():
    if request.method == "POST":
        if not _csrf_is_valid():
            return render_template("verify_code.html", msg="Your form expired. Please try again.")
        email = request.form.get("email", "", type=str).strip().casefold()
        code = request.form.get("code", "", type=str).strip()
        if len(code) == 6 and code.isdecimal() and reset_code_service.verify_code(email, code):
            session["reset_email"] = email
            session["reset_verified_until"] = int(time.time()) + RESET_SESSION_TTL_SECONDS
            return redirect(url_for("reset_password_otp"))
        return render_template("verify_code.html", msg="Invalid or expired verification code.", email=email)
    return render_template("verify_code.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password_otp():
    email = session.get("reset_email")
    expires_at = session.get("reset_verified_until", 0)
    if not email or time.time() >= expires_at:
        session.pop("reset_email", None)
        session.pop("reset_verified_until", None)
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        if not _csrf_is_valid():
            return render_template("reset_password_otp.html", email=email, msg="Your form expired. Please try again.")
        password = request.form.get("password", "", type=str)
        confirmation = request.form.get("password_confirm", "", type=str)
        if password != confirmation:
            return render_template("reset_password_otp.html", email=email, msg="Passwords do not match.")
        assessment = assess_password(password, email=email)
        if not assessment.accepted:
            return render_template("reset_password_otp.html", email=email, msg=assessment.feedback)
        user = Users.query.filter_by(email=email).first()
        if not user:
            session.clear()
            return redirect(url_for("forgot_password"))
        user.password = _password_hash(password)
        db.session.commit()
        session.pop("reset_email", None)
        session.pop("reset_verified_until", None)
        return render_template("reset_password_otp.html", email=email, success=True, show_login_link=True, msg="Password reset successfully.")
    return render_template("reset_password_otp.html", email=email)


@app.route("/", defaults={"path": "index"})
@app.route("/<path:path>")
def index(path):
    return render_template("index.html")
