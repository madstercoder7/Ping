from flask import Flask, redirect, render_template, url_for, flash, session, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from flask_session import Session
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_socketio import SocketIO, join_room, leave_room, send
from utils import validate_input
from flask_migrate import Migrate
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
import redis
import os
import bleach

load_dotenv()

app = Flask(__name__)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'


if not app.config["SECRET_KEY"]:
    raise ValueError("No SECRET_KEY set for Flask application")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, ping_interval=20, ping_timeout=35)
chat_sessions = {}

# Forms
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=5, max=70)])
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    messages = db.relationship("ChatMessage", backref="chat_session", lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey("chat_session.session_id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        name = bleach.clean(form.name.data.strip(), tags=['p', 'strong', 'em'], strip=True)
        username = bleach.clean(form.username.data.strip(), tags=['p', 'strong', 'em'], strip=True)
        password = form.password.data

        errors = validate_input(
            {
                "name": name,
                "username": username,
                "password": password
            },
            ["name", "username", 'password']
        )

        try:
            if User.query.filter_by(username=username).first():
                errors.append("Username already taken")
        except OperationalError:
            flash("Our database just woke up, please try again later", "warning")
            return redirect(url_for("login"))
        
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("register.html", form=form)
        
        try:
            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
            new_user = User(
                name=name,
                username=username,
                password=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Registered successfully, pease login", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash("An error occured while creatig your account", "danger")
            return render_template("register.html", form=form)
        
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    session.permanent = True
    if session.get("user_id"):
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        username = bleach.clean(form.username.data.strip(), tags=['p', 'strong', 'em'], strip=True)
        password = form.password.data

        errors = validate_input({
            "username": username,
            "password": password
        }, ["username", "password"])
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("login.html", form=form)
        
        try:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session["user_id"] = user.id
                session["username"] = user.username
                flash(f"Welcome back, {user.name}", "success")
                return redirect(url_for("chat"))
            else:
                flash("Invalid username or password", "danger")
                return render_template("login.html", form=form)
        except OperationalError:
            flash("Our database just woke up, please try again after some time", "warning")
            return redirect(url_for("login"))
        
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("index"))



if __name__ == "__main__":
    socketio.run(app, debug=True)