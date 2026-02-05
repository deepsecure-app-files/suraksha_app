import os
import secrets
import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 1. DATABASE CONFIGURATION (SUDHAAR) ---
database_url = os.environ.get('DATABASE_URL')

# Render fix: postgres:// ko postgresql:// mein badalna
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key_change_this')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=31)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# ✅ YE LINE SABSE JARURI HAI: Naya DB connect hote hi tables bana degi
with app.app_context():
    try:
        db.create_all()
        print("✅ Database Tables Created Successfully!")
    except Exception as e:
        print(f"❌ Error: {e}")

def generate_pairing_code():
    return secrets.token_hex(3).upper()

# --- 2. DATABASE MODELS (APKA PURANA CODE) ---
class User(db.Model):
    __tablename__ = 'app_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_parent = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    profile_pic_url = db.Column(db.String(200), nullable=True)
    children = db.relationship('Child', foreign_keys='Child.parent_id', backref='parent', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    pairing_code = db.Column(db.String(6), unique=True, nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    child_user_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)

# --- 3. ROUTES (SAB KUCH PEHLE JAISA) ---
@app.route('/')
def home():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            return redirect(url_for('parent_dashboard' if user.is_parent else 'child_dashboard'))
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        new_user = User(username=username, is_parent=(role == 'parent'))
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            return redirect(url_for('parent_dashboard' if user.is_parent else 'child_dashboard'))
    return render_template('login.html')

# (Baki dashboard aur API routes ko bhi aise hi rehne den)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
    return redirect(url_for('parent_dashboard' if user.is_parent else 'child_dashboard'))

@app.route('/geofence')
@is_parent
def geofence_page():
    return render_template('geofence.html', username=g.user.username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=10000)
