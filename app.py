from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import datetime
from functools import wraps
import os
import math

# Use os.environ.get to handle both local and production environments
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_strong_secret_key_here_for_security')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=31)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)

# --- यह वह महत्वपूर्ण बदलाव है जो डेटाबेस टेबल को बनाएगा ---
# यह कोड ऐप शुरू होते ही चलेगा और सुनिश्चित करेगा कि टेबल मौजूद हों
with app.app_context():
    db.create_all()
# ------------------------------------------------------------------

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def generate_pairing_code():
    return secrets.token_hex(3).upper()

def check_geofence_status(child, current_lat, current_lng):
    """
    यह फ़ंक्शन बच्चे की वर्तमान लोकेशन की तुलना उसके माता-पिता द्वारा बनाए गए
    सभी जिओफेंस से करता है।
    """
    geofences = Geofence.query.filter_by(parent_id=child.parent_id).all()
    
    for fence in geofences:
        # Haversine formula to calculate distance between two coordinates
        R = 6371e3 # Earth radius in meters
        phi1 = math.radians(fence.latitude)
        phi2 = math.radians(current_lat)
        delta_phi = math.radians(current_lat - fence.latitude)
        delta_lambda = math.radians(current_lng - fence.longitude)

        a = math.sin(delta_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c

        if distance < fence.radius:
            print(f"Alert: Child {child.name} has entered geofence: {fence.location_name}")
            # Here you would add code to send a push notification to the parent's app
        else:
            print(f"Child {child.name} is outside geofence: {fence.location_name}")

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_parent = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    profile_pic_url = db.Column(db.String(200), nullable=True)
    children = db.relationship('Child', foreign_keys='Child.parent_id', backref='parent', lazy=True)
    geofences = db.relationship('Geofence', backref='parent', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    pairing_code = db.Column(db.String(6), unique=True, nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    child_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    child_user = db.relationship('User', foreign_keys=[child_user_id])
    last_seen = db.Column(db.DateTime, nullable=True)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)

class Geofence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_name = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)

# New model to store location history
class LocationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)

# Helper function to check for parent status
def is_parent(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' in session:
            g.user = User.query.filter_by(username=session['username']).first()
            if g.user and g.user.is_parent:
                return f(*args, **kwargs)
        return jsonify(success=False, message="Access Denied: Not a parent or not logged in."), 403
    return wrapper

# --- Routes (API Endpoints for Android App) ---
@app.route('/')
def home():
    return "Welcome to the Family Tracker Backend API."

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    is_parent = (role == 'parent')
    phone_number = request.form.get('phone_number')
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"success": False, "message": "Username already exists! Please choose a different one."}), 409
        
    new_user = User(username=username, is_parent=is_parent, phone_number=phone_number)
    new_user.set_password(password)
    new_user.profile_pic_url = url_for('static', filename='default-profile.png')
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"success": True, "message": "User registered successfully."}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = user.username
        session.permanent = True
        return jsonify({"success": True, "message": "Login successful.", "is_parent": user.is_parent, "username": user.username})
    else:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401
        
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify(success=True, message="Logout successful.")

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.set_password(new_password)
        db.session.commit()
        return jsonify(success=True, message="Password reset successfully.")
    else:
        return jsonify(success=False, message="Username not found."), 404

@app.route('/add_child', methods=['POST'])
@is_parent
def add_child():
    user = g.user
    data = request.get_json()
    child_name = data.get('child_name')
    
    new_child = Child(name=child_name, pairing_code=generate_pairing_code(), parent=user)
    db.session.add(new_child)
    db.session.commit()
    
    return jsonify(success=True, message="Child added successfully.", pairing_code=new_child.pairing_code, child_id=new_child.id)

@app.route('/pair_child', methods=['POST'])
def pair_child():
    if 'username' not in session:
        return jsonify(success=False, message="Not logged in."), 401
    
    child_user = User.query.filter_by(username=session.get('username')).first()
    if not child_user or child_user.is_parent:
        return jsonify(success=False, message="Access Denied: Not a child user."), 403
        
    data = request.get_json()
    pairing_code = data.get('pairing_code')
        
    child_to_pair = Child.query.filter_by(pairing_code=pairing_code).first()
    if child_to_pair and child_to_pair.child_user_id is None:
        child_to_pair.child_user_id = child_user.id
        db.session.commit()
        return jsonify(success=True, message="Child paired successfully.")
    else:
        return jsonify(success=False, message="Invalid or already used pairing code."), 400

@app.route('/update_location', methods=['POST'])
def update_location():
    if 'username' not in session:
        return jsonify(success=False, message="Not logged in."), 401
    
    user = User.query.filter_by(username=session['username']).first()
    if user and not user.is_parent:
        child_entry = Child.query.filter_by(child_user_id=user.id).first()
        if child_entry:
            data = request.get_json()
            lat = data.get('lat')
            lng = data.get('lng')

            if not lat or not lng:
                return jsonify(success=False, message="Latitude and Longitude are required."), 400

            child_entry.last_latitude = lat
            child_entry.last_longitude = lng
            child_entry.last_seen = datetime.datetime.now()
            
            # Add new location to history
            new_history = LocationHistory(
                child_id=child_entry.id,
                latitude=lat,
                longitude=lng
            )
            db.session.add(new_history)
            db.session.commit()

            # Check geofence status (does not send push notification yet)
            check_geofence_status(child_entry, lat, lng)

            return jsonify(success=True)

    return jsonify(success=False, message="User not a child or not found."), 404

@app.route('/api/get_children_data', methods=['GET'])
@is_parent
def get_children_data():
    parent_user = g.user

    children_list = []
    for child in parent_user.children:
        child_user = User.query.get(child.child_user_id)
        children_list.append({
            'id': child.id,
            'name': child.name,
            'pairing_code': child.pairing_code,
            'last_latitude': child.last_latitude,
            'last_longitude': child.last_longitude,
            'last_seen': child.last_seen.isoformat() if child.last_seen else None,
            'phone_number': child_user.phone_number if child_user else None,
            'profile_pic_url': child_user.profile_pic_url if child_user and child_user.profile_pic_url else url_for('static', filename='default-profile.png')
        })
    return jsonify(children=children_list)

@app.route('/api/get_location_history/<int:child_id>', methods=['GET'])
@is_parent
def get_location_history(child_id):
    child = Child.query.get(child_id)
    if not child or child.parent_id != g.user.id:
        return jsonify(success=False, message="Child not found or not your child."), 404

    history = LocationHistory.query.filter_by(child_id=child.id).order_by(LocationHistory.timestamp.asc()).all()
    
    history_list = [{
        'lat': entry.latitude,
        'lng': entry.longitude,
        'timestamp': entry.timestamp.isoformat()
    } for entry in history]

    return jsonify(success=True, history=history_list)

@app.route('/save_geofence', methods=['POST'])
@is_parent
def save_geofence():
    data = request.get_json()
    new_geofence = Geofence(
        parent=g.user,
        location_name=data.get('location_name'),
        latitude=data.get('lat'),
        longitude=data.get('lng'),
        radius=data.get('radius')
    )
    db.session.add(new_geofence)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/get_geofences', methods=['GET'])
@is_parent
def get_geofences():
    geofences = Geofence.query.filter_by(parent_id=g.user.id).all()
    geofence_list = []
    for fence in geofences:
        geofence_list.append({
            'id': fence.id,
            'location_name': fence.location_name,
            'lat': fence.latitude,
            'lng': fence.longitude,
            'radius': fence.radius
        })
    return jsonify(geofences=geofence_list)

@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'username' not in session:
        return jsonify(success=False, message="Not logged in."), 401
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify(success=False, message="User not found."), 404
        
    if 'file' not in request.files:
        return jsonify(success=False, message="No file part."), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="No selected file."), 400

    if file:
        filename = f"{user.username}_profile_pic.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        user.profile_pic_url = url_for('static', filename=f'uploads/{filename}')
        db.session.commit()
        return jsonify(success=True, profile_pic_url=user.profile_pic_url)
    
    return jsonify(success=False, message="Failed to upload file."), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)

