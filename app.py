from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import webbrowser
import secrets
import datetime
import uuid
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL") or "sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_strong_secret_key_here_for_security'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=31)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)

# यह कोड सुनिश्चित करता है कि डेटाबेस टेबलें Render पर बन जाएं
with app.app_context():
    db.create_all()

def generate_pairing_code():
    return secrets.token_hex(3).upper()

# Database models
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

# Helper function to check for parent status
def is_parent(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' in session:
            g.user = User.query.filter_by(username=session['username']).first()
            if g.user and g.user.is_parent:
                return f(*args, **kwargs)
        return "Access Denied: Not a parent or not logged in.", 403
    return wrapper

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        is_parent = (role == 'parent')
        phone_number = request.form.get('phone_number')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists! Please choose a different one."
            
        new_user = User(username=username, is_parent=is_parent, phone_number=phone_number)
        new_user.set_password(password)
        new_user.profile_pic_url = url_for('static', filename='default-profile.png')
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
            session.permanent = True
            if user.is_parent:
                return redirect(url_for('parent_dashboard'))
            else:
                return redirect(url_for('child_dashboard'))
        else:
            return "Invalid username or password."
            
    return render_template('login.html')

@app.route('/parent')
@is_parent
def parent_dashboard():
    user = g.user
    children = user.children
    return render_template('parent_dashboard.html', username=user.username, children=children, profile_pic_url=user.profile_pic_url)

@app.route('/add_child', methods=['POST'])
@is_parent
def add_child():
    user = g.user
    child_name = request.form['child_name']
    
    new_child = Child(name=child_name, pairing_code=generate_pairing_code(), parent=user)
    db.session.add(new_child)
    db.session.commit()
    
    return redirect(url_for('parent_dashboard'))

@app.route('/refresh_pairing_code/<int:child_id>', methods=['POST'])
@is_parent
def refresh_pairing_code(child_id):
    child = Child.query.get(child_id)
    if child and child.parent_id == g.user.id:
        child.pairing_code = generate_pairing_code()
        db.session.commit()
    return redirect(url_for('parent_dashboard'))

@app.route('/child')
def child_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first_or_404()
    
    child_entry = Child.query.filter_by(child_user_id=user.id).first()
    if child_entry:
        parent = User.query.get(child_entry.parent_id)
        return render_template('child_dashboard.html', username=user.username, parent=parent, profile_pic_url=user.profile_pic_url)
    
    return redirect(url_for('pair_child'))

@app.route('/pair_child', methods=['GET', 'POST'])
def pair_child():
    if request.method == 'POST':
        pairing_code = request.form['pairing_code']
        
        child_user = User.query.filter_by(username=session.get('username')).first()
        if not child_user:
            return redirect(url_for('login'))
            
        child_to_pair = Child.query.filter_by(pairing_code=pairing_code).first()
        if child_to_pair and child_to_pair.child_user_id is None:
            child_to_pair.child_user_id = child_user.id
            db.session.commit()
            return redirect(url_for('child_dashboard'))
        else:
            return "Invalid or already used pairing code."
            
    return render_template('child_pairing.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/update_location', methods=['POST'])
def update_location():
    if 'username' not in session:
        return jsonify(success=False, message="Not logged in.")
    
    user = User.query.filter_by(username=session['username']).first()
    if user and not user.is_parent:
        child_entry = Child.query.filter_by(child_user_id=user.id).first()
        if child_entry:
            data = request.get_json()
            child_entry.last_latitude = data.get('lat')
            child_entry.last_longitude = data.get('lng')
            child_entry.last_seen = datetime.datetime.now()
            db.session.commit()
            return jsonify(success=True)

    return jsonify(success=False)

@app.route('/api/get_children_data')
def get_children_data():
    if 'username' not in session:
        return jsonify(children=[])
    
    parent_user = User.query.filter_by(username=session['username']).first()
    if not parent_user or not parent_user.is_parent:
        return jsonify(children=[])

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

@app.route('/geofence')
@is_parent
def geofence_page():
    return render_template('geofence.html', username=g.user.username)

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

@app.route('/api/get_geofences')
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
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', debug=True, threaded=True)
