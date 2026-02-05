import os
import secrets
import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 1. DATABASE CONFIGURATION ---
database_url = os.environ.get('DATABASE_URL')

# Render fix for PostgreSQL
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key_change_this')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=31)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Folders create karna jaruri hai
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

def generate_pairing_code():
    return secrets.token_hex(3).upper()

# --- 2. DATABASE MODELS ---

class User(db.Model):
    __tablename__ = 'app_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_parent = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    profile_pic_url = db.Column(db.String(200), nullable=True)
    
    # Relationships
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
    
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    child_user_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    
    child_user = db.relationship('User', foreign_keys=[child_user_id])
    
    last_seen = db.Column(db.DateTime, nullable=True)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)

class Geofence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=False)
    location_name = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)

# --- 3. HELPER FUNCTIONS ---

def is_parent(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' in session:
            # Har request par user load karte hain
            g.user = User.query.filter_by(username=session['username']).first()
            if g.user and g.user.is_parent:
                return f(*args, **kwargs)
        return "Access Denied: Not a parent or not logged in.", 403
    return wrapper

# --- 4. ROUTES ---

@app.route('/')
def home():
    # Login check
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            if user.is_parent:
                return redirect(url_for('parent_dashboard'))
            else:
                return redirect(url_for('child_dashboard'))
    return render_template('home.html') 

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        is_parent = (role == 'parent')
        phone_number = request.form.get('phone_number')
        
        try:
            if User.query.filter_by(username=username).first():
                return "Username already exists!"
                
            new_user = User(username=username, is_parent=is_parent, phone_number=phone_number)
            new_user.set_password(password)
            # Default pic set karte hain
            new_user.profile_pic_url = url_for('static', filename='default-profile.png')
            
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            return f"Error: {str(e)}"
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
    # Ensure children list load ho
    children = user.children
    return render_template('parent_dashboard.html', 
                           username=user.username, 
                           children=children, 
                           profile_pic_url=user.profile_pic_url)

@app.route('/add_child', methods=['POST'])
@is_parent
def add_child():
    user = g.user
    child_name = request.form['child_name']
    new_child = Child(name=child_name, pairing_code=generate_pairing_code(), parent=user)
    db.session.add(new_child)
    db.session.commit()
    return redirect(url_for('parent_dashboard'))

@app.route('/child')
def child_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first_or_404()
    
    # Check pairing
    child_entry = Child.query.filter_by(child_user_id=user.id).first()
    
    parent_data = None
    if child_entry:
        parent_data = User.query.get(child_entry.parent_id)
        
    return render_template('child_dashboard.html', 
                           username=user.username, 
                           parent=parent_data, 
                           child_info=child_entry, 
                           profile_pic_url=user.profile_pic_url)

@app.route('/pair_device', methods=['POST'])
def pair_device():
    if 'username' not in session: return redirect(url_for('login'))
    
    pairing_code = request.form['pairing_code']
    child_user = User.query.filter_by(username=session['username']).first()
    
    child_to_pair = Child.query.filter_by(pairing_code=pairing_code).first()
    
    if child_to_pair:
        child_to_pair.child_user_id = child_user.id
        db.session.commit()
        return redirect(url_for('child_dashboard'))
    else:
        return "Invalid Code"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# --- API FOR TRACKING ---
@app.route('/api/update_location', methods=['POST'])
def update_location():
    if 'username' not in session:
        return jsonify(status='error', message="Not logged in")
    
    user = User.query.filter_by(username=session['username']).first()
    
    # Agar user child hai, to location update karo
    if user and not user.is_parent:
        child_entry = Child.query.filter_by(child_user_id=user.id).first()
        if child_entry:
            data = request.get_json()
            child_entry.last_latitude = data.get('latitude')
            child_entry.last_longitude = data.get('longitude')
            child_entry.last_seen = datetime.datetime.utcnow()
            db.session.commit()
            return jsonify(status='success')

    return jsonify(status='error')

@app.route('/api/get_children_data')
def get_children_data():
    if 'username' not in session: return jsonify(children=[])
    
    parent_user = User.query.filter_by(username=session['username']).first()
    if not parent_user or not parent_user.is_parent: return jsonify(children=[])

    children_list = []
    for child in parent_user.children:
        child_user = User.query.get(child.child_user_id)
        # Profile pic logic
        pic = url_for('static', filename='default-profile.png')
        if child_user and child_user.profile_pic_url:
            pic = child_user.profile_pic_url

        children_list.append({
            'id': child.id,
            'name': child.name,
            'pairing_code': child.pairing_code,
            'last_latitude': child.last_latitude,
            'last_longitude': child.last_longitude,
            'last_seen': child.last_seen.isoformat() if child.last_seen else None,
            'profile_pic': pic
        })
    return jsonify(children=children_list)

@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'username' not in session: return redirect(url_for('home'))
    
    user = User.query.filter_by(username=session['username']).first()
    file = request.files.get('profile_pic')
    
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        # Unique name
        new_filename = f"u{user.id}_{int(datetime.datetime.now().timestamp())}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
        
        user.profile_pic_url = url_for('static', filename='uploads/' + new_filename)
        db.session.commit()
        
    # Redirect back to correct dashboard
    if user.is_parent:
        return redirect(url_for('parent_dashboard'))
    else:
        return redirect(url_for('child_dashboard'))

# ✅ UPDATED Geofence Route
@app.route('/geofence')
@is_parent
def geofence_page():
    user = g.user
    # Sahi HTML page render kar rahe hain
    return render_template('geofence.html', username=user.username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=10000)
