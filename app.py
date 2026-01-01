import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import math # Zone calculation ke liye

app = Flask(__name__)
app.config['SECRET_KEY'] = 'suraksha_key_secret_123'

# --- 1. DATABASE CONFIGURATION ---
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///suraksha.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- 2. PHOTO UPLOAD CONFIG ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- 3. MODELS (Tables) ---
class User(UserMixin, db.Model):
    __tablename__ = 'app_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    
    # NEW: Photo URL Column
    profile_pic_url = db.Column(db.String(500), nullable=True)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    pairing_code = db.Column(db.String(10), unique=True, nullable=False)
    
    # Rishtey (Relationships)
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    child_user_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    
    # Location Data
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Zone Settings (Ye Logic Wapas Aa Gayi Hai)
    safe_zone_lat = db.Column(db.Float, nullable=True)
    safe_zone_lng = db.Column(db.Float, nullable=True)
    safe_zone_radius = db.Column(db.Integer, default=500) # Meters mein

    parent = db.relationship('User', foreign_keys=[parent_id], backref='children_added')
    child_user = db.relationship('User', foreign_keys=[child_user_id], backref='child_profile')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 4. HELPER FUNCTIONS ---
# Do points ke beech ki doori nikalne ka formula (Haversine)
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371000 # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    
    a = math.sin(delta_phi / 2.0) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2.0) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c # Distance in meters

# --- 5. ROUTES ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check details.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if User.query.filter_by(username=username).first():
            flash('Username exists.')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'parent':
        children = Child.query.filter_by(parent_id=current_user.id).all()
        return render_template('parent_dashboard.html', 
                               username=current_user.username,
                               user_profile_pic=current_user.profile_pic_url,
                               children=children)
    else:
        child_profile = Child.query.filter_by(child_user_id=current_user.id).first()
        return render_template('child_dashboard.html', 
                               username=current_user.username,
                               user_profile_pic=current_user.profile_pic_url,
                               child_info=child_profile)

# --- NEW: PROFILE PIC UPLOAD ---
@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        return redirect(url_for('dashboard'))
    file = request.files['profile_pic']
    if file.filename == '':
        return redirect(url_for('dashboard'))
    if file:
        filename = secure_filename(file.filename)
        # Timestamp lagaya taki naam unique rahe
        new_filename = f"u{current_user.id}_{int(datetime.now().timestamp())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(file_path)
        
        current_user.profile_pic_url = url_for('static', filename='uploads/' + new_filename)
        db.session.commit()
        return redirect(url_for('dashboard'))

# --- PARENT FEATURES ---
@app.route('/add_child', methods=['POST'])
@login_required
def add_child():
    if current_user.role != 'parent': return "No", 403
    name = request.form.get('child_name')
    code = str(int(datetime.utcnow().timestamp()))[-6:]
    new_child = Child(name=name, pairing_code=code, parent_id=current_user.id)
    db.session.add(new_child)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/api/get_children_data')
@login_required
def get_children_data():
    if current_user.role != 'parent': return jsonify({})
    children = Child.query.filter_by(parent_id=current_user.id).all()
    data = []
    for child in children:
        # Distance calculation logic (Zone Check)
        status = "Safe"
        distance = 0
        if child.last_latitude and child.safe_zone_lat:
            dist = calculate_distance(child.last_latitude, child.last_longitude, 
                                      child.safe_zone_lat, child.safe_zone_lng)
            distance = round(dist, 2)
            if dist > (child.safe_zone_radius or 500):
                status = "Alert: Out of Zone!"
        
        pic = None
        if child.child_user:
            pic = child.child_user.profile_pic_url
            
        data.append({
            'id': child.id,
            'name': child.name,
            'pairing_code': child.pairing_code,
            'last_latitude': child.last_latitude,
            'last_longitude': child.last_longitude,
            'last_seen': child.last_seen.isoformat() if child.last_seen else None,
            'profile_pic': pic,
            'zone_status': status,
            'distance_from_home': distance
        })
    return jsonify({'children': data})

# --- GEFENCE SETTING (Zone Set Karna) ---
@app.route('/set_geofence', methods=['POST'])
@login_required
def set_geofence():
    child_id = request.form.get('child_id')
    lat = request.form.get('latitude')
    lng = request.form.get('longitude')
    radius = request.form.get('radius')
    
    child = Child.query.get(child_id)
    if child and child.parent_id == current_user.id:
        child.safe_zone_lat = float(lat)
        child.safe_zone_lng = float(lng)
        child.safe_zone_radius = int(radius)
        db.session.commit()
        flash('Safe Zone Updated!')
    return redirect(url_for('geofence_page'))

@app.route('/geofence')
@login_required
def geofence_page():
    if current_user.role != 'parent': return redirect(url_for('dashboard'))
    children = Child.query.filter_by(parent_id=current_user.id).all()
    return render_template('geofence.html', children=children) # Iske liye alag HTML chahiye hoga baad me

# --- CHILD FEATURES ---
@app.route('/pair_device', methods=['POST'])
@login_required
def pair_device():
    code = request.form.get('pairing_code')
    child_entry = Child.query.filter_by(pairing_code=code).first()
    if child_entry:
        child_entry.child_user_id = current_user.id
        db.session.commit()
        flash('Connected!')
    else:
        flash('Invalid Code')
    return redirect(url_for('dashboard'))

@app.route('/api/update_location', methods=['POST'])
def update_location():
    data = request.json
    if not current_user.is_authenticated:
        return jsonify({'status': 'error'}), 401
    
    child_entry = Child.query.filter_by(child_user_id=current_user.id).first()
    if child_entry:
        child_entry.last_latitude = data.get('latitude')
        child_entry.last_longitude = data.get('longitude')
        child_entry.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Not paired'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- DB FIX (IMPORTANT) ---
@app.route('/fix_db_now')
def fix_db_now():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return "Database RESET Complete. Create new account."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=10000)
