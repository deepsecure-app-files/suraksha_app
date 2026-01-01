import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'suraksha_key_secret_123'

# --- DATABASE CONFIGURATION ---
# Render par internal URL use karein, local par sqlite
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///suraksha.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- PHOTO UPLOAD SETTINGS ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    __tablename__ = 'app_users'  # Table name fixed
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False) # 'parent' or 'child'
    
    # NEW: Photo save karne ke liye column
    profile_pic_url = db.Column(db.String(500), nullable=True)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    pairing_code = db.Column(db.String(10), unique=True, nullable=False)
    
    # Connection to Parent
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    
    # Connection to Child User Account (Jo login karega)
    child_user_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    
    # Tracking Data
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    parent = db.relationship('User', foreign_keys=[parent_id], backref='children_added')
    child_user = db.relationship('User', foreign_keys=[child_user_id], backref='child_profile')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

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
            flash('Login failed. Check username and password.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role') # 'parent' ya 'child'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
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
        # Photo URL pass kar rahe hain template ko
        return render_template('parent_dashboard.html', 
                               username=current_user.username,
                               user_profile_pic=current_user.profile_pic_url,
                               children=children)
    else:
        # Child Dashboard Logic
        child_profile = Child.query.filter_by(child_user_id=current_user.id).first()
        return render_template('child_dashboard.html', 
                               username=current_user.username,
                               user_profile_pic=current_user.profile_pic_url,
                               child_info=child_profile)

# --- NEW: PROFILE PIC UPLOAD ROUTE ---
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
        # Unique name: user_123_photo.jpg
        new_filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(file_path)
        
        # Save link to DB
        current_user.profile_pic_url = url_for('static', filename='uploads/' + new_filename)
        db.session.commit()
        
        return redirect(url_for('dashboard'))

# --- PARENT FEATURES ---
@app.route('/add_child', methods=['POST'])
@login_required
def add_child():
    if current_user.role != 'parent':
        return "Unauthorized", 403
    
    name = request.form.get('child_name')
    # Generate unique code (Last 6 chars of timestamp)
    code = str(int(datetime.utcnow().timestamp()))[-6:]
    
    new_child = Child(name=name, pairing_code=code, parent_id=current_user.id)
    db.session.add(new_child)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/api/get_children_data')
@login_required
def get_children_data():
    if current_user.role != 'parent':
        return jsonify({})
    
    children = Child.query.filter_by(parent_id=current_user.id).all()
    data = []
    for child in children:
        # Check photo
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
            'profile_pic': pic
        })
    return jsonify({'children': data})

# --- CHILD FEATURES ---
@app.route('/pair_device', methods=['POST'])
@login_required
def pair_device():
    code = request.form.get('pairing_code')
    child_entry = Child.query.filter_by(pairing_code=code).first()
    
    if child_entry:
        child_entry.child_user_id = current_user.id
        db.session.commit()
        flash('Device Paired Successfully!')
    else:
        flash('Invalid Code')
        
    return redirect(url_for('dashboard'))

@app.route('/api/update_location', methods=['POST'])
def update_location():
    data = request.json
    print("Location Data Received:", data) # Debugging ke liye
    
    if not current_user.is_authenticated:
        return jsonify({'status': 'error', 'message': 'Login required'}), 401

    child_entry = Child.query.filter_by(child_user_id=current_user.id).first()
    if child_entry:
        child_entry.last_latitude = data.get('latitude')
        child_entry.last_longitude = data.get('longitude')
        child_entry.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify({'status': 'success'})
    
    return jsonify({'status': 'error', 'message': 'Device not paired'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- DB FIX ROUTE (One Time Use) ---
@app.route('/fix_db_now')
def fix_db_now():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return "Database Reset Successful! Purana data delete ho gaya. Naya account banayein."

# --- ZONE/GEOFENCE PAGE (Placeholder) ---
@app.route('/geofence')
@login_required
def geofence_page():
    return render_template('parent_dashboard.html', username=current_user.username) # Temporary

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=10000)
