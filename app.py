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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key_deepak_darbhanga')
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=31)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# --- 2. DATABASE MODELS ---

class User(db.Model):
    __tablename__ = 'app_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
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
    
    parent_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    child_user_id = db.Column(db.Integer, db.ForeignKey('app_users.id'), nullable=True)
    
    child_user = db.relationship('User', foreign_keys=[child_user_id])
    
    last_seen = db.Column(db.DateTime, nullable=True)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)

    # SOS Feature (Active)
    is_sos = db.Column(db.Boolean, default=False)

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
            g.user = User.query.filter_by(username=session['username']).first()
            if g.user and g.user.is_parent:
                return f(*args, **kwargs)
        return "Access Denied", 403
    return wrapper

def generate_pairing_code():
    return secrets.token_hex(3).upper()

# --- 4. ROUTES ---

@app.route('/')
def home():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            return redirect(url_for('parent_dashboard')) if user.is_parent else redirect(url_for('child_dashboard'))
    # 🔥 CHANGE: Ab sidha Login Page khulega (Extra home page hata diya)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Auto-create tables if missing
    db.create_all()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        is_parent = (role == 'parent')
        phone_number = request.form.get('phone_number')
        
        if User.query.filter_by(username=username).first():
            return "Username already exists!"
            
        new_user = User(username=username, is_parent=is_parent, phone_number=phone_number)
        new_user.set_password(password)
        new_user.profile_pic_url = url_for('static', filename='default-profile.png')
        
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db.create_all()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            session.permanent = True
            return redirect(url_for('parent_dashboard')) if user.is_parent else redirect(url_for('child_dashboard'))
        else:
            return "Invalid credentials."
    return render_template('login.html')

@app.route('/parent')
@is_parent
def parent_dashboard():
    user = g.user
    return render_template('parent_dashboard.html', 
                           username=user.username, 
                           children=user.children, 
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
    if 'username' not in session: return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user: return redirect(url_for('logout'))
    
    child_entry = Child.query.filter_by(child_user_id=user.id).first()
    parent_data = User.query.get(child_entry.parent_id) if child_entry else None
        
    return render_template('child_dashboard.html', 
                           username=user.username, 
                           parent=parent_data, 
                           child_info=child_entry, 
                           profile_pic_url=user.profile_pic_url)

@app.route('/pair_device', methods=['POST'])
def pair_device():
    if 'username' not in session: return redirect(url_for('login'))
    code = request.form['pairing_code']
    child_user = User.query.filter_by(username=session['username']).first()
    child_obj = Child.query.filter_by(pairing_code=code).first()
    
    if child_obj:
        child_obj.child_user_id = child_user.id
        db.session.commit()
        return redirect(url_for('child_dashboard'))
    return "Invalid Pairing Code"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/api/update_location', methods=['POST'])
def update_location():
    if 'username' not in session: return jsonify(status='error')
    user = User.query.filter_by(username=session['username']).first()
    
    if user and not user.is_parent:
        child_entry = Child.query.filter_by(child_user_id=user.id).first()
        if child_entry:
            data = request.get_json()
            child_entry.last_latitude = data.get('latitude')
            child_entry.last_longitude = data.get('longitude')
            # SOS Save Logic
            child_entry.is_sos = data.get('is_sos', False)
            child_entry.last_seen = datetime.datetime.utcnow()
            db.session.commit()
            return jsonify(status='success')
    return jsonify(status='error')

@app.route('/api/get_children_data')
def get_children_data():
    if 'username' not in session: return jsonify(children=[])
    user = User.query.filter_by(username=session['username']).first()
    
    if not user or not user.is_parent: return jsonify(children=[])
    
    data = []
    for c in user.children:
        c_user = User.query.get(c.child_user_id)
        pic = c_user.profile_pic_url if (c_user and c_user.profile_pic_url) else url_for('static', filename='default-profile.png')
        
        data.append({
            'id': c.id,
            'name': c.name,
            'pairing_code': c.pairing_code,
            'last_latitude': c.last_latitude,
            'last_longitude': c.last_longitude,
            'last_seen': c.last_seen.isoformat() if c.last_seen else None,
            'profile_pic': pic,
            'is_sos': c.is_sos # SOS status send kar raha hai
        })
    return jsonify(children=data)

@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'username' not in session: return redirect(url_for('home'))
    user = User.query.filter_by(username=session['username']).first()
    file = request.files.get('profile_pic')
    
    if file and file.filename != '':
        fname = secure_filename(file.filename)
        new_name = f"u{user.id}_{int(datetime.datetime.now().timestamp())}_{fname}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_name))
        user.profile_pic_url = url_for('static', filename='uploads/' + new_name)
        db.session.commit()
        
    return redirect(url_for('parent_dashboard')) if user.is_parent else redirect(url_for('child_dashboard'))

@app.route('/geofence')
@is_parent
def geofence_page():
    return render_template('geofence.html', username=g.user.username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=10000)

