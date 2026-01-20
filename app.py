from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import uuid
import secrets
from datetime import datetime, timedelta
import json
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_share.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

db = SQLAlchemy(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)
    file_password = db.Column(db.String(255), nullable=False)
    secure_link = db.Column(db.String(255), unique=True, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    download_count = db.Column(db.Integer, default=0)
    max_downloads = db.Column(db.Integer, default=10)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str) -> tuple:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + encrypted_data)
    
    return encrypted_file_path, key.decode()

def decrypt_file(encrypted_file_path: str, password: str) -> bytes:
    with open(encrypted_file_path, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()
    
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('signup.html')
        
        password_hash = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).order_by(File.upload_date.desc()).all()
    return render_template('dashboard.html', user=user, files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    file_password = request.form.get('file_password', '')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file_password == '':
        return jsonify({'error': 'File password is required'}), 400
    
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    file.save(file_path)
    
    encrypted_file_path, encryption_key = encrypt_file(file_path, file_password)
    
    secure_link = secrets.token_urlsafe(16)
    
    new_file = File(
        filename=unique_filename,
        original_filename=filename,
        file_path=encrypted_file_path,
        file_size=os.path.getsize(encrypted_file_path),
        encryption_key=encryption_key,
        file_password=generate_password_hash(file_password),
        secure_link=secure_link,
        expiry_date=datetime.utcnow() + timedelta(days=7),
        user_id=session['user_id']
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    os.remove(file_path)
    
    return jsonify({
        'success': True,
        'secure_link': f"{request.host_url}download/{secure_link}",
        'file_id': new_file.id
    })

@app.route('/download/<secure_link>', methods=['GET', 'POST'])
def download_file(secure_link):
    file_record = File.query.filter_by(secure_link=secure_link).first()
    
    if not file_record:
        flash('File not found or link expired', 'error')
        return render_template('download.html', error=True)
    
    if file_record.expiry_date and file_record.expiry_date < datetime.utcnow():
        flash('File link has expired', 'error')
        return render_template('download.html', error=True)
    
    if file_record.download_count >= file_record.max_downloads:
        flash('Download limit exceeded', 'error')
        return render_template('download.html', error=True)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if not check_password_hash(file_record.file_password, password):
            flash('Incorrect password', 'error')
            return render_template('download.html', secure_link=secure_link)
        
        decrypted_data = decrypt_file(file_record.file_path, password)
        
        if decrypted_data is None:
            flash('Failed to decrypt file', 'error')
            return render_template('download.html', secure_link=secure_link)
        
        file_record.download_count += 1
        db.session.commit()
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file_record.original_filename,
            mimetype='application/octet-stream'
        )
    
    return render_template('download.html', secure_link=secure_link, filename=file_record.original_filename)

@app.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first()
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    try:
        if os.path.exists(file_record.file_path):
            os.remove(file_record.file_path)
        
        db.session.delete(file_record)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': 'Failed to delete file'}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    from datetime import datetime
    return render_template('profile.html', user=user, now=datetime.utcnow())

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
