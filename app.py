import os
import jwt
import random
import uuid
import numpy as np
from datetime import datetime, timezone, timedelta
import mysql.connector
from flask import Flask, request, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app, send_from_directory
from functools import wraps
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import pytesseract
import cv2
import re
import difflib
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# 🔴 IMPORTANT: Replace with your deployed URL
BASE_URL = "https://180.235.121.253:8115.onrender.com"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

from flask import send_from_directory
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Database Configuration ---
# Update these values or set environment variables according to your local MySQL setup.
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '') # Empty string is default for some XAMPP/WAMP setups
DB_NAME = os.environ.get('DB_NAME', 'scanmypills')

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

def init_db():
    try:
        # Connect to MySQL server without a database selected first to create it if needed
        server_conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = server_conn.cursor()
        
        # Read and execute setup_db.sql
        if os.path.exists('setup_db.sql'):
            with open('setup_db.sql', 'r') as f:
                sql_script = f.read()
            
            # Split by ';' and execute each statement individually
            sql_statements = sql_script.split(';')
            
            for statement in sql_statements:
                statement = statement.strip()
                if statement:
                    cursor.execute(statement)
                    
        server_conn.commit()
        cursor.close()
        server_conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize Database on Startup
init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(user_id, *args, **kwargs)

    return decorated

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

def send_otp_email(email, otp):
    msg = Message(
        subject="Password Reset OTP - ScanMyPills",
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[email]
    )

    msg.body = f"""
Hello,

Your password reset OTP is: {otp}

This OTP will expire in 5 minutes.

If you did not request this, please ignore this email.

Regards,
ScanMyPills Team
"""

    mail.send(msg)

# --- Authentication Routes ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not 'name' in data or not 'email' in data or not 'password' in data:
        return jsonify({'error': 'Missing required fields: name, email, password'}), 400
    
    name = data['name']
    email = data['email']
    password = data['password']
    hashed_password = generate_password_hash(password)
    
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'Database unavailable'}), 500
    
    try:
        cursor = conn.cursor()
        # MySQL uses %s for parameterized queries instead of ?
        cursor.execute("INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
                       (name, email, hashed_password))
        conn.commit()
        user_id = cursor.lastrowid
        return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields: email, password'}), 400

    email = data['email']
    password = data['password']

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database unavailable'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, email, password_hash FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Create real JWT token
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }

    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    # PyJWT sometimes returns bytes → convert to string
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email']
        }
    }), 200
       
@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT otp_created_at
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    # ✅ Cooldown check (60 seconds)
    if user['otp_created_at']:
        last_otp_time = user['otp_created_at'].replace(tzinfo=timezone.utc)

        seconds_since_last_otp = (now - last_otp_time).total_seconds()

        if seconds_since_last_otp < 60:
            cursor.close()
            conn.close()
            return jsonify({
                'error': 'Please wait before requesting another OTP',
                'seconds_remaining': int(60 - seconds_since_last_otp)
            }), 429

    # ✅ Generate OTP
    import random
    otp = str(random.randint(100000, 999999))

    expires_at = now + timedelta(minutes=5)

    # Store as naive UTC for MySQL DATETIME
    created_at_db = now.replace(tzinfo=None)
    expires_at_db = expires_at.replace(tzinfo=None)

    # ✅ Update database
    cursor.execute("""
        UPDATE users
        SET reset_otp = %s,
            otp_created_at = %s,
            otp_expires_at = %s,
            otp_verified = FALSE
        WHERE email = %s
    """, (otp, created_at_db, expires_at_db, email))

    conn.commit()

    cursor.close()
    conn.close()

    # ✅ Send email using reusable function
    try:
        send_otp_email(email, otp)
    except Exception as e:
        return jsonify({
            "error": "Failed to send OTP email",
            "details": str(e)
        }), 500

    return jsonify({'message': 'OTP sent successfully'}), 200

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'error': 'Email and OTP required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT reset_otp, otp_expires_at
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    if not user['reset_otp']:
        cursor.close()
        conn.close()
        return jsonify({'error': 'No OTP requested'}), 400

    if user['reset_otp'] != otp:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Invalid OTP'}), 400

    # ✅ FIXED DATETIME COMPARISON
    now = datetime.now(timezone.utc)

    otp_expires_at = user['otp_expires_at']
    otp_expires_at = otp_expires_at.replace(tzinfo=timezone.utc)

    if now > otp_expires_at:
        cursor.close()
        conn.close()
        return jsonify({'error': 'OTP expired'}), 400

    # Mark OTP as verified
    cursor.execute("""
        UPDATE users
        SET otp_verified = TRUE
        WHERE email = %s
    """, (email,))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'message': 'OTP verified successfully'}), 200

@app.route('/api/auth/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT otp_created_at
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # ⛔ Prevent spam resend (60 seconds restriction)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    if user['otp_created_at']:
        last_otp_time = user['otp_created_at'].replace(tzinfo=timezone.utc)

        if (now - last_otp_time).total_seconds() < 60:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Please wait before requesting new OTP'}), 429

    # ✅ Generate new OTP
    import random
    new_otp = str(random.randint(100000, 999999))

    expires_at = now + timedelta(minutes=5)

    # ✅ Update database
    cursor.execute("""
        UPDATE users
        SET reset_otp = %s,
            otp_created_at = %s,
            otp_expires_at = %s,
            otp_verified = FALSE
        WHERE email = %s
    """, (new_otp, now, expires_at, email))

    conn.commit()

    # ✅ Send email again
    send_otp_email(email, new_otp)

    cursor.close()
    conn.close()

    return jsonify({'message': 'OTP resent successfully'}), 200

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    if not email or not new_password:
        return jsonify({'error': 'Email and new password required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check if user exists and OTP was verified
    cursor.execute("""
        SELECT otp_verified
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    if not user['otp_verified']:
        cursor.close()
        conn.close()
        return jsonify({'error': 'OTP not verified'}), 403

    # Hash new password
    hashed_password = generate_password_hash(new_password)

    # Update password and clear OTP fields
    cursor.execute("""
        UPDATE users
        SET password_hash = %s,
            reset_otp = NULL,
            otp_expires_at = NULL,
            otp_created_at = NULL,
            otp_verified = FALSE
        WHERE email = %s
    """, (hashed_password, email))

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'message': 'Password reset successfully'}), 200

# --- User Profile Routes ---

@app.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user_profile(current_user_id, user_id):
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized access to profile'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database unavailable'}), 500

    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, name, email, phone, profile_photo, created_at
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(user), 200

@app.route('/api/user/<int:user_id>', methods=['PUT'])
@token_required
def update_user_profile(current_user_id, user_id):
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized access to profile'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database unavailable'}), 500

    cursor = conn.cursor(dictionary=True)

    # Check if user exists
    cursor.execute("SELECT id, profile_photo FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    name = request.form.get('name')
    phone = request.form.get('phone')
    photo = request.files.get('profile_photo')

    # Validate name
    if not name:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Name is required'}), 400

    profile_photo_path = user['profile_photo']

    # Handle photo upload
    if photo:
        if not allowed_file(photo.filename):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid file type'}), 400

        filename = secure_filename(photo.filename)

        # Prevent filename collision
        import uuid
        unique_filename = str(uuid.uuid4()) + "_" + filename

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        photo.save(file_path)

        profile_photo_path = unique_filename

    # Update database
    cursor.execute("""
        UPDATE users
        SET name = %s,
            phone = %s,
            profile_photo = %s
        WHERE id = %s
    """, (name, phone, profile_photo_path, user_id))

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'message': 'Profile updated successfully'}), 200

@app.route('/api/upload-photo', methods=['POST'])
def upload_photo():

    if 'photo' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['photo']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):

        # 🔴 ENSURE DIRECTORY EXISTS HERE
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(file_path)

        return jsonify({
            "message": "File uploaded successfully",
            "filename": filename,
            "url": filename
        }), 200

    return jsonify({"error": "Invalid file type"}), 400

@app.route('/api/user/change-password', methods=['PUT'])
@token_required
def change_password(user_id):
    data = request.get_json()

    current_password = data.get("current_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match"}), 400

    connection = get_db_connection()
    if not connection:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = connection.cursor(dictionary=True)

    # IMPORTANT: use correct column name
    cursor.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        connection.close()
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user["password_hash"], current_password):
        cursor.close()
        connection.close()
        return jsonify({"error": "Current password is incorrect"}), 400

    new_hashed_password = generate_password_hash(new_password)

    cursor.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (new_hashed_password, user_id)
    )

    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({"message": "Password updated successfully"}), 200

@app.route('/api/delete-account', methods=['DELETE'])
@token_required
def delete_account(user_id):
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database unavailable"}), 500
            
        cursor = connection.cursor()

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            connection.close()
            return jsonify({"error": "User find error"}), 404

        # Delete user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({"message": "User deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Medicines Routes ---
#---------------------------------#

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ---------------- IMAGE PREPROCESS ----------------
def preprocess_image(image_path):
    img = cv2.imread(image_path)
    if img is None: return None
    
    # 1. Resize for better OCR
    height, width = img.shape[:2]
    scaling_factor = 2 if width < 1500 else 1
    if scaling_factor > 1:
        img = cv2.resize(img, (width * scaling_factor, height * scaling_factor), interpolation=cv2.INTER_CUBIC)
    
    # 2. Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # 3. Increase Contrast (CLAHE is excellent for medical/box labels)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    contrast = clahe.apply(gray)
    
    # 4. Sharpening
    kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
    sharpened = cv2.filter2D(contrast, -1, kernel)
    
    # 5. Denoise (Bilateral filtering keeps edges sharp)
    denoised = cv2.bilateralFilter(sharpened, 9, 75, 75)
    
    # 6. Thresholding (Using a combination or adaptive)
    # Using Otsu + Binary
    _, thresh = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    return thresh

def extract_text(image_path):
    processed = preprocess_image(image_path)
    # Using psm 3 (Auto page segmentation with OSD) or 6 (Assume a single uniform block of text)
    # For medicine packs, psm 3 or 11 (Sparse text) is often better.
    config = '--psm 3 --oem 3'
    text = pytesseract.image_to_string(processed, lang="eng", config=config)
    return text

def extract_name_from_image(image_path):
    processed = preprocess_image(image_path)
    if processed is None: return None
    
    try:
        data = pytesseract.image_to_data(processed, output_type=pytesseract.Output.DICT)
    except Exception:
        return None
        
    keywords = ['EXP', 'MFD', 'BATCH', 'MRP', 'NO', 'TABLET', 'CAPSULE', 'BY', 'FOR', 'MG', 'ML', 'RS', 'DATE', 'PRICE', 'PRESCRIPTION', 'SCHEDULE']
    
    # Group words by line to handle names like "S-Numlo-5" which might be split
    lines = {} # (line_id) -> [words]
    for i in range(len(data['text'])):
        text = data['text'][i].strip()
        if not text: continue
        
        line_key = f"{data['page_num'][i]}_{data['block_num'][i]}_{data['line_num'][i]}"
        if line_key not in lines:
            lines[line_key] = []
        lines[line_key].append({
            'text': text,
            'height': data['height'][i],
            'top': data['top'][i]
        })

    candidate_names = {} # text -> {score, count}
    
    for line_key, words in lines.items():
        # Clean words and join them
        row_text = ""
        max_h = 0
        valid_words = []
        
        for w in words:
            word_clean = w['text'].strip().upper()
            # Ignore noise and headers
            if any(kw == word_clean for kw in keywords): continue
            if not any(c.isalpha() for c in word_clean): continue
            
            valid_words.append(word_clean)
            if w['height'] > max_h: max_h = w['height']
            
        if not valid_words: continue
        
        # Try joining words in the line. S-Numlo-5 might stay separate or be joined.
        # We'll consider both the full line and individual large words.
        row_text = " ".join(valid_words)
        # Remove trailing hyphens or symbols
        row_text = re.sub(r'[^A-Z0-9\-\s]', '', row_text).strip()
        
        if len(row_text) < 3: continue
        
        # Scoring row_text
        if row_text not in candidate_names:
            candidate_names[row_text] = {'score': max_h, 'count': 0}
        
        candidate_names[row_text]['count'] += 1
        if max_h > candidate_names[row_text]['score']:
            candidate_names[row_text]['score'] = max_h

    if not candidate_names: return None
    
    # Calculate final scores
    best_name = None
    max_final_score = 0
    
    for name, stats in candidate_names.items():
        # Frequency bonus: 1.5x for 2+, 2x for 4+
        # Names on medicinal strips repeat!
        bonus = 1.0
        if stats['count'] >= 2: bonus = 1.5
        if stats['count'] >= 4: bonus = 3.0 # Strong indicator
        
        final_score = stats['score'] * bonus
        if final_score > max_final_score:
            max_final_score = final_score
            best_name = name
            
    return best_name.title() if best_name else None

# --- Improved Filtering for Medicine Names ---
NOISE_KEYWORDS = [
    'STORE', 'COOL', 'DRY', 'REACH', 'CHILDREN', 'PLACE', 'DIRECT', 'SUNLIGHT',
    'MOISTURE', 'PHYSICIAN', 'DIRECTION', 'DOSAGE', 'WARNING', 'CAUTION',
    'SCHEDULE', 'PRESCRIPTION', 'PHARMACIST', 'KEEP', 'OUT', 'OF', 'THE',
    'ROOM', 'TEMPERATURE', 'EXCEED', 'NOT', 'FOR', 'USE', 'EXTERNAL', 'INTERNAL',
    'PROTECT', 'FROM', 'LIGHT', 'HEAT', 'MEDICINE', 'DRUG', 'TABLETS', 'CAPSULES',
    'PHARMACEUTICALS', 'COMPOSITION', 'EACH', 'FILM', 'COATED', 'CONTAINS',
    'MFG', 'MFD', 'BY', 'MARKETED', 'MKTD', 'MANUFACTURED', 'LIMITED', 'LTD', 'PVT',
    'EXP', 'EXPIRY', 'BATCH', 'LOT', 'MRP', 'DATE', 'PRICE'
]

def clean_text(text):
    text = text.upper()
    text = re.sub(r'\s+', ' ', text)
    return text

def extract_expiry(text):
    # Support exhaustive formats
    # 12/2026, 12-2026, 12/26, MAY 2026, 05.2027, etc.
    patterns = [
        # Keywords with alphanumeric month (e.g. EXP JUN 2026)
        r'(?:EXP|EXPIRY|ED|E\s*X\s*P|BEST|VALID)[\.\s:;-]*([A-Z0-9]{3,9})[\.\s/-]*([0-9OISLBS]{2,4})',
        # Keywords with numeric month (e.g. EXP 12/2026)
        r'(?:EXP|EXPIRY|ED|E\s*X\s*P|BEST|VALID)[\.\s:;-]*([0-9OISLBS]{1,2})[\.\s/-]+([0-9OISLBS]{2,4})',
        # Numeric month with separators (e.g. 12/2026)
        r'\b([0-9OISLBS]{1,2})[\.\s/-]+([0-9OISLBS]{2,4})\b',
        # Alphanumeric month with separators (e.g. JUN/2026)
        r'\b([A-Z0-9]{3,9})[\.\s/-]+([0-9OISLBS]{2,4})\b',
    ]
    
    month_map = {
        "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
        "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
        "SEPT": 9, "JANUARY": 1, "FEBRUARY": 2, "MARCH": 3, "APRIL": 4,
        "JUNE": 6, "JULY": 7, "AUGUST": 8, "OCTOBER": 10, "NOVEMBER": 11, "DECEMBER": 12
    }

    text = text.upper()
    
    # We'll try each pattern
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            try:
                g1 = match.group(1).strip()
                g2 = match.group(2).strip()
                
                # Normalize numeric strings (OCR often swaps 0/O, 1/I/L)
                def normalize_num(s):
                    return s.replace('O', '0').replace('I', '1').replace('L', '1').replace('|', '1').replace('S', '5').replace('B', '8')

                month = 0
                if any(c.isalpha() for c in g1):
                    # It's a month name? 
                    # Clean it first: remove common OCR noise at end of month name like JUL. or JUNE-
                    clean_month = re.sub(r'[^A-Z]', '', g1)
                    month = month_map.get(clean_month[:3], 0)
                    if month == 0:
                        # Try fuzzy or common variants
                        if 'JU1' in clean_month: month = 7
                        elif 'MA1' in clean_month: month = 5
                else:
                    month_str = normalize_num(g1)
                    month = int(month_str)
                
                if not (1 <= month <= 12): continue
                
                year_str = normalize_num(g2)
                year = int(year_str)
                if year < 100:
                    year += 2000
                
                # Sanity check: expiry shouldn't be too far in past or insane future
                if 2015 < year < 2050:
                    return f"{year}-{month:02d}-01"
            except: continue
    return None

def extract_batch(text):
    # Support more keywords
    match = re.search(r'(?:B[\.\s]*NO|BATCH|LOT|B\.N|BN|B\)N|B\)NO)[\.\s:;]*([A-Z0-9/-]+)', text, re.I)
    return match.group(1).strip() if match else None

def extract_mrp(text):
    match = re.search(r'(?:MRP|RS|PRICE)[\.\s:;]*(\d+\.?\d*)', text, re.I)
    return float(match.group(1)) if match else None

def extract_name(text):
    lines = text.split('\n')
    
    scored_names = []
    for line in lines:
        line = line.strip()
        if len(line) < 3: continue
        
        upper_line = line.upper()
        # Filter out lines that contain any noise keywords
        noise_words = ['EXP', 'EXPIRY', 'MFG', 'MFD', 'BATCH', 'LOT', 'MRP', 'PRICE', 'LTD', 'LIMITED', 'PVT', 'PHARMACEUTICALS', 'MANUFACTURED', 'MARKETED', 'COMPOSITION', 'CONTAINS', 'EACH', 'DOSAGE', 'WARNING', 'SCHEDULE', 'STORAGE', 'STORE']
        if any(kw in upper_line for kw in noise_words): continue
        
        # Check if it contains letters
        if not any(c.isalpha() for c in line): continue
        
        upper_chars = sum(1 for c in line if c.isupper())
        # Lenient candidate selection: starts with Alpha and has at least one uppercase
        if line[0].isalpha() and upper_chars >= 1:
            score = len(line)
            # Penalize very long lines (likely descriptions)
            if len(line) > 25: score -= 20
            
            # Traits of brand/medicine names
            if any(c.isdigit() for c in line): score += 10 # Strengths like 40mg
            if '-' in line: score += 5 # PAN-D, S-Numlo
            if upper_chars / len(line) > 0.4: score += 10 # Favor uppercase
            
            # Dosage forms are common in generic names but not brand names
            # We penalize them slightly to favor the brand if both are present
            if any(kw in upper_line for kw in ['TABLET', 'CAPSULE', 'SYRUP', 'INJECTION']):
                score -= 5
                
            scored_names.append((score, line))
    
    if scored_names:
        scored_names.sort(key=lambda x: x[0], reverse=True)
        return scored_names[0][1]
            
    # Fallback to general regex
    match = re.search(r'\b([A-Z]{3,}[A-Z0-9\-\s]{0,15})\b', text)
    return match.group(1).strip() if match else "Unknown Medicine"

def extract_manufacturer(text):
    text = text.upper()
    # Handle common OCR issues for trademark/registered symbols
    text = text.replace('R®', ' ').replace('®', ' ').replace('™', ' ')
    
    # 1. Strict regex search for manufacturing keyword
    boundary_keywords = r'LTD|PVT|LIMITED|CORP|INC|PHARMA|PHAR|HEALTHCARE|INDUSTRIES|LABS|LABORATORIES|ORGANICS'
    mfd_pattern = r'(?:MKTD|MARKETED|MFD|MFG|MANUFACTURED|DISTRIBUTED)[\.\s]*BY[\.\s:;]*([\w\s\-\.\,\']{3,50})(?:\s(?:' + boundary_keywords + r'))?'
    
    match = re.search(mfd_pattern, text, re.I)
    if match:
        name = match.group(1).strip().split('\n')[0].strip()
        # Clean up name: remove anything after a comma (usually address)
        if ',' in name:
            name = name.split(',')[0].strip()
            
        # Clean up name: keep first 4 words if it's still too long
        words = name.split()
        if len(words) > 4:
            name = " ".join(words[:4])
        
        # Clean up trailing trademark junk
        name = re.sub(r'[\s]R$', '', name)
        name = name.rstrip('., ') # Strip trailing punctuation
        
        # If we found a boundary nearby, append it
        for bk in ['LTD', 'PVT LTD', 'LIMITED', 'INC', 'CORP', 'PHARMACEUTICALS', 'INDUSTRIES', 'LABS', 'LABORATORIES', 'ORGANICS']:
            if bk in text[match.start():match.start()+150]:
                if bk not in name:
                    name += " " + bk
                break
        
        if len(name) > 3: return name.title()

    # 2. Fallback: Search for lines containing specific industry keywords
    mfd_keywords = ['LABORATORIES', 'PHARMA', 'PHARMACEUTICALS', 'HEALTHCARE', 'BIOTECH', 'LIFE SCIENCES', 'INDUSTRIES', 'LABS']
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if any(kw in line for kw in mfd_keywords):
            # Limit to 5 words
            words = line.split()
            if len(words) > 5:
                for i, w in enumerate(words):
                    if any(kw in w for kw in mfd_keywords):
                        return " ".join(words[max(0, i-2):min(len(words), i+3)]).strip().title()
            return line.title()
                
    return "Unknown Manufacturer"

# ---------------- MAIN ROUTE ----------------
@app.route("/api/process-medicine", methods=["POST"])
def process_medicine():
    try:
        if 'front_image' not in request.files or 'back_image' not in request.files:
            return jsonify({"success": False, "message": "Both images required"}), 400

        front = request.files['front_image']
        back = request.files['back_image']

        import uuid
        unique_id = str(uuid.uuid4())[:8]
        front_filename = f"{unique_id}_{secure_filename(front.filename)}"
        back_filename = f"{unique_id}_{secure_filename(back.filename)}"
        
        medicine_upload_dir = os.path.join(UPLOAD_FOLDER, 'medicines')
        os.makedirs(medicine_upload_dir, exist_ok=True)
        
        front_path = os.path.join(medicine_upload_dir, front_filename)
        back_path = os.path.join(medicine_upload_dir, back_filename)
        
        front.save(front_path)
        back.save(back_path)

        front_text = extract_text(front_path)
        back_text = extract_text(back_path)

        combined = clean_text(front_text + " " + back_text)
        
        front_name = extract_name_from_image(front_path)
        back_name = extract_name_from_image(back_path)
        
        if front_name and back_name:
            final_name = front_name
        elif front_name:
            final_name = front_name
        elif back_name:
            final_name = back_name
        else:
            final_name = extract_name(combined)

        data = {
            "name": final_name,
            "manufacturer": extract_manufacturer(combined),
            "expiry_date": extract_expiry(combined),
            "batch_number": extract_batch(combined),
            "mrp": extract_mrp(combined),
            "front_image": f"medicines/{front_filename}",
            "back_image": f"medicines/{back_filename}"
        }

        return jsonify({"success": True, "data": data}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/medicines', methods=['POST'])
@token_required
def save_medicine(user_id):

    conn = None
    cursor = None

    try:
        # ✅ Get form data (NOT JSON)
        name = request.form.get("name")
        manufacturer = request.form.get("manufacturer")
        expiry_date = request.form.get("expiry_date")
        batch_number = request.form.get("batch_number")
        mrp = request.form.get("mrp")
        dosage = request.form.get("dosage")
        category = request.form.get("category")
        quantity = request.form.get("quantity")

        # ✅ Get image files
        front_file = request.files.get("front_image")
        back_file = request.files.get("back_image")
        main_file = request.files.get("main_image")

        if not name:
            return jsonify({"error": "Medicine name is required"}), 400

        # ✅ Function to save file safely
        def save_file(file):
            if file and allowed_file(file.filename):
                unique_name = str(uuid.uuid4()) + "_" + file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                file.save(filepath)

                # Return FULL URL (IMPORTANT)
                return f"{BASE_URL}/uploads/{unique_name}"
            return None

        # ✅ Save images
        front_image = save_file(front_file)
        back_image = save_file(back_file)
        main_image = save_file(main_file)

        # DB connection
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(dictionary=True)

        # 🔎 Check duplicate
        check_query = """
        SELECT id FROM medicines
        WHERE user_id = %s AND name = %s AND batch_number = %s
        LIMIT 1
        """
        cursor.execute(check_query, (user_id, name, batch_number))
        existing = cursor.fetchone()

        if existing:
            return jsonify({"error": "This medicine is already saved"}), 409

        # ✅ Insert data
        insert_query = """
        INSERT INTO medicines
        (user_id, name, manufacturer, expiry_date, batch_number, mrp,
        dosage, category, quantity, front_image, back_image, main_image)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """

        cursor.execute(insert_query, (
            user_id,
            name,
            manufacturer,
            expiry_date,
            batch_number,
            mrp,
            dosage,
            category,
            quantity,
            front_image,
            back_image,
            main_image
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Medicine saved successfully"
        }), 201

    except mysql.connector.Error as err:
        if conn:
            conn.rollback()
        return jsonify({
            "error": "Database error",
            "details": str(err)
        }), 500

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/medicines/<int:medicine_id>', methods=['GET'])
@token_required
def get_medicine_details(user_id, medicine_id):

    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(dictionary=True)

        # 1️⃣ Get medicine details
        medicine_query = """
        SELECT id, name, manufacturer, expiry_date, batch_number,
               mrp, dosage, category, quantity,
               front_image, back_image, main_image
        FROM medicines
        WHERE id = %s AND user_id = %s
        """

        cursor.execute(medicine_query, (medicine_id, user_id))
        medicine = cursor.fetchone()

        if not medicine:
            return jsonify({
                "error": "Medicine not found"
            }), 404


        # Format expiry date
        if medicine["expiry_date"]:
            medicine["expiry_date"] = medicine["expiry_date"].strftime("%Y-%m-%d")


        # Remove manual URL prefixing - handled by the app


        # 2️⃣ Get reminders for this medicine
        reminder_query = """
        SELECT id, reminder_time, dosage, is_active
        FROM reminders
        WHERE medicine_id = %s AND user_id = %s
        ORDER BY reminder_time
        """

        cursor.execute(reminder_query, (medicine_id, user_id))
        reminders = cursor.fetchall()


        # Format time properly safely
        for r in reminders:
            if r["reminder_time"]:
                # If it's a timedelta (TIME col), convert to HH:MM
                if hasattr(r["reminder_time"], "seconds"):
                    total_seconds = int(r["reminder_time"].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    r["reminder_time"] = f"{hours:02d}:{minutes:02d}"
                else:
                    # It's a string, keep it but ensure it's at least HH:MM
                    r["reminder_time"] = str(r["reminder_time"])[:5]


        return jsonify({
            "success": True,
            "medicine": medicine,
            "reminders": reminders
        }), 200


    except mysql.connector.Error as err:

        return jsonify({
            "error": "Database error",
            "details": str(err)
        }), 500

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/medicines/<int:medicine_id>', methods=['DELETE'])
@token_required
def delete_medicine_api(user_id, medicine_id):

    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(dictionary=True)

        # Check if medicine exists for this user
        check_query = """
        SELECT id FROM medicines
        WHERE id = %s AND user_id = %s
        LIMIT 1
        """

        cursor.execute(check_query, (medicine_id, user_id))
        existing = cursor.fetchone()

        if not existing:
            return jsonify({
                "error": "Medicine not found"
            }), 404

        # Delete medicine
        delete_query = """
        DELETE FROM medicines
        WHERE id = %s AND user_id = %s
        """

        cursor.execute(delete_query, (medicine_id, user_id))
        conn.commit()

        return jsonify({
            "success": True,
            "message": "Medicine deleted successfully",
            "medicine_id": medicine_id
        }), 200

    except mysql.connector.Error as err:

        if conn:
            conn.rollback()

        return jsonify({
            "error": "Database error",
            "details": str(err)
        }), 500

    except Exception as e:

        if conn:
            conn.rollback()

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/medicines/<int:medicine_id>', methods=['PUT'])
@token_required
def update_medicine(user_id, medicine_id):

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get existing medicine
        cursor.execute("""
        SELECT * FROM medicines
        WHERE id=%s AND user_id=%s
        """, (medicine_id, user_id))

        medicine = cursor.fetchone()

        if not medicine:
            return jsonify({"success": False, "error": "Medicine not found"}), 404

        # Get new values
        name = request.form.get('medicine_name') or medicine["name"]
        manufacturer = request.form.get('manufacturer') or medicine["manufacturer"]
        category = request.form.get('category') or medicine["category"]
        quantity = request.form.get('quantity') or medicine["quantity"]
        dosage = request.form.get('dosage') or medicine["dosage"]
        expiry_date = request.form.get('expiry_date') or medicine["expiry_date"]
        batch_number = request.form.get('batch_number') or medicine["batch_number"]

        main_image = request.files.get('main_image')
        front_image = request.files.get('front_image')
        back_image = request.files.get('back_image')

        main_path = medicine["main_image"]
        front_path = medicine["front_image"]
        back_path = medicine["back_image"]

        import os
        upload_folder = "uploads/medicines/"
        os.makedirs(upload_folder, exist_ok=True)

        # Update main image if uploaded
        if main_image:
            filename = secure_filename(f"main_{medicine_id}_{main_image.filename}")
            path = os.path.join(app.config['UPLOAD_FOLDER'], 'medicines', filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            main_image.save(path)
            main_path = f"medicines/{filename}"

        # Update front image if uploaded
        if front_image:
            filename = secure_filename(f"front_{medicine_id}_{front_image.filename}")
            path = os.path.join(app.config['UPLOAD_FOLDER'], 'medicines', filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            front_image.save(path)
            front_path = f"medicines/{filename}"

        # Update back image if uploaded
        if back_image:
            filename = secure_filename(f"back_{medicine_id}_{back_image.filename}")
            path = os.path.join(app.config['UPLOAD_FOLDER'], 'medicines', filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            back_image.save(path)
            back_path = f"medicines/{filename}"

        # Update query
        update_query = """
        UPDATE medicines
        SET
            name=%s,
            manufacturer=%s,
            category=%s,
            quantity=%s,
            dosage=%s,
            expiry_date=%s,
            batch_number=%s,
            main_image=%s,
            front_image=%s,
            back_image=%s
        WHERE id=%s AND user_id=%s
        """

        cursor.execute(update_query, (
            name,
            manufacturer,
            category,
            quantity,
            dosage,
            expiry_date,
            batch_number,
            main_path,
            front_path,
            back_path,
            medicine_id,
            user_id
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Medicine updated successfully"
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/medicines', methods=['GET'])
@token_required
def get_all_medicines(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT 
            id, 
            name, 
            manufacturer, 
            dosage, 
            expiry_date, 
            batch_number, 
            category, 
            quantity, 
            main_image
        FROM medicines
        WHERE user_id = %s
        ORDER BY created_at DESC
        """

        cursor.execute(query, (user_id,))
        medicines = cursor.fetchall()

        BASE_URL = "http://10.0.2.2:5000/"

        for med in medicines:
            # Format expiry date
            if med["expiry_date"]:
                med["expiry_date"] = med["expiry_date"].strftime("%Y-%m-%d")

            # Format image path - return as is for app to handle
            pass

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "count": len(medicines),
            "medicines": medicines
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/identify-medicine', methods=['GET'])
@token_required
def identify_medicine(user_id):

    medicine_name = request.args.get('name')

    if not medicine_name:
        return jsonify({
            "status": "error",
            "message": "Medicine name is required"
        }), 400

    conn = get_db_connection()

    if not conn:
        return jsonify({
            "status": "error",
            "message": "Database connection failed"
        }), 500

    cursor = conn.cursor(dictionary=True)

    try:

        # SEARCH MEDICINES (PARTIAL MATCH)
        search_query = """
        SELECT id, name, manufacturer, dosage, expiry_date,
               category, main_image, front_image, back_image
        FROM medicines
        WHERE user_id = %s AND name LIKE %s
        ORDER BY name ASC
        """

        cursor.execute(search_query, (user_id, f"%{medicine_name}%"))
        medicines = cursor.fetchall()

        matches = []
        BASE_URL = "http://10.0.2.2:5000/"

        for med in medicines:
            # Fix image URLs
            main_url = med["main_image"]
            front_url = med["front_image"]
            back_url = med["back_image"]

            # Image URLs will be handled by the app

            matches.append({
                "id": med["id"],
                "name": med["name"],
                "manufacturer": med["manufacturer"],
                "dosage": med["dosage"],
                "expiry_date": str(med["expiry_date"]) if med["expiry_date"] else None,
                "category": med["category"],
                "main_image": main_url,
                "front_image": front_url,
                "back_image": back_url
            })

        suggestions = []

        # IF NO EXACT MATCH → USE FUZZY SEARCH
        if len(matches) == 0:

            cursor.execute(
                "SELECT DISTINCT name FROM medicines WHERE user_id=%s",
                (user_id,)
            )

            all_medicines = cursor.fetchall()

            medicine_list = [m["name"] for m in all_medicines]

            suggestions = difflib.get_close_matches(
                medicine_name,
                medicine_list,
                n=5,
                cutoff=0.5
            )

        return jsonify({
            "status": "success",
            "entered_name": medicine_name,
            "match_count": len(matches),
            "matches": matches,
            "suggestions": suggestions
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

    finally:
        cursor.close()
        conn.close()
        
#-----------------------------------------------
# --- Remainder routes ---
@app.route('/api/reminders', methods=['POST'])
@token_required
def add_reminder(user_id):

    conn = None
    cursor = None

    try:

        data = request.get_json()

        medicine_id = data.get("medicine_id")
        reminder_time = data.get("reminder_time")
        dosage = data.get("dosage")

        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
        INSERT INTO reminders (user_id, medicine_id, reminder_time, dosage, is_active)
        VALUES (%s, %s, %s, %s, 1)
        """

        cursor.execute(query, (user_id, medicine_id, reminder_time, dosage))
        conn.commit()

        return jsonify({
            "success": True,
            "message": "Reminder added"
        }), 201

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/medicines/<int:medicine_id>/reminders', methods=['GET'])
@token_required
def get_medicine_reminders(user_id, medicine_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT id, reminder_time, dosage, is_active
    FROM reminders
    WHERE user_id=%s AND medicine_id=%s
    ORDER BY reminder_time
    """

    cursor.execute(query, (user_id, medicine_id))
    reminders = cursor.fetchall()

    # ✅ convert time to string
    for reminder in reminders:
        reminder["reminder_time"] = str(reminder["reminder_time"])
        # is_active is already an int (0/1) from DB, so it's JSON serializable

    return jsonify({
        "success": True,
        "reminders": reminders
    }), 200

@app.route('/api/reminders/today', methods=['GET'])
@token_required
def get_today_schedule(user_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT 
            r.id,
            r.reminder_time,
            r.dosage,
            m.name AS medicine_name
        FROM reminders r
        JOIN medicines m ON r.medicine_id = m.id
        WHERE r.user_id = %s
        AND r.is_active = 1
        ORDER BY r.reminder_time
        """

        cursor.execute(query, (user_id,))
        reminders = cursor.fetchall()

        from datetime import datetime

        current_time = datetime.now().time()
        schedule = []
        for r in reminders:
            reminder_time_val = r["reminder_time"]
            
            # Convert to actual time object for comparison
            if isinstance(reminder_time_val, str):
                try:
                    # Handle both 24h and 12h if they exist in DB
                    if "AM" in reminder_time_val.upper() or "PM" in reminder_time_val.upper():
                        parsed_dt = datetime.strptime(reminder_time_val, "%I:%M %p")
                    else:
                        parsed_dt = datetime.strptime(reminder_time_val, "%H:%M")
                    t_obj = parsed_dt.time()
                except:
                    # Fallback to current time to avoid crash if data is corrupted
                    t_obj = current_time
            elif hasattr(reminder_time_val, "seconds"):
                # It's a timedelta
                t_obj = (datetime.min + reminder_time_val).time()
            else:
                t_obj = reminder_time_val # Already a time object?

            formatted_time = t_obj.strftime("%H:%M")
            
            # Simple status calculation (could be improved with timezone awareness later)
            # Use a tiny buffer to match client logic
            is_past = t_obj < current_time
            status = "past" if is_past else "upcoming"

            schedule.append({
                "id": r["id"],
                "time": formatted_time,
                "medicine_name": r["medicine_name"],
                "dosage": r["dosage"],
                "status": status
            })

        return jsonify({
            "success": True,
            "schedule": schedule
        }), 200

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/reminders', methods=['GET'])
@token_required
def get_all_reminders(user_id):

    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT 
            r.id,
            r.reminder_time,
            r.dosage,
            r.is_active,
            m.name AS medicine_name,
            m.main_image
        FROM reminders r
        JOIN medicines m ON r.medicine_id = m.id
        WHERE r.user_id = %s
        ORDER BY m.name, r.reminder_time
        """

        cursor.execute(query, (user_id,))
        rows = cursor.fetchall()

        from datetime import datetime

        grouped = {}

        for r in rows:
            reminder_time_val = r["reminder_time"]

            if hasattr(reminder_time_val, "seconds"):
                t_obj = (datetime.min + reminder_time_val).time()
            elif isinstance(reminder_time_val, str):
                try:
                    if "AM" in reminder_time_val.upper() or "PM" in reminder_time_val.upper():
                        t_obj = datetime.strptime(reminder_time_val, "%I:%M %p").time()
                    else:
                        t_obj = datetime.strptime(reminder_time_val, "%H:%M").time()
                except:
                    continue # or fallback
            else:
                t_obj = reminder_time_val

            formatted_time = t_obj.strftime("%H:%M")

            medicine = r["medicine_name"]

            if medicine not in grouped:
                grouped[medicine] = {
                    "medicine_name": medicine,
                    "main_image": r["main_image"],
                    "items": []
                }

            grouped[medicine]["items"].append({
                "id": r["id"],
                "time": formatted_time,
                "dosage": r["dosage"],
                "is_active": r["is_active"]
            })

        return jsonify({
            "success": True,
            "reminders": list(grouped.values())
        }), 200

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/reminders/<int:reminder_id>/toggle', methods=['PUT'])
@token_required
def toggle_reminder(user_id, reminder_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT is_active
        FROM reminders
        WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (reminder_id, user_id))
        reminder = cursor.fetchone()

        if not reminder:
            return jsonify({"error": "Reminder not found"}), 404

        current_status = reminder["is_active"]

        new_status = 0 if current_status == 1 else 1

        update_query = """
        UPDATE reminders
        SET is_active = %s
        WHERE id = %s AND user_id = %s
        """

        cursor.execute(update_query, (new_status, reminder_id, user_id))
        conn.commit()

        return jsonify({
            "success": True,
            "is_active": new_status
        }), 200

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

@app.route('/api/reminders/<int:reminder_id>', methods=['DELETE'])
@token_required
def delete_reminder(user_id, reminder_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
        DELETE FROM reminders
        WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (reminder_id, user_id))
        conn.commit()

        return jsonify({
            "success": True,
            "message": "Reminder deleted"
        }), 200

    except Exception as e:

        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# --- Pill Scanning Mock Route ---

@app.route('/api/scan', methods=['POST'])
def scan_pill():
    # If image upload logic is needed:
    # file = request.files.get('image')
    
    mock_identified_result = {
        'match_status': 'success',
        'confidence': 98.4,
        'medicine': {
            'name': 'Amoxicillin',
            'dosage': '500mg',
            'type': 'Capsule',
            'description': 'Antibiotic used to treat a number of bacterial infections. Primarily for ears, nose, and throat infections.',
            'warnings': 'May cause allergic reactions in penicillin-sensitive patients. Complete the full course.'
        }
    }
    
    return jsonify(mock_identified_result), 200


if __name__ == '__main__':
    # Listens on all interfaces so the Android emulator can access it using 10.0.2.2 
    app.run(host='0.0.0.0', port=5000, debug=True)
