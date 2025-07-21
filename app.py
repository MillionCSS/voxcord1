import os
import hashlib
import secrets
import jwt
import smtplib
import json
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import uuid
import time
import re
# Import missing modules
from flask import Flask, request, Response, send_file, jsonify, redirect, render_template_string, send_from_directory, render_template
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client
from openai import OpenAI
import threading
from pathlib import Path
import logging
from dotenv import load_dotenv
from functools import wraps
import redis
from contextlib import contextmanager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('voxcord.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Static file configuration
app.static_folder = 'static'
app.static_url_path = '/static'

# Initialize clients
try:
    openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    twilio_client = Client(os.getenv('TWILIO_ACCOUNT_SID'), os.getenv('TWILIO_AUTH_TOKEN'))
except Exception as e:
    logger.error(f"Failed to initialize clients: {e}")
    openai_client = None
    twilio_client = None

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///voxcord.db')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Try to connect to Redis, fallback to in-memory
try:
    redis_client = redis.from_url(REDIS_URL)
    redis_client.ping()
    logger.info("Connected to Redis")
except:
    redis_client = None
    logger.warning("Redis not available, using in-memory storage")

# JWT Secret
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', '587')),
    'email': os.getenv('EMAIL_ADDRESS'),
    'password': os.getenv('EMAIL_PASSWORD'),
    'from_name': 'Voxcord Team'
}

# Plan configurations
PLAN_LIMITS = {
    'free': {
        'max_assistants': 1,
        'max_calls_per_month': 100,
        'max_call_duration': 300,
        'features': ['basic_ai', 'email_support'],
        'price': 0,
        'trial_days': None
    },
    'professional': {
        'max_assistants': 5,
        'max_calls_per_month': -1,
        'max_call_duration': -1,
        'features': ['custom_training', 'crm_integration', 'analytics', 'priority_support'],
        'price': 99,
        'trial_days': 14
    },
    'enterprise': {
        'max_assistants': -1,
        'max_calls_per_month': -1,
        'max_call_duration': -1,
        'features': ['voice_cloning', 'api_access', 'custom_integration', 'dedicated_support', 'white_label'],
        'price': 299,
        'trial_days': 14
    }
}

# Create directories
AUDIO_DIR = Path("audio_files")
AUDIO_DIR.mkdir(exist_ok=True)

STATIC_DIR = Path("static")
STATIC_DIR.mkdir(exist_ok=True)

class DatabaseManager:
    """Centralized database management"""
    
    def __init__(self, db_path='voxcord.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    company TEXT,
                    industry TEXT,
                    phone TEXT,
                    plan TEXT DEFAULT 'free',
                    verified BOOLEAN DEFAULT FALSE,
                    verification_token TEXT,
                    verification_expiry TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    subscription_status TEXT DEFAULT 'active',
                    trial_end TIMESTAMP,
                    settings TEXT DEFAULT '{}'
                )
            ''')
            
            # Call sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS call_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    call_sid TEXT UNIQUE,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    duration INTEGER,
                    status TEXT DEFAULT 'active',
                    conversation_history TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Usage tracking table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usage_tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    date DATE,
                    calls_count INTEGER DEFAULT 0,
                    total_duration INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, date)
                )
            ''')
            
            # Phone numbers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phone_numbers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE,
                    phone_number TEXT UNIQUE,
                    twilio_sid TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, user_data):
        """Create a new user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Handle the verified field - THIS IS THE KEY FIX
            verified = user_data.get('verified', False)
            
            cursor.execute('''
                INSERT INTO users (
                    id, first_name, last_name, email, password_hash, company, 
                    industry, phone, plan, verification_token, verification_expiry, verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_data['id'], user_data['firstName'], user_data['lastName'],
                user_data['email'], user_data['passwordHash'], user_data['company'],
                user_data['industry'], user_data['phone'], user_data['plan'],
                user_data['verificationToken'], user_data['verificationExpiry'], verified
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_user_by_email(self, email):
        """Get user by email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def verify_user(self, verification_token):
        """Verify user email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET verified = TRUE, verification_token = NULL 
                WHERE verification_token = ? AND verification_expiry > datetime('now')
            ''', (verification_token,))
            conn.commit()
            return cursor.rowcount > 0
    
    def create_call_session(self, call_data):
        """Create a new call session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO call_sessions (id, user_id, call_sid, metadata)
                VALUES (?, ?, ?, ?)
            ''', (
                call_data['id'], call_data.get('user_id'), 
                call_data['call_sid'], json.dumps(call_data.get('metadata', {}))
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_active_calls(self):
        """Get all active call sessions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM call_sessions 
                WHERE status = 'active' 
                ORDER BY started_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def update_call_session(self, call_sid, updates):
        """Update call session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            set_clause = ', '.join([f"{key} = ?" for key in updates.keys()])
            values = list(updates.values()) + [call_sid]
            cursor.execute(f'''
                UPDATE call_sessions 
                SET {set_clause}
                WHERE call_sid = ?
            ''', values)
            conn.commit()
            return cursor.rowcount > 0

# Initialize database
db = DatabaseManager()

class CacheManager:
    """Unified cache management using Redis or in-memory fallback"""
    
    def __init__(self):
        self.redis_client = redis_client
        self.memory_cache = {} if not redis_client else None
    
    def get(self, key):
        """Get value from cache"""
        if self.redis_client:
            try:
                value = self.redis_client.get(key)
                return json.loads(value) if value else None
            except:
                return None
        else:
            return self.memory_cache.get(key)
    
    def set(self, key, value, ttl=3600):
        """Set value in cache"""
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, json.dumps(value))
                return True
            except:
                return False
        else:
            self.memory_cache[key] = value
            # Simple TTL implementation for memory cache
            threading.Timer(ttl, lambda: self.memory_cache.pop(key, None)).start()
            return True
    
    def delete(self, key):
        """Delete key from cache"""
        if self.redis_client:
            try:
                self.redis_client.delete(key)
                return True
            except:
                return False
        else:
            self.memory_cache.pop(key, None)
            return True

cache = CacheManager()

class SecurityManager:
    """Enhanced security management"""
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def hash_password(password):
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    @staticmethod
    def verify_password(password, stored_hash):
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(':')
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return password_hash.hex() == hash_value
        except:
            return False

class PhoneNumberManager:
    """Manage Twilio phone numbers"""
    
    @staticmethod
    def generate_phone_number(user_id):
        """Generate/assign phone number to user"""
        # Check if user already has a phone number
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT phone_number FROM phone_numbers WHERE user_id = ?', (user_id,))
            existing = cursor.fetchone()
            if existing:
                return existing['phone_number']
        
        # Use your actual Twilio number for all users
        phone_number = "+16095073300"  # Your actual number
        
        # Store in database
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO phone_numbers (user_id, phone_number)
                VALUES (?, ?)
            ''', (user_id, phone_number))
            conn.commit()
        
        return phone_number

class EmailService:
    """Email service for notifications and verification"""
    
    @staticmethod
    def send_email(to_email, subject, html_body, text_body=None):
        """Send email using SMTP"""
        if not EMAIL_CONFIG['email'] or not EMAIL_CONFIG['password']:
            logger.warning("Email service not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{EMAIL_CONFIG['from_name']} <{EMAIL_CONFIG['email']}>"
            msg['To'] = to_email
            
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['email'], EMAIL_CONFIG['password'])
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    @staticmethod
    def send_verification_email(user_email, user_name, verification_token):
        """Send email verification"""
        verification_url = f"{request.host_url}verify-email?token={verification_token}"
        
        subject = "Welcome to Voxcord - Verify Your Email"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Verify Your Email - Voxcord</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 0; background-color: #f8fafc; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
                .header {{ background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); color: white; padding: 2rem; text-align: center; }}
                .content {{ padding: 2rem; }}
                .button {{ display: inline-block; background: #1e40af; color: white; padding: 1rem 2rem; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 1rem 0; }}
                .footer {{ background: #f1f5f9; padding: 1rem; text-align: center; color: #64748b; font-size: 0.875rem; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Welcome to Voxcord!</h1>
                    <p>Enterprise AI Voice Solutions</p>
                </div>
                <div class="content">
                    <h2>Hi {user_name},</h2>
                    <p>Thanks for signing up for Voxcord! To verify your email address, click the button below:</p>
                    <div style="text-align: center; margin: 2rem 0;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </div>
                    <p>If you can't click the button, copy this link: {verification_url}</p>
                    <p><strong>This link expires in 24 hours.</strong></p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Voxcord. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Welcome to Voxcord!
        
        Hi {user_name},
        
        Thanks for signing up for Voxcord! To verify your email address, please visit:
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, you can ignore this email.
        
        Best regards,
        The Voxcord Team
        """
        
        return EmailService.send_email(user_email, subject, html_body, text_body)

# Utility functions
def create_session_token(user):
    """Create JWT session token"""
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'plan': user['plan'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_session_token(token):
    """Verify JWT session token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except:
        return None

def require_auth(f):
    """Decorator for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_session_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated_function

def rate_limit_check(ip_address, max_attempts=5, window_minutes=15):
    """Check rate limiting"""
    key = f"rate_limit:{ip_address}"
    attempts = cache.get(key) or []
    now = datetime.utcnow()
    
    # Remove old attempts
    attempts = [attempt for attempt in attempts if now - datetime.fromisoformat(attempt) < timedelta(minutes=window_minutes)]
    
    if len(attempts) >= max_attempts:
        return False
    
    attempts.append(now.isoformat())
    cache.set(key, attempts, ttl=window_minutes * 60)
    return True

# Routes
@app.route('/')
def index():
    return redirect('/landing')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    try:
        return send_from_directory('static', filename)
    except Exception as e:
        logger.error(f"Error serving static file {filename}: {e}")
        return "File not found", 404

@app.route('/landing')
def landing_page():
    try:
        return send_file('landing.html')
    except Exception as e:
        logger.error(f"Error serving landing page: {e}")
        return "Landing page not found", 404

@app.route('/signup')
def signup_page():
    try:
        return send_file('signup.html')
    except Exception as e:
        logger.error(f"Error serving signup page: {e}")
        return "Signup page not found", 404

@app.route('/login')
def login_page():
    try:
        return send_file('login.html')
    except Exception as e:
        logger.error(f"Error serving login page: {e}")
        return "Login page not found", 404

@app.route('/dashboard')
def dashboard():
    try:
        return send_file('dashboard.html')
    except Exception as e:
        logger.error(f"Error serving dashboard: {e}")
        return "Dashboard not found", 404

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Enhanced signup with proper email verification"""
    try:
        data = request.json
        client_ip = request.remote_addr
        
        # Rate limiting
        if not rate_limit_check(client_ip):
            return jsonify({'success': False, 'message': 'Too many attempts. Please try again later.'}), 429
        
        # Validate required fields - MAKE THEM OPTIONAL
        required_fields = ['firstName', 'lastName', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        # Validate email format
        email = data['email'].lower().strip()
        if not SecurityManager.validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # CHECK FOR DUPLICATE EMAIL - CRITICAL FIX
        existing_user = db.get_user_by_email(email)
        if existing_user:
            logger.warning(f"Duplicate signup attempt: {email}")
            return jsonify({'success': False, 'message': 'An account with this email already exists. Please try logging in instead.'}), 400
        
        # Validate password - MAKE IT SIMPLER
        password = data['password']
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Validate plan
        plan = data.get('plan', 'free')
        if plan not in PLAN_LIMITS:
            return jsonify({'success': False, 'message': 'Invalid plan selected'}), 400
        
        # Generate user ID and hash password
        user_id = str(uuid.uuid4())
        password_hash = SecurityManager.hash_password(password)
        
        # Check if email service is configured
        email_configured = EMAIL_CONFIG['email'] and EMAIL_CONFIG['password']
        
        # Generate verification token only if email is configured
        verification_token = secrets.token_urlsafe(32) if email_configured else None
        verification_expiry = (datetime.utcnow() + timedelta(hours=24)).isoformat() if email_configured else None
        
        # Create user account with AUTO-VERIFICATION if no email service
        user_data = {
            'id': user_id,
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'email': email,
            'passwordHash': password_hash,
            'company': data.get('company', ''),
            'industry': data.get('industry', ''),
            'phone': data.get('phone', ''),
            'plan': plan,
            'verificationToken': verification_token,
            'verificationExpiry': verification_expiry,
            'verified': not email_configured  # AUTO-VERIFY if no email service
        }
        
        db.create_user(user_data)
        
        # Send verification email only if configured
        email_sent = False
        if email_configured:
            email_sent = EmailService.send_verification_email(
                email,
                data['firstName'],
                verification_token
            )
        
        # Generate phone number
        phone_number = PhoneNumberManager.generate_phone_number(user_id)
        
        logger.info(f"New user registration: {email} - {plan} plan - Auto-verified: {not email_configured}")
        
        # Different messages based on email configuration
        if email_configured:
            message = 'Account created successfully! Please check your email to verify your account.'
        else:
            message = 'Account created successfully! You can now sign in immediately.'
        
        return jsonify({
            'success': True,
            'userId': user_id,
            'plan': plan,
            'phoneNumber': phone_number,
            'message': message,
            'emailSent': email_sent,
            'autoVerified': not email_configured
        })
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500


    
@app.route('/api/signup/simple', methods=['POST'])
def simple_signup():
    """Simplified signup for modern frontend"""
    try:
        data = request.json
        client_ip = request.remote_addr
        
        # Rate limiting
        if not rate_limit_check(client_ip):
            return jsonify({'success': False, 'message': 'Too many attempts. Please try again later.'}), 429
        
        # Only require essential fields
        required_fields = ['firstName', 'lastName', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Check for duplicate
        existing_user = db.get_user_by_email(email)
        if existing_user:
            return jsonify({'success': False, 'message': 'An account with this email already exists. Please try logging in instead.'}), 400
        
        # Simple password validation
        if len(data['password']) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = SecurityManager.hash_password(data['password'])
        
        user_data = {
            'id': user_id,
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'email': email,
            'passwordHash': password_hash,
            'company': data.get('company', ''),
            'industry': data.get('industry', ''),
            'phone': '',
            'plan': data.get('plan', 'free'),
            'verificationToken': None,
            'verificationExpiry': None,
            'verified': True  # Auto-verify for simplified flow
        }
        
        db.create_user(user_data)
        phone_number = PhoneNumberManager.generate_phone_number(user_id)
        
        session_token = create_session_token({
            'id': user_id,
            'email': email,
            'plan': user_data['plan']
        })
        
        logger.info(f"Simple signup completed: {email}")
        
        return jsonify({
            'success': True,
            'sessionToken': session_token,
            'user': {
                'id': user_id,
                'email': email,
                'name': f"{data['firstName']} {data['lastName']}",
                'plan': user_data['plan'],
                'phoneNumber': phone_number
            },
            'message': 'Account created successfully! You can now use your AI assistant.'
        })
        
    except Exception as e:
        logger.error(f"Simple signup error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500
    
@app.route('/api/auth/google', methods=['POST'])
def google_oauth():
    """Handle Google OAuth authentication"""
    try:
        data = request.json
        
        # Extract user info from Google OAuth response
        user_info = {
            'email': data.get('email'),
            'name': data.get('name'),
            'picture': data.get('picture', ''),
            'provider': 'google'
        }
        
        if not user_info['email']:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        email = user_info['email'].lower().strip()
        
        # Check if user exists
        existing_user = db.get_user_by_email(email)
        
        if existing_user:
            # User exists, log them in
            session_token = create_session_token(existing_user)
            phone_number = PhoneNumberManager.generate_phone_number(existing_user['id'])
            
            return jsonify({
                'success': True,
                'sessionToken': session_token,
                'user': {
                    'id': existing_user['id'],
                    'email': existing_user['email'],
                    'name': f"{existing_user['first_name']} {existing_user['last_name']}",
                    'plan': existing_user['plan'],
                    'phoneNumber': phone_number
                }
            })
        else:
            # Create new user from OAuth
            user_id = str(uuid.uuid4())
            name_parts = user_info['name'].split(' ', 1) if user_info['name'] else ['User', '']
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            user_data = {
                'id': user_id,
                'firstName': first_name,
                'lastName': last_name,
                'email': email,
                'passwordHash': '',  # No password for OAuth users
                'company': '',
                'industry': '',
                'phone': '',
                'plan': 'free',
                'verificationToken': None,
                'verificationExpiry': None,
                'verified': True  # OAuth users are auto-verified
            }
            
            db.create_user(user_data)
            phone_number = PhoneNumberManager.generate_phone_number(user_id)
            
            session_token = create_session_token({
                'id': user_id,
                'email': email,
                'plan': 'free'
            })
            
            logger.info(f"New OAuth user created: {email} via Google")
            
            return jsonify({
                'success': True,
                'sessionToken': session_token,
                'user': {
                    'id': user_id,
                    'email': email,
                    'name': user_info['name'] or f"{first_name} {last_name}",
                    'plan': 'free',
                    'phoneNumber': phone_number
                }
            })
            
    except Exception as e:
        logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500

@app.route('/api/auth/apple', methods=['POST'])
def apple_oauth():
    """Handle Apple OAuth authentication"""
    try:
        data = request.json
        
        # Similar to Google OAuth
        user_info = {
            'email': data.get('email'),
            'name': data.get('name', 'Apple User'),
            'provider': 'apple'
        }
        
        # Same logic as Google OAuth
        # ... (copy the logic from google_oauth but change provider to 'apple')
        
        return jsonify({
            'success': True,
            'message': 'Apple OAuth processed successfully'
        })
        
    except Exception as e:
        logger.error(f"Apple OAuth error: {str(e)}")
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """Enhanced login with proper security"""
    try:
        data = request.json
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        client_ip = request.remote_addr
        
        # Check rate limiting
        if not rate_limit_check(client_ip, max_attempts=5):
            return jsonify({
                'success': False, 
                'message': 'Too many failed attempts. Please try again in 15 minutes.'
            }), 429
        
        # Find user by email
        user = db.get_user_by_email(email)
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Verify password
        if not SecurityManager.verify_password(password, user['password_hash']):
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check if account is verified
        if not user['verified']:
            return jsonify({
                'success': False, 
                'message': 'Please verify your email address before signing in.'
            }), 401
        
        # Create session token
        session_token = create_session_token(user)
        
        # Update last login
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            conn.commit()
        
        # Get phone number
        phone_number = PhoneNumberManager.generate_phone_number(user['id'])
        
        logger.info(f"Successful login: {email}")
        
        return jsonify({
            'success': True,
            'sessionToken': session_token,
            'user': {
                'id': user['id'],
                'firstName': user['first_name'],
                'lastName': user['last_name'],
                'email': user['email'],
                'company': user['company'],
                'plan': user['plan'],
                'phoneNumber': phone_number
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/verify-email')
def verify_email():
    """Email verification endpoint"""
    token = request.args.get('token')
    
    if not token:
        return render_template_string(ERROR_PAGE_TEMPLATE, 
            title="Invalid Verification Link",
            message="The verification link is invalid or missing."
        )
    
    # Verify the token
    if db.verify_user(token):
        # Get user data
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE verification_token IS NULL AND verified = TRUE ORDER BY created_at DESC LIMIT 1')
            user = cursor.fetchone()
        
        if user:
            user = dict(user)
            # Generate phone number
            phone_number = PhoneNumberManager.generate_phone_number(user['id'])
            
            # Create session token for auto-login
            session_token = create_session_token(user)
            
            logger.info(f"Email verified for user: {user['email']}")
            
            return render_template_string(SUCCESS_PAGE_TEMPLATE,
                user_name=user['first_name'],
                plan=user['plan'],
                phone_number=phone_number,
                session_token=session_token,
                user_data={
                    'id': user['id'],
                    'email': user['email'],
                    'plan': user['plan']
                }
            )
    
    return render_template_string(ERROR_PAGE_TEMPLATE,
        title="Verification Failed",
        message="This verification link is invalid or has expired."
    )

@app.route('/api/verify-session', methods=['GET'])
@require_auth
def verify_session():
    """Verify if session is still valid"""
    return jsonify({'success': True, 'user': request.current_user})

@app.route('/phone_info')
@require_auth
def phone_info():
    """Get user's phone number"""
    # Return your actual Twilio number
    return jsonify({'phone_number': '+1 (609) 507-3300'})

@app.route('/active_calls')
def active_calls():
    """Get active call sessions"""
    try:
        calls = db.get_active_calls()
        
        # Format the response
        formatted_calls = []
        for call in calls:
            conversation_history = json.loads(call.get('conversation_history', '[]'))
            formatted_calls.append({
                'call_sid': call['call_sid'],
                'started_at': time.mktime(datetime.fromisoformat(call['started_at']).timetuple()),
                'message_count': len(conversation_history),
                'status': call['status']
            })
        
        return jsonify(formatted_calls)
    except Exception as e:
        logger.error(f"Error fetching active calls: {e}")
        return jsonify([])

@app.route('/call_summary/<call_sid>')
def call_summary(call_sid):
    """Get call summary and transcript"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM call_sessions WHERE call_sid = ?', (call_sid,))
            call = cursor.fetchone()
            
            if not call:
                return jsonify({'error': 'Call not found'}), 404
            
            call_dict = dict(call)
            conversation_history = json.loads(call_dict.get('conversation_history', '[]'))
            
            return jsonify({
                'call_sid': call_dict['call_sid'],
                'started_at': call_dict['started_at'],
                'conversation_history': conversation_history,
                'status': call_dict['status']
            })
    except Exception as e:
        logger.error(f"Error fetching call summary: {e}")
        return jsonify({'error': 'Failed to fetch call summary'}), 500

@app.route('/update_config', methods=['POST'])
@require_auth
def update_config():
    """Update AI configuration"""
    try:
        data = request.json
        user_id = request.current_user['user_id']
        
        # Store configuration in database
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET settings = ? 
                WHERE id = ?
            ''', (json.dumps(data), user_id))
            conn.commit()
        
        # Cache the configuration
        cache.set(f"config:{user_id}", data, ttl=86400)  # 24 hours
        
        logger.info(f"Configuration updated for user: {user_id}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({'success': False, 'error': 'Failed to update configuration'}), 500

@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio voice calls - FIXED VERSION"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"Incoming call - CallSid: {call_sid}, From: {from_number}, To: {to_number}")
        
        # SIMPLIFIED APPROACH - Since everyone uses the same number (+16095073300)
        # We don't need to find a specific user, just handle the call generically
        
        # Create a generic call session for tracking
        call_data = {
            'id': str(uuid.uuid4()),
            'user_id': 'system',  # Generic system user
            'call_sid': call_sid,
            'metadata': {
                'from_number': from_number,
                'to_number': to_number,
                'timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Try to create call session (don't fail if it doesn't work)
        try:
            db.create_call_session(call_data)
            logger.info(f"Call session created for: {call_sid}")
        except Exception as e:
            logger.warning(f"Could not create call session: {e}")
        
        # Create TwiML response - THIS IS THE IMPORTANT PART
        response = VoiceResponse()
        
        # Default greeting - you can customize this
        greeting = "Hello! Thank you for calling Voxcord, your AI voice assistant platform. How can I help you today?"
        
        # Say the greeting
        response.say(greeting, voice='alice')
        
        # Set up for conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Please tell me what you need assistance with.", voice='alice')
        response.append(gather)
        
        # Fallback if no speech detected
        response.say("I didn't hear anything. Please call back when you're ready to talk. Thank you!")
        
        logger.info(f"TwiML response sent for call: {call_sid}")
        return str(response)
        
    except Exception as e:
        logger.error(f"Error handling voice call: {e}")
        
        # ALWAYS return a valid TwiML response, even on error
        response = VoiceResponse()
        response.say("I'm sorry, there was a technical issue. Please try calling back in a few minutes.")
        return str(response)

@app.route('/debug/users')
def debug_users():
    """Debug route to check users in database"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, email, verified, plan, created_at FROM users ORDER BY created_at DESC LIMIT 10')
            users = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute('SELECT COUNT(*) as total FROM users')
            total_count = cursor.fetchone()['total']
            
            return jsonify({
                'success': True,
                'total_users': total_count,
                'recent_users': users,
                'database_path': db.db_path
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'database_path': getattr(db, 'db_path', 'Unknown')
        })

@app.route('/debug/phone')
def debug_phone():
    """Debug phone number assignments"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM phone_numbers ORDER BY created_at DESC LIMIT 10')
            phone_records = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                'success': True,
                'phone_records': phone_records,
                'expected_number': '+16095073300'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/test')
def test_system():
    """Test system functionality"""
    try:
        # Test database connection
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM users')
            user_count = cursor.fetchone()['count']
            
            # Test phone number generation
            test_phone = PhoneNumberManager.generate_phone_number('test-user')
        
        return jsonify({
            'status': 'OK',
            'database': 'Connected',
            'user_count': user_count,
            'phone_number_test': test_phone,
            'expected_phone': '+16095073300',
            'openai_configured': bool(openai_client),
            'twilio_configured': bool(twilio_client),
            'email_configured': bool(EMAIL_CONFIG['email'])
        })
        
    except Exception as e:
        return jsonify({
            'status': 'ERROR',
            'error': str(e)
        }), 500


@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech_input(call_sid):
    """Handle speech input from Twilio"""
    try:
        speech_result = request.form.get('SpeechResult')
        
        if not speech_result:
            response = VoiceResponse()
            gather = Gather(
                input='speech',
                action=f'/api/twilio/gather/{call_sid}',
                method='POST',
                speech_timeout='auto',
                language='en-US'
            )
            gather.say("I didn't catch that. Could you please repeat?")
            response.append(gather)
            return str(response)
        
        # Get call session
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM call_sessions WHERE call_sid = ?', (call_sid,))
            call = cursor.fetchone()
        
        if not call:
            response = VoiceResponse()
            response.say("Sorry, there was an error with your call.")
            return str(response)
        
        call = dict(call)
        user_id = call['user_id']
        
        # Get conversation history
        conversation_history = json.loads(call.get('conversation_history', '[]'))
        
        # Get user's AI configuration
        config = cache.get(f"config:{user_id}")
        if not config:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT settings FROM users WHERE id = ?', (user_id,))
                user_settings = cursor.fetchone()
                if user_settings and user_settings['settings']:
                    config = json.loads(user_settings['settings'])
                else:
                    config = {}
        
        # Generate AI response
        ai_response = generate_ai_response(speech_result, conversation_history, config)
        
        # Update conversation history
        conversation_history.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': time.time()
        })
        
        # Update call session
        db.update_call_session(call_sid, {
            'conversation_history': json.dumps(conversation_history)
        })
        
        # Create TwiML response
        response = VoiceResponse()
        response.say(ai_response, voice=config.get('voice', 'alice'))
        
        # Continue listening
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Is there anything else I can help you with?")
        response.append(gather)
        
        # Fallback
        response.say("Thank you for calling. Have a great day!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Error handling speech input: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, I'm having trouble understanding. Please try again.")
        return str(response)

def generate_ai_response(user_input, conversation_history, config):
    """Generate AI response using OpenAI"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Build context from conversation history
        messages = [
            {
                "role": "system",
                "content": config.get('instructions', 
                    "You are a helpful customer service assistant. Be friendly, professional, and concise. "
                    "Keep responses under 50 words since this is a phone conversation."
                )
            }
        ]
        
        # Add conversation history
        for exchange in conversation_history[-5:]:  # Last 5 exchanges for context
            messages.append({"role": "user", "content": exchange['user']})
            messages.append({"role": "assistant", "content": exchange['assistant']})
        
        # Add current user input
        messages.append({"role": "user", "content": user_input})
        
        # Generate response
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=150,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Error generating AI response: {e}")
        return config.get('fallback', "I'm sorry, I didn't understand. Could you please repeat that?")

@app.route('/health')
def health_check():
    """System health check"""
    active_calls_count = len(db.get_active_calls())
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as verified FROM users WHERE verified = TRUE')
        verified_users = cursor.fetchone()['verified']
        
        cursor.execute('SELECT plan, COUNT(*) as count FROM users GROUP BY plan')
        plan_distribution = {row['plan']: row['count'] for row in cursor.fetchall()}
    
    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "openai_configured": bool(openai_client),
        "twilio_configured": bool(twilio_client),
        "email_configured": bool(EMAIL_CONFIG['email']),
        "redis_available": bool(redis_client),
        "total_users": total_users,
        "verified_users": verified_users,
        "active_calls": active_calls_count,
        "plan_distribution": plan_distribution
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# Template constants
ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Voxcord</title>
    <link rel="stylesheet" href="/static/styles.css">
    <style>
        body { background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 500px; text-align: center; }
        .error-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #e74c3c; margin-bottom: 1rem; }
        .btn { background: #1e40af; color: white; padding: 1rem 2rem; border: none; border-radius: 8px; text-decoration: none; display: inline-block; margin-top: 1rem; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>{{ title }}</h1>
        <p>{{ message }}</p>
        <a href="/login" class="btn">Back to Login</a>
        <a href="/signup" class="btn" style="background: #6b7280;">Sign Up</a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Verified - Voxcord</title>
    <link rel="stylesheet" href="/static/styles.css">
    <style>
        body { background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 500px; text-align: center; }
        .success-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #10b981; margin-bottom: 1rem; }
        .btn { background: #1e40af; color: white; padding: 1rem 2rem; border: none; border-radius: 8px; text-decoration: none; display: inline-block; margin-top: 1rem; font-weight: 600; }
        .info-box { background: #f0f9ff; padding: 1rem; border-radius: 8px; margin: 1rem 0; border-left: 4px solid #0ea5e9; }
    </style>
    <script>
        setTimeout(() => {
            localStorage.setItem('sessionToken', '{{ session_token }}');
            localStorage.setItem('user', JSON.stringify({{ user_data | tojson }}));
            window.location.href = '/dashboard';
        }, 3000);
    </script>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Email Verified!</h1>
        <p>Welcome to Voxcord, {{ user_name }}!</p>
        
        <div class="info-box">
            <p><strong>Plan:</strong> {{ plan.title() }}</p>
            <p><strong>Phone Number:</strong> {{ phone_number }}</p>
        </div>
        
        <p>Your account is now active. Redirecting to dashboard...</p>
        <a href="/dashboard" class="btn">Go to Dashboard Now</a>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    # Validate environment variables
    required_vars = ['OPENAI_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        exit(1)
    
    # Check configurations
    if not EMAIL_CONFIG['email']:
        logger.warning("Email service not configured - verification emails will not be sent")
    
    if not twilio_client:
        logger.warning("Twilio not configured - voice calls will not work")
    
    logger.info("Starting Voxcord backend server...")
    logger.info(f"Email service: {'Configured' if EMAIL_CONFIG['email'] else 'Not configured'}")
    logger.info(f"Twilio service: {'Configured' if twilio_client else 'Not configured'}")
    logger.info(f"Redis cache: {'Available' if redis_client else 'Using in-memory storage'}")
    
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=os.getenv('DEBUG', 'False').lower() == 'true')
