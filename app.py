#!/usr/bin/env python3
"""
Voxcord Backend - AI Voice Assistant Platform
Production-ready Flask application with Gunicorn support
"""

import os
import hashlib
import secrets
import jwt
import smtplib
import json
import sqlite3
import psycopg2
import psycopg2.extras
import re
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse

# Flask and extensions
from flask import Flask, request, jsonify, send_file, send_from_directory, render_template_string, redirect
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound, InternalServerError

# External services
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client as TwilioClient
from openai import OpenAI

# Utilities
import logging
import threading
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Only stdout for Digital Ocean
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
    JSON_SORT_KEYS=False,
    JSONIFY_PRETTYPRINT_REGULAR=False  # Disable for production
)

# Constants
SHARED_PHONE_NUMBER = "+16095073300"
DEFAULT_AI_GREETING = "Hello! Thank you for calling. How can I help you today?"

# Configuration Classes
class Config:
    """Application configuration"""
    
    @staticmethod
    def get_env(key: str, default=None) -> str:
        """Get environment variable with fallback"""
        return os.getenv(key, default)
    
    # API Keys
    OPENAI_API_KEY = get_env('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = get_env('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = get_env('TWILIO_AUTH_TOKEN')
    
    # Security
    JWT_SECRET = get_env('JWT_SECRET', secrets.token_hex(64))
    JWT_EXPIRY_HOURS = int(get_env('JWT_EXPIRY_HOURS', '24'))
    
    # Email
    SMTP_SERVER = get_env('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(get_env('SMTP_PORT', '587'))
    EMAIL_ADDRESS = get_env('EMAIL_ADDRESS')
    EMAIL_PASSWORD = get_env('EMAIL_PASSWORD')
    
    # Database - Auto-detect PostgreSQL vs SQLite
    DATABASE_URL = get_env('DATABASE_URL')
    
    # Application
    DEBUG = get_env('DEBUG', 'False').lower() == 'true'
    PORT = int(get_env('PORT', '8080'))
    HOST = get_env('HOST', '0.0.0.0')
    DOMAIN = get_env('DOMAIN', 'localhost:8080')
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = int(get_env('RATE_LIMIT_REQUESTS', '10'))
    RATE_LIMIT_WINDOW = int(get_env('RATE_LIMIT_WINDOW', '15'))


class ServiceClients:
    """External service clients"""
    
    def __init__(self):
        self.openai = None
        self.twilio = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize external service clients"""
        try:
            if Config.OPENAI_API_KEY:
                self.openai = OpenAI(api_key=Config.OPENAI_API_KEY)
                logger.info("OpenAI client initialized")
            else:
                logger.warning("OpenAI API key not provided")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI: {e}")
        
        try:
            if Config.TWILIO_ACCOUNT_SID and Config.TWILIO_AUTH_TOKEN:
                self.twilio = TwilioClient(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
                logger.info("Twilio client initialized")
            else:
                logger.warning("Twilio credentials not provided")
        except Exception as e:
            logger.error(f"Failed to initialize Twilio: {e}")

# Initialize service clients
services = ServiceClients()

class DatabaseManager:
    """Database operations manager with PostgreSQL/SQLite support"""
    
    def __init__(self):
        self.db_url = Config.DATABASE_URL
        self.is_postgres = self.db_url and self.db_url.startswith('postgres')
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Database connection context manager"""
        if self.is_postgres:
            # PostgreSQL connection
            conn = psycopg2.connect(
                self.db_url,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
        else:
            # SQLite connection
            db_path = 'voxcord.db'
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if self.is_postgres:
                # PostgreSQL schema
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        company TEXT DEFAULT '',
                        industry TEXT DEFAULT '',
                        phone TEXT DEFAULT '',
                        plan TEXT DEFAULT 'free',
                        verified BOOLEAN DEFAULT FALSE,
                        verification_token TEXT,
                        verification_expiry TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        settings TEXT DEFAULT '{}',
                        oauth_provider TEXT,
                        oauth_id TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS call_sessions (
                        id TEXT PRIMARY KEY,
                        user_id TEXT,
                        call_sid TEXT UNIQUE,
                        caller_number TEXT,
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ended_at TIMESTAMP,
                        duration INTEGER,
                        status TEXT DEFAULT 'active',
                        conversation_history TEXT DEFAULT '[]',
                        metadata TEXT DEFAULT '{}'
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_phone_routing (
                        id SERIAL PRIMARY KEY,
                        user_id TEXT UNIQUE,
                        routing_key TEXT UNIQUE,
                        phone_number TEXT DEFAULT %s,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''', (SHARED_PHONE_NUMBER,))
                
            else:
                # SQLite schema
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        company TEXT DEFAULT '',
                        industry TEXT DEFAULT '',
                        phone TEXT DEFAULT '',
                        plan TEXT DEFAULT 'free',
                        verified BOOLEAN DEFAULT FALSE,
                        verification_token TEXT,
                        verification_expiry TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        settings TEXT DEFAULT '{}',
                        oauth_provider TEXT,
                        oauth_id TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS call_sessions (
                        id TEXT PRIMARY KEY,
                        user_id TEXT,
                        call_sid TEXT UNIQUE,
                        caller_number TEXT,
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ended_at TIMESTAMP,
                        duration INTEGER,
                        status TEXT DEFAULT 'active',
                        conversation_history TEXT DEFAULT '[]',
                        metadata TEXT DEFAULT '{}'
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_phone_routing (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT UNIQUE,
                        routing_key TEXT UNIQUE,
                        phone_number TEXT DEFAULT ?,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''', (SHARED_PHONE_NUMBER,))
            
            conn.commit()
            logger.info(f"Database initialized ({'PostgreSQL' if self.is_postgres else 'SQLite'})")
    
    def create_user(self, user_data: dict) -> str:
        """Create a new user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            user_id = str(uuid.uuid4())
            
            if self.is_postgres:
                cursor.execute('''
                    INSERT INTO users (
                        id, first_name, last_name, email, password_hash,
                        company, industry, phone, plan, verified,
                        verification_token, verification_expiry, oauth_provider, oauth_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    user_id, user_data['first_name'], user_data['last_name'], user_data['email'],
                    user_data['password_hash'], user_data.get('company', ''), user_data.get('industry', ''),
                    user_data.get('phone', ''), user_data.get('plan', 'free'), user_data.get('verified', False),
                    user_data.get('verification_token'), user_data.get('verification_expiry'),
                    user_data.get('oauth_provider'), user_data.get('oauth_id')
                ))
                
                # Create routing entry
                routing_key = user_id[-8:]
                cursor.execute('''
                    INSERT INTO user_phone_routing (user_id, routing_key, phone_number)
                    VALUES (%s, %s, %s)
                ''', (user_id, routing_key, SHARED_PHONE_NUMBER))
            else:
                cursor.execute('''
                    INSERT INTO users (
                        id, first_name, last_name, email, password_hash,
                        company, industry, phone, plan, verified,
                        verification_token, verification_expiry, oauth_provider, oauth_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, user_data['first_name'], user_data['last_name'], user_data['email'],
                    user_data['password_hash'], user_data.get('company', ''), user_data.get('industry', ''),
                    user_data.get('phone', ''), user_data.get('plan', 'free'), user_data.get('verified', False),
                    user_data.get('verification_token'), user_data.get('verification_expiry'),
                    user_data.get('oauth_provider'), user_data.get('oauth_id')
                ))
                
                # Create routing entry
                routing_key = user_id[-8:]
                cursor.execute('''
                    INSERT INTO user_phone_routing (user_id, routing_key, phone_number)
                    VALUES (?, ?, ?)
                ''', (user_id, routing_key, SHARED_PHONE_NUMBER))
            
            conn.commit()
            logger.info(f"User created: {user_data['email']} (ID: {user_id})")
            return user_id
    
    def get_user_by_email(self, email: str) -> dict:
        """Get user by email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            param = '%s' if self.is_postgres else '?'
            cursor.execute(f'SELECT * FROM users WHERE email = {param}', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: str) -> dict:
        """Get user by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            param = '%s' if self.is_postgres else '?'
            cursor.execute(f'SELECT * FROM users WHERE id = {param}', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def verify_user_email(self, verification_token: str) -> bool:
        """Verify user email with token"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if self.is_postgres:
                cursor.execute('''
                    UPDATE users 
                    SET verified = TRUE, verification_token = NULL 
                    WHERE verification_token = %s 
                    AND verification_expiry > NOW()
                ''', (verification_token,))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET verified = TRUE, verification_token = NULL 
                    WHERE verification_token = ? 
                    AND verification_expiry > datetime('now')
                ''', (verification_token,))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def get_user_by_routing_key(self, routing_key: str) -> dict:
        """Get user by routing key"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            param = '%s' if self.is_postgres else '?'
            cursor.execute(f'''
                SELECT u.* FROM users u
                JOIN user_phone_routing upr ON u.id = upr.user_id
                WHERE upr.routing_key = {param}
            ''', (routing_key,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def create_call_session(self, call_data: dict) -> str:
        """Create a new call session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            call_id = str(uuid.uuid4())
            
            if self.is_postgres:
                cursor.execute('''
                    INSERT INTO call_sessions (
                        id, user_id, call_sid, caller_number, metadata
                    ) VALUES (%s, %s, %s, %s, %s)
                ''', (
                    call_id, call_data.get('user_id'), call_data['call_sid'],
                    call_data.get('caller_number'), json.dumps(call_data.get('metadata', {}))
                ))
            else:
                cursor.execute('''
                    INSERT INTO call_sessions (
                        id, user_id, call_sid, caller_number, metadata
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    call_id, call_data.get('user_id'), call_data['call_sid'],
                    call_data.get('caller_number'), json.dumps(call_data.get('metadata', {}))
                ))
            
            conn.commit()
            logger.info(f"Call session created: {call_data['call_sid']}")
            return call_id
    
    def get_active_calls(self) -> list:
        """Get all active call sessions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM call_sessions 
                WHERE status = 'active' 
                ORDER BY started_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_call_by_sid(self, call_sid: str) -> dict:
        """Get call session by SID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            param = '%s' if self.is_postgres else '?'
            cursor.execute(f'SELECT * FROM call_sessions WHERE call_sid = {param}', (call_sid,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_call_conversation(self, call_sid: str, conversation_history: list):
        """Update call conversation history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if self.is_postgres:
                cursor.execute('''
                    UPDATE call_sessions 
                    SET conversation_history = %s 
                    WHERE call_sid = %s
                ''', (json.dumps(conversation_history), call_sid))
            else:
                cursor.execute('''
                    UPDATE call_sessions 
                    SET conversation_history = ? 
                    WHERE call_sid = ?
                ''', (json.dumps(conversation_history), call_sid))
            
            conn.commit()

# Initialize database
db = DatabaseManager()

class SecurityManager:
    """Security utilities for authentication and validation"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email or not isinstance(email, str) or len(email) > 254:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        return True, "Password is strong"
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        if not password or not stored_hash or ':' not in stored_hash:
            return False
        try:
            salt, hash_value = stored_hash.split(':', 1)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return password_hash.hex() == hash_value
        except Exception:
            return False

class EmailService:
    """Email service for notifications"""
    
    @staticmethod
    def send_verification_email(email: str, name: str, token: str) -> bool:
        """Send email verification"""
        if not Config.EMAIL_ADDRESS or not Config.EMAIL_PASSWORD:
            logger.warning("Email service not configured")
            return False
        
        verification_url = f"https://{Config.DOMAIN}/verify-email?token={token}"
        
        subject = "Welcome to Voxcord - Verify Your Email"
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Inter, sans-serif; margin: 0; padding: 40px; background: #f8fafc;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; padding: 40px;">
                <h1 style="color: #3b82f6; text-align: center;">📡 Welcome to Voxcord!</h1>
                <p>Hi {name},</p>
                <p>Thanks for signing up! Click the button below to verify your email:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_url}" style="background: #3b82f6; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email</a>
                </div>
                <p>Or copy this link: {verification_url}</p>
                <p><small>This link expires in 24 hours.</small></p>
            </div>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"Voxcord <{Config.EMAIL_ADDRESS}>"
            msg['To'] = email
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
                server.starttls()
                server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Verification email sent to {email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {email}: {e}")
            return False

class AIService:
    """AI service for generating responses"""
    
    @staticmethod
    def generate_response(user_input: str, conversation_history: list, user_config: dict) -> str:
        """Generate AI response using OpenAI"""
        if not services.openai:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        try:
            # Build context
            messages = [
                {
                    "role": "system",
                    "content": user_config.get('instructions', 
                        "You are a helpful customer service assistant. Be friendly, professional, and concise. "
                        "Keep responses under 50 words since this is a phone conversation."
                    )
                }
            ]
            
            # Add conversation history (last 5 exchanges for context)
            for exchange in conversation_history[-5:]:
                messages.append({"role": "user", "content": exchange['user']})
                messages.append({"role": "assistant", "content": exchange['assistant']})
            
            # Add current user input
            messages.append({"role": "user", "content": user_input})
            
            # Generate response
            response = services.openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=150,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Error generating AI response: {e}")
            return user_config.get('fallback', "I'm sorry, I didn't understand. Could you please repeat that?")

# In-memory cache for user configurations
user_config_cache = {}

def get_user_config(user_id: str) -> dict:
    """Get user configuration with caching"""
    if user_id in user_config_cache:
        return user_config_cache[user_id]
    
    user = db.get_user_by_id(user_id)
    if user and user.get('settings'):
        try:
            config = json.loads(user['settings'])
            user_config_cache[user_id] = config
            return config
        except:
            pass
    
    # Default configuration
    default_config = {
        'voice': 'alice',
        'greeting': DEFAULT_AI_GREETING,
        'instructions': "You are a helpful customer service assistant. Be friendly and professional.",
        'fallback': "I'm sorry, I didn't understand. Could you please repeat that?"
    }
    user_config_cache[user_id] = default_config
    return default_config

# Authentication utilities
def create_jwt_token(user: dict) -> str:
    """Create JWT token for user"""
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'plan': user['plan'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            request.current_user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated_function

# Static File Routes
@app.route('/')
def index():
    """Home page redirect"""
    return redirect('/landing')

@app.route('/landing')
def landing_page():
    """Landing page"""
    try:
        return send_file('landing.html')
    except:
        return "Landing page not found", 404

@app.route('/signup')
def signup_page():
    """Signup page"""
    try:
        return send_file('signup.html')
    except:
        return "Signup page not found", 404

@app.route('/login')
def login_page():
    """Login page"""
    try:
        return send_file('login.html')
    except:
        return "Login page not found", 404

@app.route('/dashboard')
def dashboard_page():
    """Dashboard page"""
    try:
        return send_file('dashboard.html')
    except:
        return "Dashboard not found", 404

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    try:
        return send_from_directory('static', filename)
    except:
        return "File not found", 404

# API Routes
@app.route('/api/health')
def health_check():
    """System health check"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM users')
            user_count = cursor.fetchone()['count']
        
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'PostgreSQL' if db.is_postgres else 'SQLite',
            'services': {
                'openai': bool(services.openai),
                'twilio': bool(services.twilio),
                'email': bool(Config.EMAIL_ADDRESS)
            },
            'stats': {'total_users': user_count}
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """User registration endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if db.get_user_by_email(email):
            return jsonify({'error': 'Email already registered'}), 400
        
        password = str(data['password']).strip()
        is_valid, message = SecurityManager.validate_password(password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Create user
        password_hash = SecurityManager.hash_password(password)
        verification_token = secrets.token_urlsafe(32)
        verification_expiry = datetime.utcnow() + timedelta(hours=24)
        
        user_data = {
            'first_name': str(data['firstName']).strip(),
            'last_name': str(data['lastName']).strip(),
            'email': email,
            'password_hash': password_hash,
            'company': str(data.get('company', '')).strip(),
            'industry': str(data.get('industry', '')).strip(),
            'plan': data.get('plan', 'free'),
            'verification_token': verification_token,
            'verification_expiry': verification_expiry.isoformat(),
            'verified': False
        }
        
        user_id = db.create_user(user_data)
        email_sent = EmailService.send_verification_email(email, user_data['first_name'], verification_token)
        
        return jsonify({
            'success': True,
            'message': 'Account created! Please check your email to verify.',
            'userId': user_id,
            'phoneNumber': SHARED_PHONE_NUMBER,
            'emailSent': email_sent
        })
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """User login endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = db.get_user_by_email(email)
        if not user or not SecurityManager.verify_password(password, user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user['verified']:
            return jsonify({'error': 'Please verify your email first'}), 401
        
        token = create_jwt_token(user)
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user['id'],
                'firstName': user['first_name'],
                'lastName': user['last_name'],
                'email': user['email'],
                'plan': user['plan']
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/verify-email')
def verify_email():
    """Email verification endpoint"""
    token = request.args.get('token')
    if not token:
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="Invalid Verification Link",
            message="The verification link is invalid or missing."
        )
    
    if db.verify_user_email(token):
        return render_template_string(SUCCESS_PAGE_TEMPLATE)
    
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
    """Get user's phone number info"""
    return jsonify({'phone_number': SHARED_PHONE_NUMBER})

@app.route('/active_calls')
def active_calls():
    """Get active call sessions"""
    try:
        calls = db.get_active_calls()
        
        formatted_calls = []
        for call in calls:
            conversation_history = json.loads(call.get('conversation_history', '[]'))
            started_at = call['started_at']
            if isinstance(started_at, str):
                started_at = datetime.fromisoformat(started_at).timestamp()
            elif hasattr(started_at, 'timestamp'):
                started_at = started_at.timestamp()
            
            formatted_calls.append({
                'call_sid': call['call_sid'],
                'started_at': started_at,
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
        call = db.get_call_by_sid(call_sid)
        if not call:
            return jsonify({'error': 'Call not found'}), 404
        
        conversation_history = json.loads(call.get('conversation_history', '[]'))
        
        return jsonify({
            'call_sid': call['call_sid'],
            'started_at': call['started_at'],
            'conversation_history': conversation_history,
            'status': call['status']
        })
    except Exception as e:
        logger.error(f"Error fetching call summary: {e}")
        return jsonify({'error': 'Failed to fetch call summary'}), 500

@app.route('/update_config', methods=['POST'])
@require_auth
def update_config():
    """Update AI configuration"""
    try:
        data = request.get_json()
        user_id = request.current_user['user_id']
        
        # Update user settings in database
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            if db.is_postgres:
                cursor.execute('''
                    UPDATE users SET settings = %s WHERE id = %s
                ''', (json.dumps(data), user_id))
            else:
                cursor.execute('''
                    UPDATE users SET settings = ? WHERE id = ?
                ''', (json.dumps(data), user_id))
            
            conn.commit()
        
        # Update cache
        user_config_cache[user_id] = data
        
        logger.info(f"Configuration updated for user: {user_id}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({'success': False, 'error': 'Failed to update configuration'}), 500

# Twilio Voice Routes
@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio voice calls"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"Incoming call: {call_sid} from {from_number} to {to_number}")
        
        # Extract routing key from caller's input or use default
        # For now, we'll use a simple approach - the caller will need to provide their routing key
        response = VoiceResponse()
        
        # Ask for routing key
        gather = Gather(
            input='dtmf',
            action=f'/api/twilio/route/{call_sid}',
            method='POST',
            num_digits=8,
            timeout=10
        )
        gather.say("Welcome to Voxcord! Please enter your 8-digit routing key followed by the pound key.")
        response.append(gather)
        
        # Fallback if no input
        response.say("I didn't receive your routing key. Please call back and enter your 8-digit routing key. Goodbye!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Error handling voice call: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, there was an error processing your call. Please try again later.")
        return str(response)

@app.route('/api/twilio/route/<call_sid>', methods=['POST'])
def route_call(call_sid):
    """Route call to appropriate user based on routing key"""
    try:
        routing_key = request.form.get('Digits')
        from_number = request.form.get('From')
        
        if not routing_key or len(routing_key) != 8:
            response = VoiceResponse()
            response.say("Invalid routing key. Please call back with a valid 8-digit routing key. Goodbye!")
            return str(response)
        
        # Find user by routing key
        user = db.get_user_by_routing_key(routing_key)
        
        if not user:
            response = VoiceResponse()
            response.say("Routing key not found. Please check your routing key and try again. Goodbye!")
            return str(response)
        
        # Create call session
        call_data = {
            'call_sid': call_sid,
            'user_id': user['id'],
            'caller_number': from_number,
            'metadata': {
                'routing_key': routing_key,
                'to_number': request.form.get('To')
            }
        }
        
        db.create_call_session(call_data)
        
        # Get user configuration
        config = get_user_config(user['id'])
        
        # Create initial response
        response = VoiceResponse()
        
        greeting = config.get('greeting', DEFAULT_AI_GREETING)
        response.say(greeting, voice=config.get('voice', 'alice'))
        
        # Set up for conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("How can I help you today?", voice=config.get('voice', 'alice'))
        response.append(gather)
        
        # Fallback
        response.say("Thank you for calling. Have a great day!")
        
        logger.info(f"Call routed: {call_sid} to user {user['id']}")
        return str(response)
        
    except Exception as e:
        logger.error(f"Error routing call: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, there was an error routing your call. Please try again later.")
        return str(response)

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
        call = db.get_call_by_sid(call_sid)
        if not call:
            response = VoiceResponse()
            response.say("Sorry, there was an error with your call.")
            return str(response)
        
        user_id = call['user_id']
        conversation_history = json.loads(call.get('conversation_history', '[]'))
        
        # Get user configuration
        config = get_user_config(user_id)
        
        # Generate AI response
        ai_response = AIService.generate_response(speech_result, conversation_history, config)
        
        # Update conversation history
        conversation_history.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': time.time()
        })
        
        # Update database
        db.update_call_conversation(call_sid, conversation_history)
        
        # Create TwiML response
        response = VoiceResponse()
        response.say(ai_response, voice=config.get('voice', 'alice'))
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Is there anything else I can help you with?", voice=config.get('voice', 'alice'))
        response.append(gather)
        
        # Fallback
        response.say("Thank you for calling. Have a great day!")
        
        logger.info(f"Speech processed for call: {call_sid}")
        return str(response)
        
    except Exception as e:
        logger.error(f"Error handling speech input: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, I'm having trouble understanding. Please try again.")
        return str(response)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

# HTML Templates
ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Voxcord</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            margin: 0; 
        }
        .container { 
            background: white; 
            padding: 3rem; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
            max-width: 500px; 
            text-align: center; 
        }
        .error-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #e74c3c; margin-bottom: 1rem; }
        .btn { 
            background: #1e40af; 
            color: white; 
            padding: 1rem 2rem; 
            border: none; 
            border-radius: 8px; 
            text-decoration: none; 
            display: inline-block; 
            margin: 1rem 0.5rem; 
            font-weight: 600; 
        }
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            margin: 0; 
        }
        .container { 
            background: white; 
            padding: 3rem; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
            max-width: 500px; 
            text-align: center; 
        }
        .success-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #10b981; margin-bottom: 1rem; }
        .btn { 
            background: #1e40af; 
            color: white; 
            padding: 1rem 2rem; 
            border: none; 
            border-radius: 8px; 
            text-decoration: none; 
            display: inline-block; 
            margin-top: 1rem; 
            font-weight: 600; 
        }
        .info-box { 
            background: #f0f9ff; 
            padding: 1rem; 
            border-radius: 8px; 
            margin: 1rem 0; 
            border-left: 4px solid #0ea5e9; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Email Verified!</h1>
        <p>Your account has been successfully verified. You can now sign in to your Voxcord dashboard.</p>
        
        <div class="info-box">
            <p><strong>Phone Number:</strong> {{ phone_number }}</p>
            <p><small>Use this number to test your AI assistant</small></p>
        </div>
        
        <a href="/login" class="btn">Sign In to Dashboard</a>
    </div>
</body>
</html>
"""

# WSGI application object for production servers
application = app

if __name__ == '__main__':
    # Development server
    logger.info("Starting Voxcord development server...")
    logger.info(f"Database: {'PostgreSQL' if db.is_postgres else 'SQLite'}")
    logger.info(f"OpenAI: {'Configured' if services.openai else 'Not configured'}")
    logger.info(f"Twilio: {'Configured' if services.twilio else 'Not configured'}")
    logger.info(f"Email: {'Configured' if Config.EMAIL_ADDRESS else 'Not configured'}")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )
