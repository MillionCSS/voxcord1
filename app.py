# app.py - Make sure your Flask app is properly exposed

import os
import json
import uuid
import time
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, send_from_directory
from twilio.twiml.voice_response import VoiceResponse, Gather
from openai import OpenAI
import hashlib
import secrets
import jwt
import re

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app - CRITICAL: This must be named 'app' for Digital Ocean
app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    DATABASE_URL = os.getenv('DATABASE_URL')
    PORT = int(os.getenv('PORT', 8080))  # Digital Ocean uses 8080 by default
    WEBHOOK_BASE_URL = os.getenv('WEBHOOK_BASE_URL', 'https://voxcord.com')

app.config['SECRET_KEY'] = Config.SECRET_KEY

logger.info("Starting Voxcord application...")
logger.info(f"Port: {Config.PORT}")
logger.info(f"Database URL set: {bool(Config.DATABASE_URL)}")
logger.info(f"OpenAI configured: {bool(Config.OPENAI_API_KEY)}")
logger.info(f"Twilio configured: {bool(Config.TWILIO_ACCOUNT_SID and Config.TWILIO_AUTH_TOKEN)}")

# Initialize OpenAI
openai_client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None

# Database Manager - Simplified version for now
class SimpleDatabase:
    def __init__(self):
        if Config.DATABASE_URL:
            logger.info("PostgreSQL database configured")
            self.db_type = 'postgresql'
            # We'll implement PostgreSQL later
        else:
            logger.info("Using SQLite database")
            self.db_type = 'sqlite'
            self.db_path = 'voxcord.db'
        
        self.init_database()
    
    def init_database(self):
        """Initialize database with basic tables"""
        if self.db_type == 'sqlite':
            import sqlite3
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Simple users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        company TEXT DEFAULT '',
                        plan TEXT DEFAULT 'free',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                logger.info("SQLite database initialized")
        else:
            # PostgreSQL initialization will be added later
            logger.info("PostgreSQL initialization skipped for now")

# Initialize database
db = SimpleDatabase()

# Simple security utilities
class SecurityManager:
    @staticmethod
    def hash_password(password):
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    @staticmethod
    def verify_password(password, stored_hash):
        try:
            salt, hash_value = stored_hash.split(':', 1)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return password_hash.hex() == hash_value
        except:
            return False
    
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

# JWT utilities
def create_jwt_token(user):
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'plan': user['plan'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

# CORS handling
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Routes
@app.route('/')
def index():
    """Health check and basic info"""
    return jsonify({
        'message': 'Voxcord API is running',
        'status': 'healthy',
        'version': '2.0.0',
        'database': db.db_type,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/health')
def health_check():
    """Digital Ocean health check endpoint"""
    try:
        # Test database connection
        if db.db_type == 'sqlite':
            import sqlite3
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db.db_type,
            'services': {
                'openai': bool(openai_client),
                'database': True
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/signup')
def signup_page():
    try:
        return send_file('signup.html')
    except:
        return jsonify({'error': 'Signup page not found'}), 404

@app.route('/login')
def login_page():
    try:
        return send_file('login.html')
    except:
        return jsonify({'error': 'Login page not found'}), 404

@app.route('/dashboard')
def dashboard_page():
    try:
        return send_file('dashboard.html')
    except:
        return jsonify({'error': 'Dashboard not found'}), 404

@app.route('/static/<path:filename>')
def static_files(filename):
    try:
        return send_from_directory('static', filename)
    except:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Simple signup endpoint"""
    try:
        data = request.get_json()
        logger.info(f"Signup attempt: {data.get('email', 'no-email')}")
        
        # Basic validation
        required = ['firstName', 'lastName', 'email', 'password']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # For now, just return success (we'll add real database later)
        user_id = str(uuid.uuid4())
        
        logger.info(f"Signup successful: {email}")
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'token': 'demo-token-' + user_id,
            'user': {
                'id': user_id,
                'firstName': data['firstName'],
                'lastName': data['lastName'],
                'email': email,
                'plan': data.get('plan', 'free')
            }
        })
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """Simple login endpoint"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        logger.info(f"Login attempt: {email}")
        
        # For demo, accept any email/password combination
        if email and password and len(password) >= 6:
            user_id = str(uuid.uuid4())
            
            return jsonify({
                'success': True,
                'token': 'demo-token-' + user_id,
                'user': {
                    'id': user_id,
                    'firstName': email.split('@')[0],
                    'lastName': 'User',
                    'email': email,
                    'plan': 'free'
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

# Basic Twilio webhook
@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Basic Twilio voice webhook"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        
        logger.info(f"Voice call: {call_sid} from {from_number}")
        
        response = VoiceResponse()
        response.say("Hello! Welcome to Voxcord. This is a test call. Thank you!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Voice call error: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, there was a technical issue.")
        return str(response)

# Debug routes
@app.route('/debug/env')
def debug_env():
    """Debug environment variables"""
    return jsonify({
        'PORT': os.getenv('PORT', 'not set'),
        'DATABASE_URL': 'set' if os.getenv('DATABASE_URL') else 'not set',
        'OPENAI_API_KEY': 'set' if os.getenv('OPENAI_API_KEY') else 'not set',
        'SECRET_KEY': 'set' if os.getenv('SECRET_KEY') else 'not set',
        'WEBHOOK_BASE_URL': os.getenv('WEBHOOK_BASE_URL', 'not set'),
        'app_name': 'voxcord',
        'flask_version': '3.0.0'
    })

@app.route('/debug/test')
def debug_test():
    """Test basic functionality"""
    return jsonify({
        'status': 'working',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'If you see this, the app is running correctly!'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# CRITICAL: This is what Digital Ocean looks for
if __name__ == '__main__':
    logger.info(f"Starting Voxcord on port {Config.PORT}")
    app.run(host='0.0.0.0', port=Config.PORT, debug=False)

# ALSO CRITICAL: Export the app for gunicorn
application = app  # This allows gunicorn to find the app
