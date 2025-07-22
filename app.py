#!/usr/bin/env python3
"""
Voxcord - Production AI Voice Assistant Platform
Complete authentication system with email verification, OAuth, persistent sessions
Built for Digital Ocean App Platform with PostgreSQL
"""

import os
import hashlib
import secrets
import jwt
import json
import time
import re
import uuid
import smtplib
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlencode, parse_qs
import requests

# Flask and extensions
from flask import Flask, request, jsonify, send_file, send_from_directory, session, redirect, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

# Twilio and OpenAI
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client
from openai import OpenAI

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

# Configuration class
class Config:
    # Core settings
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))
    
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///voxcord.db')
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # Session configuration
    SESSION_TYPE = 'sqlalchemy'
    SESSION_SQLALCHEMY_TABLE = 'user_sessions'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'voxcord:'
    SESSION_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    
    # External APIs
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    
    # Email configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    # OAuth configuration
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    
    # App settings
    PORT = int(os.getenv('PORT', 5000))
    DOMAIN = os.getenv('DOMAIN', 'localhost:5000')
    BASE_URL = f"https://{DOMAIN}" if os.getenv('FLASK_ENV') == 'production' else f"http://{DOMAIN}"

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cors = CORS(app, origins=['*'])

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Session management
app.config['SESSION_SQLALCHEMY'] = db
sess = Session(app)

# Initialize external services
openai_client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None
twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN) if Config.TWILIO_ACCOUNT_SID else None

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    
    # Account status
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    verification_token = db.Column(db.String(255))
    verification_token_expires = db.Column(db.DateTime)
    
    # Subscription
    plan = db.Column(db.String(20), default='free')
    trial_ends_at = db.Column(db.DateTime)
    subscription_status = db.Column(db.String(20), default='active')
    
    # OAuth
    oauth_provider = db.Column(db.String(20))
    oauth_id = db.Column(db.String(100))
    avatar_url = db.Column(db.String(255))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    
    # Settings
    settings = db.Column(db.Text, default='{}')
    
    # Relationships
    phone_numbers = db.relationship('PhoneNumber', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    call_sessions = db.relationship('CallSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_premium(self):
        return self.plan in ['professional', 'enterprise']
    
    def get_settings(self):
        try:
            return json.loads(self.settings) if self.settings else {}
        except:
            return {}
    
    def set_settings(self, settings_dict):
        self.settings = json.dumps(settings_dict)
    
    def generate_verification_token(self):
        self.verification_token = secrets.token_urlsafe(32)
        self.verification_token_expires = datetime.utcnow() + timedelta(hours=24)
        return self.verification_token
    
    def verify_email(self):
        self.is_verified = True
        self.verification_token = None
        self.verification_token_expires = None

class PhoneNumber(db.Model):
    __tablename__ = 'phone_numbers'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    twilio_sid = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CallSession(db.Model):
    __tablename__ = 'call_sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    call_sid = db.Column(db.String(100), unique=True, nullable=False)
    caller_number = db.Column(db.String(20))
    
    # Call details
    status = db.Column(db.String(20), default='active')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # in seconds
    
    # Conversation
    conversation = db.Column(db.Text, default='[]')
    summary = db.Column(db.Text)
    sentiment = db.Column(db.String(20))
    
    # Metadata
    metadata = db.Column(db.Text, default='{}')

class DemoSession(db.Model):
    __tablename__ = 'demo_sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    # Demo data
    business_config = db.Column(db.Text, default='{}')
    conversation = db.Column(db.Text, default='[]')
    messages_count = db.Column(db.Integer, default=0)
    
    # Analytics
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_signup = db.Column(db.Boolean, default=False)

# Security utilities
class SecurityManager:
    @staticmethod
    def hash_password(password):
        """Hash password with salt using PBKDF2"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    @staticmethod
    def verify_password(password, stored_hash):
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(':', 1)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return password_hash.hex() == hash_value
        except:
            return False
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
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
        return True, "Password is strong"

# JWT utilities
def create_jwt_token(user, expires_in=24):
    """Create JWT token for user"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'plan': user.plan,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=expires_in)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def decode_jwt_token(token):
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Authentication decorators
def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get user from database
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            return jsonify({'error': 'User not found or inactive'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function

def verified_required(f):
    """Require user to have verified email"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(request, 'current_user') or not request.current_user.is_verified:
            return jsonify({'error': 'Email verification required'}), 403
        return f(*args, **kwargs)
    
    return decorated_function

# Email service
class EmailService:
    @staticmethod
    def send_email(to_email, subject, html_body, text_body=None):
        """Send email via SMTP"""
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            logger.warning("Email service not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = Config.MAIL_DEFAULT_SENDER
            msg['To'] = to_email
            
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
                if Config.MAIL_USE_TLS:
                    server.starttls()
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    @staticmethod
    def send_verification_email(user, token):
        """Send email verification"""
        verification_url = f"{Config.BASE_URL}/verify-email?token={token}"
        
        subject = f"Welcome to Voxcord - Verify Your Email"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Verify Your Email - Voxcord</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 0; background-color: #f8fafc; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07); }}
                .header {{ background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 2rem; text-align: center; }}
                .content {{ padding: 2rem; }}
                .button {{ display: inline-block; background: #3b82f6; color: white; padding: 1rem 2rem; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 1rem 0; }}
                .footer {{ background: #f8fafc; padding: 1rem; text-align: center; color: #6b7280; font-size: 0.875rem; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Welcome to Voxcord!</h1>
                    <p>AI Voice Assistant Platform</p>
                </div>
                <div class="content">
                    <h2>Hi {user.first_name},</h2>
                    <p>Thanks for signing up for Voxcord! To complete your registration and start using your AI voice assistant, please verify your email address:</p>
                    <div style="text-align: center; margin: 2rem 0;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </div>
                    <p>If you can't click the button, copy this link: <br>{verification_url}</p>
                    <p><strong>This link expires in 24 hours.</strong></p>
                    <p>Once verified, you'll get access to:</p>
                    <ul>
                        <li>🤖 AI-powered voice assistant</li>
                        <li>📞 Your dedicated phone number</li>
                        <li>📊 Real-time call analytics</li>
                        <li>🎯 Custom business training</li>
                    </ul>
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
        
        Hi {user.first_name},
        
        Thanks for signing up for Voxcord! To verify your email address, please visit:
        {verification_url}
        
        This link will expire in 24 hours.
        
        Best regards,
        The Voxcord Team
        """
        
        return EmailService.send_email(user.email, subject, html_body, text_body)

# OAuth providers
class OAuthProvider:
    @staticmethod
    def get_google_oauth_url(state):
        """Generate Google OAuth URL"""
        if not Config.GOOGLE_CLIENT_ID:
            return None
        
        params = {
            'client_id': Config.GOOGLE_CLIENT_ID,
            'redirect_uri': f"{Config.BASE_URL}/auth/google/callback",
            'scope': 'openid email profile',
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    
    @staticmethod
    def get_github_oauth_url(state):
        """Generate GitHub OAuth URL"""
        if not Config.GITHUB_CLIENT_ID:
            return None
        
        params = {
            'client_id': Config.GITHUB_CLIENT_ID,
            'redirect_uri': f"{Config.BASE_URL}/auth/github/callback",
            'scope': 'user:email',
            'state': state
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    @staticmethod
    def exchange_google_code(code):
        """Exchange Google OAuth code for user info"""
        try:
            # Exchange code for token
            token_data = {
                'client_id': Config.GOOGLE_CLIENT_ID,
                'client_secret': Config.GOOGLE_CLIENT_SECRET,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': f"{Config.BASE_URL}/auth/google/callback"
            }
            
            response = requests.post('https://oauth2.googleapis.com/token', data=token_data, timeout=10)
            response.raise_for_status()
            token_info = response.json()
            
            # Get user info
            headers = {'Authorization': f"Bearer {token_info['access_token']}"}
            user_response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers, timeout=10)
            user_response.raise_for_status()
            
            return user_response.json()
        except Exception as e:
            logger.error(f"Google OAuth error: {e}")
            return None
    
    @staticmethod
    def exchange_github_code(code):
        """Exchange GitHub OAuth code for user info"""
        try:
            # Exchange code for token
            token_data = {
                'client_id': Config.GITHUB_CLIENT_ID,
                'client_secret': Config.GITHUB_CLIENT_SECRET,
                'code': code
            }
            
            headers = {'Accept': 'application/json'}
            response = requests.post('https://github.com/login/oauth/access_token', data=token_data, headers=headers, timeout=10)
            response.raise_for_status()
            token_info = response.json()
            
            # Get user info
            headers = {'Authorization': f"token {token_info['access_token']}"}
            user_response = requests.get('https://api.github.com/user', headers=headers, timeout=10)
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Get email (GitHub doesn't always include it in /user)
            email_response = requests.get('https://api.github.com/user/emails', headers=headers, timeout=10)
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((e['email'] for e in emails if e['primary']), user_data.get('email'))
                if primary_email:
                    user_data['email'] = primary_email
            
            return user_data
        except Exception as e:
            logger.error(f"GitHub OAuth error: {e}")
            return None

# Phone number management
class PhoneNumberManager:
    @staticmethod
    def assign_phone_number(user):
        """Assign phone number to user"""
        # For now, everyone gets the same shared number
        shared_number = "+16095073300"
        
        # Check if user already has this number
        existing = PhoneNumber.query.filter_by(
            user_id=user.id, 
            phone_number=shared_number
        ).first()
        
        if not existing:
            phone_number = PhoneNumber(
                user_id=user.id,
                phone_number=shared_number,
                is_active=True
            )
            db.session.add(phone_number)
            db.session.commit()
        
        return shared_number

# Routes
@app.route('/')
def index():
    """Serve landing page"""
    try:
        return send_file('landing.html')
    except:
        return jsonify({'message': 'Voxcord API is running', 'status': 'healthy'})

@app.route('/signup')
def signup_page():
    return send_file('signup.html')

@app.route('/login')
def login_page():
    return send_file('login.html')

@app.route('/dashboard')
def dashboard_page():
    # No authentication required here - the frontend will handle it
    return send_file('dashboard.html')

@app.route('/verify-email')
def verify_email_page():
    """Email verification page"""
    token = request.args.get('token')
    
    if not token:
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="Invalid Verification Link",
            message="The verification link is invalid or missing."
        )
    
    # Find user by verification token
    user = User.query.filter_by(verification_token=token).first()
    
    if not user or not user.verification_token_expires or user.verification_token_expires < datetime.utcnow():
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="Verification Failed",
            message="This verification link is invalid or has expired."
        )
    
    # Verify user
    user.verify_email()
    db.session.commit()
    
    # Assign phone number
    phone_number = PhoneNumberManager.assign_phone_number(user)
    
    logger.info(f"Email verified for user: {user.email}")
    
    return render_template_string(SUCCESS_PAGE_TEMPLATE,
        user_name=user.first_name,
        plan=user.plan.title(),
        phone_number=phone_number
    )

# API Routes
@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
        user_count = User.query.count()
    except Exception as e:
        db_status = f'error: {str(e)}'
        user_count = 0
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0',
        'database': db_status,
        'users': user_count,
        'services': {
            'openai': bool(openai_client),
            'twilio': bool(twilio_client),
            'email': bool(Config.MAIL_USERNAME)
        }
    })
# Continued from Part 1...

# Authentication API Routes
@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("5 per minute")
def api_signup():
    """User registration with email verification"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['firstName', 'lastName', 'email', 'password']
        for field in required:
            if not data.get(field, '').strip():
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Validate email format
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'An account with this email already exists'}), 400
        
        # Validate password
        is_valid, message = SecurityManager.validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Create user
        user = User(
            email=email,
            password_hash=SecurityManager.hash_password(data['password']),
            first_name=data['firstName'].strip(),
            last_name=data['lastName'].strip(),
            company=data.get('company', '').strip(),
            phone=data.get('phone', '').strip(),
            plan=data.get('plan', 'free')
        )
        
        # Generate verification token
        verification_token = user.generate_verification_token()
        
        # Set trial period for paid plans
        if user.plan in ['professional', 'enterprise']:
            user.trial_ends_at = datetime.utcnow() + timedelta(days=14)
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        email_sent = EmailService.send_verification_email(user, verification_token)
        
        logger.info(f"User registered: {email} - Plan: {user.plan}")
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully! Please check your email to verify your account.',
            'userId': user.id,
            'emailSent': email_sent
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    """User login with session creation"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        if not user or not SecurityManager.verify_password(password, user.password_hash):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if user is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Check email verification for new accounts
        if not user.is_verified and user.created_at > datetime.utcnow() - timedelta(hours=1):
            return jsonify({
                'error': 'Please verify your email address before signing in',
                'needsVerification': True
            }), 403
        
        # Auto-verify old accounts that weren't verified
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()
        
        # Update last login
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        
        # Create session
        session.permanent = True
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['logged_in_at'] = datetime.utcnow().isoformat()
        
        # Assign phone number if not exists
        phone_number = PhoneNumberManager.assign_phone_number(user)
        
        logger.info(f"User logged in: {email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'fullName': user.full_name,
                'company': user.company,
                'plan': user.plan,
                'isVerified': user.is_verified,
                'isPremium': user.is_premium,
                'phoneNumber': phone_number,
                'avatarUrl': user.avatar_url
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """User logout"""
    try:
        user_email = session.get('user_email', 'unknown')
        session.clear()
        logger.info(f"User logged out: {user_email}")
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    user = request.current_user
    phone_number = PhoneNumberManager.assign_phone_number(user)
    
    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'fullName': user.full_name,
            'company': user.company,
            'plan': user.plan,
            'isVerified': user.is_verified,
            'isPremium': user.is_premium,
            'phoneNumber': phone_number,
            'avatarUrl': user.avatar_url,
            'createdAt': user.created_at.isoformat(),
            'lastLoginAt': user.last_login_at.isoformat() if user.last_login_at else None
        }
    })

# OAuth Routes
@app.route('/api/auth/oauth/<provider>')
def oauth_login(provider):
    """Initiate OAuth login"""
    if provider not in ['google', 'github']:
        return jsonify({'error': 'Unsupported OAuth provider'}), 400
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oauth_provider'] = provider
    
    if provider == 'google':
        auth_url = OAuthProvider.get_google_oauth_url(state)
    elif provider == 'github':
        auth_url = OAuthProvider.get_github_oauth_url(state)
    
    if not auth_url:
        return jsonify({'error': f'{provider.title()} OAuth not configured'}), 500
    
    return jsonify({'authUrl': auth_url})

@app.route('/auth/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    try:
        # Verify state parameter
        state = request.args.get('state')
        if not state or state != session.get('oauth_state'):
            return render_template_string(ERROR_PAGE_TEMPLATE,
                title="OAuth Error",
                message="Invalid state parameter. Please try again."
            )
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            error = request.args.get('error', 'Unknown error')
            return render_template_string(ERROR_PAGE_TEMPLATE,
                title="OAuth Error",
                message=f"Authorization failed: {error}"
            )
        
        # Exchange code for user info
        if provider == 'google':
            user_data = OAuthProvider.exchange_google_code(code)
        elif provider == 'github':
            user_data = OAuthProvider.exchange_github_code(code)
        else:
            return render_template_string(ERROR_PAGE_TEMPLATE,
                title="OAuth Error",
                message="Unsupported OAuth provider"
            )
        
        if not user_data or not user_data.get('email'):
            return render_template_string(ERROR_PAGE_TEMPLATE,
                title="OAuth Error",
                message="Failed to get user information from OAuth provider"
            )
        
        email = user_data['email'].lower().strip()
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info for existing user
            user.oauth_provider = provider
            user.oauth_id = str(user_data.get('id', ''))
            user.avatar_url = user_data.get('picture') or user_data.get('avatar_url')
            user.is_verified = True  # OAuth users are auto-verified
            user.last_login_at = datetime.utcnow()
        else:
            # Create new user from OAuth
            name_parts = user_data.get('name', '').split(' ', 1)
            first_name = name_parts[0] if name_parts else user_data.get('given_name', email.split('@')[0])
            last_name = name_parts[1] if len(name_parts) > 1 else user_data.get('family_name', '')
            
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                oauth_provider=provider,
                oauth_id=str(user_data.get('id', '')),
                avatar_url=user_data.get('picture') or user_data.get('avatar_url'),
                is_verified=True,
                plan='free'
            )
            db.session.add(user)
            logger.info(f"New OAuth user created: {email} via {provider}")
        
        db.session.commit()
        
        # Create session
        session.permanent = True
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['logged_in_at'] = datetime.utcnow().isoformat()
        
        # Clear OAuth session data
        session.pop('oauth_state', None)
        session.pop('oauth_provider', None)
        
        # Assign phone number
        PhoneNumberManager.assign_phone_number(user)
        
        # Redirect to dashboard with success message
        return redirect('/dashboard?oauth=success')
        
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="OAuth Error",
            message="Authentication failed. Please try again."
        )

# Resend verification email
@app.route('/api/auth/resend-verification', methods=['POST'])
@limiter.limit("3 per hour")
def resend_verification():
    """Resend verification email"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            # Don't reveal if email exists
            return jsonify({'success': True, 'message': 'If the email exists, a verification link has been sent.'})
        
        if user.is_verified:
            return jsonify({'error': 'Email is already verified'}), 400
        
        # Generate new verification token
        verification_token = user.generate_verification_token()
        db.session.commit()
        
        # Send verification email
        EmailService.send_verification_email(user, verification_token)
        
        return jsonify({
            'success': True,
            'message': 'Verification email sent successfully'
        })
        
    except Exception as e:
        logger.error(f"Resend verification error: {str(e)}")
        return jsonify({'error': 'Failed to send verification email'}), 500

# User settings and profile
@app.route('/api/user/settings', methods=['GET', 'POST'])
@login_required
@verified_required
def user_settings():
    """Get or update user settings"""
    user = request.current_user
    
    if request.method == 'GET':
        settings = user.get_settings()
        return jsonify({
            'settings': settings,
            'profile': {
                'firstName': user.first_name,
                'lastName': user.last_name,
                'company': user.company,
                'phone': user.phone
            }
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Update profile fields
            if 'profile' in data:
                profile = data['profile']
                if 'firstName' in profile:
                    user.first_name = profile['firstName'].strip()
                if 'lastName' in profile:
                    user.last_name = profile['lastName'].strip()
                if 'company' in profile:
                    user.company = profile['company'].strip()
                if 'phone' in profile:
                    user.phone = profile['phone'].strip()
            
            # Update settings
            if 'settings' in data:
                current_settings = user.get_settings()
                current_settings.update(data['settings'])
                user.set_settings(current_settings)
            
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Settings updated successfully'})
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Settings update error: {str(e)}")
            return jsonify({'error': 'Failed to update settings'}), 500

# Call management
@app.route('/api/calls')
@login_required
@verified_required
def get_calls():
    """Get user's call history"""
    user = request.current_user
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    calls = CallSession.query.filter_by(user_id=user.id)\
        .order_by(CallSession.started_at.desc())\
        .paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
    
    call_list = []
    for call in calls.items:
        try:
            conversation = json.loads(call.conversation) if call.conversation else []
            preview = conversation[-1].get('user', 'No conversation') if conversation else 'No conversation'
        except:
            preview = 'Invalid conversation data'
        
        call_list.append({
            'id': call.id,
            'callSid': call.call_sid,
            'callerNumber': call.caller_number,
            'status': call.status,
            'startedAt': call.started_at.isoformat(),
            'endedAt': call.ended_at.isoformat() if call.ended_at else None,
            'duration': call.duration,
            'preview': preview,
            'summary': call.summary,
            'sentiment': call.sentiment
        })
    
    return jsonify({
        'calls': call_list,
        'pagination': {
            'page': calls.page,
            'pages': calls.pages,
            'perPage': calls.per_page,
            'total': calls.total,
            'hasNext': calls.has_next,
            'hasPrev': calls.has_prev
        }
    })

@app.route('/api/calls/<call_id>')
@login_required
@verified_required
def get_call_details(call_id):
    """Get detailed call information"""
    user = request.current_user
    
    call = CallSession.query.filter_by(id=call_id, user_id=user.id).first()
    if not call:
        return jsonify({'error': 'Call not found'}), 404
    
    try:
        conversation = json.loads(call.conversation) if call.conversation else []
        metadata = json.loads(call.metadata) if call.metadata else {}
    except:
        conversation = []
        metadata = {}
    
    return jsonify({
        'call': {
            'id': call.id,
            'callSid': call.call_sid,
            'callerNumber': call.caller_number,
            'status': call.status,
            'startedAt': call.started_at.isoformat(),
            'endedAt': call.ended_at.isoformat() if call.ended_at else None,
            'duration': call.duration,
            'conversation': conversation,
            'summary': call.summary,
            'sentiment': call.sentiment,
            'metadata': metadata
        }
    })

# Analytics
@app.route('/api/analytics/overview')
@login_required
@verified_required
def analytics_overview():
    """Get analytics overview for user"""
    user = request.current_user
    
    # Get date range (default to last 30 days)
    days = request.args.get('days', 30, type=int)
    since = datetime.utcnow() - timedelta(days=days)
    
    # Basic stats
    total_calls = CallSession.query.filter_by(user_id=user.id).count()
    recent_calls = CallSession.query.filter(
        CallSession.user_id == user.id,
        CallSession.started_at >= since
    ).count()
    
    # Average call duration
    avg_duration_result = db.session.query(
        db.func.avg(CallSession.duration)
    ).filter(
        CallSession.user_id == user.id,
        CallSession.duration.isnot(None)
    ).scalar()
    
    avg_duration = int(avg_duration_result or 0)
    
    # Success rate (calls that weren't hung up immediately)
    successful_calls = CallSession.query.filter(
        CallSession.user_id == user.id,
        CallSession.duration > 10  # More than 10 seconds
    ).count()
    
    success_rate = (successful_calls / total_calls * 100) if total_calls > 0 else 0
    
    return jsonify({
        'overview': {
            'totalCalls': total_calls,
            'recentCalls': recent_calls,
            'avgDuration': avg_duration,
            'successRate': round(success_rate, 1)
        },
        'period': {
            'days': days,
            'since': since.isoformat()
        }
    })

# Demo API (for landing page)
@app.route('/api/demo/chat', methods=['POST'])
@limiter.limit("20 per hour")
def demo_chat():
    """Handle demo chat from landing page"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        business_config = data.get('config', {})
        conversation_history = data.get('conversationHistory', [])
        
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Track demo usage
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Generate AI response
        try:
            ai_response = generate_demo_ai_response(user_message, business_config, conversation_history)
        except Exception as e:
            logger.error(f"Demo AI response error: {e}")
            ai_response = generate_fallback_response(user_message, business_config)
        
        # Store demo session for analytics
        try:
            demo_session = DemoSession(
                session_ip=client_ip,
                user_agent=user_agent,
                business_config=json.dumps(business_config),
                conversation=json.dumps(conversation_history + [
                    {'role': 'user', 'content': user_message},
                    {'role': 'assistant', 'content': ai_response}
                ]),
                messages_count=len(conversation_history) + 2
            )
            db.session.add(demo_session)
            db.session.commit()
        except Exception as e:
            logger.warning(f"Demo session tracking failed: {e}")
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Demo chat error: {e}")
        return jsonify({'error': 'Demo temporarily unavailable'}), 500

def generate_demo_ai_response(user_message, business_config, conversation_history):
    """Generate AI response for demo using OpenAI"""
    if not openai_client:
        return generate_fallback_response(user_message, business_config)
    
    try:
        business_name = business_config.get('businessName', 'our company')
        business_type = business_config.get('businessType', 'business')
        business_hours = business_config.get('businessHours', 'regular business hours')
        instructions = business_config.get('instructions', '')
        
        system_prompt = f"""You are a professional AI customer service assistant for {business_name}, a {business_type}.

Business Details:
- Company: {business_name}
- Type: {business_type}  
- Hours: {business_hours}
- Instructions: {instructions}

Your role:
- Provide helpful, friendly customer service
- Keep responses conversational and under 100 words
- Reference the business naturally
- Ask clarifying questions when needed
- Offer to escalate to humans when appropriate

Be professional, empathetic, and solution-focused."""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        for exchange in conversation_history[-6:]:
            if exchange.get('role') and exchange.get('content'):
                messages.append({
                    "role": exchange['role'],
                    "content": exchange['content']
                })
        
        messages.append({"role": "user", "content": user_message})
        
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=150,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"OpenAI demo error: {e}")
        return generate_fallback_response(user_message, business_config)

def generate_fallback_response(user_message, business_config):
    """Generate fallback response when OpenAI isn't available"""
    business_name = business_config.get('businessName', 'our company')
    business_type = business_config.get('businessType', 'business')
    business_hours = business_config.get('businessHours', 'regular business hours')
    
    message_lower = user_message.lower()
    
    responses = {
        'greeting': f"Hello! Welcome to {business_name}, your {business_type}. I'm here to help with any questions. What can I assist you with today?",
        'hours': f"{business_name} operates during {business_hours}. You can reach us anytime through this AI assistant. What information do you need?",
        'pricing': f"I'd be happy to help with pricing information for {business_name}. For specific quotes, I can connect you with our team. What service interests you?",
        'support': f"I'm here to help with any {business_name} related questions. I can provide information and help resolve common issues. What do you need assistance with?",
        'services': f"{business_name} specializes in {business_type} services. I can provide general information about our offerings. What specific service would you like to know about?",
        'contact': f"You can contact {business_name} during {business_hours}. I'm available 24/7 for basic questions. How can I help you today?",
        'default': f"Thank you for contacting {business_name}! I understand you're asking about: \"{user_message}\". I'm here to help with information about our {business_type} services. Could you tell me more about what you need?"
    }
    
    if any(word in message_lower for word in ['hello', 'hi', 'hey']):
        return responses['greeting']
    elif any(word in message_lower for word in ['hours', 'open', 'time']):
        return responses['hours']
    elif any(word in message_lower for word in ['price', 'cost', 'how much']):
        return responses['pricing']
    elif any(word in message_lower for word in ['help', 'support', 'problem']):
        return responses['support']
    elif any(word in message_lower for word in ['service', 'offer', 'what do you']):
        return responses['services']
    elif any(word in message_lower for word in ['contact', 'phone', 'reach']):
        return responses['contact']
    else:
        return responses['default']

# Continue with Twilio webhook routes...

# Twilio Voice Webhooks
@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio voice calls"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"Incoming call: {call_sid} from {from_number} to {to_number}")
        
        # Create call session
        call_session = CallSession(
            call_sid=call_sid,
            caller_number=from_number,
            status='active'
        )
        db.session.add(call_session)
        db.session.commit()
        
        # Generate TwiML response
        response = VoiceResponse()
        
        # Default greeting
        greeting = "Hello! Thank you for calling Voxcord. I'm your AI assistant, ready to help. How can I assist you today?"
        response.say(greeting, voice='Polly.Joanna', language='en-US')
        
        # Gather speech input
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US',
            timeout=10
        )
        gather.say("Please tell me what you need help with.", voice='Polly.Joanna')
        response.append(gather)
        
        # Fallback if no input
        response.say("I didn't hear anything. Please call back when you're ready. Thank you!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Voice call error: {e}")
        
        # Always return valid TwiML
        response = VoiceResponse()
        response.say("I'm sorry, there was a technical issue. Please try calling back.")
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
            gather.say("I didn't catch that. Could you please repeat?", voice='Polly.Joanna')
            response.append(gather)
            return str(response)
        
        # Get call session
        call_session = CallSession.query.filter_by(call_sid=call_sid).first()
        if not call_session:
            response = VoiceResponse()
            response.say("Sorry, there was an error with your call.")
            return str(response)
        
        # Get conversation history
        try:
            conversation = json.loads(call_session.conversation) if call_session.conversation else []
        except:
            conversation = []
        
        # Generate AI response
        ai_response = generate_voice_ai_response(speech_result, conversation)
        
        # Update conversation
        conversation.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': time.time()
        })
        
        call_session.conversation = json.dumps(conversation)
        db.session.commit()
        
        # Create TwiML response
        response = VoiceResponse()
        response.say(ai_response, voice='Polly.Joanna', language='en-US')
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US',
            timeout=10
        )
        gather.say("Is there anything else I can help you with?", voice='Polly.Joanna')
        response.append(gather)
        
        # End call option
        response.say("Thank you for calling. Have a great day!", voice='Polly.Joanna')
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble understanding. Please try again.", voice='Polly.Joanna')
        return str(response)

def generate_voice_ai_response(user_input, conversation_history):
    """Generate AI response for voice calls"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Build context for phone conversation
        messages = [
            {
                "role": "system",
                "content": "You are a helpful customer service assistant. Be friendly, professional, and concise. Keep responses under 50 words for phone conversations. Ask clarifying questions when needed."
            }
        ]
        
        # Add recent conversation history
        for exchange in conversation_history[-3:]:
            messages.append({"role": "user", "content": exchange['user']})
            messages.append({"role": "assistant", "content": exchange['assistant']})
        
        # Add current input
        messages.append({"role": "user", "content": user_input})
        
        # Generate response
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=100,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Voice AI response error: {e}")
        return "I apologize, but I'm having trouble processing your request right now. Could you please try again?"

# Static file serving
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    try:
        return send_from_directory('static', filename)
    except:
        return "File not found", 404

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Request too large'}), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': e.retry_after}), 429

# Template constants for email verification pages
ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Voxcord</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            margin: 0; 
            padding: 20px;
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
        h1 { color: #ef4444; margin-bottom: 1rem; font-size: 1.5rem; }
        p { color: #6b7280; margin-bottom: 2rem; line-height: 1.6; }
        .btn { 
            background: #3b82f6; 
            color: white; 
            padding: 1rem 2rem; 
            border: none; 
            border-radius: 8px; 
            text-decoration: none; 
            display: inline-block; 
            margin: 0.5rem; 
            font-weight: 600; 
            transition: all 0.2s ease;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
        .btn-secondary { background: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>{{ title }}</h1>
        <p>{{ message }}</p>
        <a href="/login" class="btn">Back to Login</a>
        <a href="/signup" class="btn btn-secondary">Sign Up</a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Verified - Voxcord</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            margin: 0; 
            padding: 20px;
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
        h1 { color: #10b981; margin-bottom: 1rem; font-size: 1.5rem; }
        p { color: #6b7280; margin-bottom: 1rem; line-height: 1.6; }
        .info-box { 
            background: #f0f9ff; 
            padding: 1rem; 
            border-radius: 8px; 
            margin: 1rem 0; 
            border-left: 4px solid #0ea5e9; 
        }
        .btn { 
            background: #3b82f6; 
            color: white; 
            padding: 1rem 2rem; 
            border: none; 
            border-radius: 8px; 
            text-decoration: none; 
            display: inline-block; 
            margin-top: 1rem; 
            font-weight: 600; 
            transition: all 0.2s ease;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
        .countdown { color: #8b5cf6; font-weight: 600; }
    </style>
    <script>
        let countdown = 3;
        function updateCountdown() {
            const element = document.getElementById('countdown');
            if (element && countdown > 0) {
                element.textContent = countdown;
                countdown--;
                setTimeout(updateCountdown, 1000);
            } else {
                window.location.href = '/dashboard';
            }
        }
        setTimeout(updateCountdown, 1000);
    </script>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Email Verified!</h1>
        <p>Welcome to Voxcord, {{ user_name }}!</p>
        
        <div class="info-box">
            <p><strong>Plan:</strong> {{ plan }}</p>
            <p><strong>Phone Number:</strong> {{ phone_number }}</p>
        </div>
        
        <p>Your account is now active. Redirecting to dashboard in <span id="countdown" class="countdown">3</span> seconds...</p>
        <a href="/dashboard" class="btn">Go to Dashboard Now</a>
    </div>
</body>
</html>
"""

# Initialize database tables
def init_db():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Validate required environment variables
    if not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY not set - AI responses will be limited")
    
    if not Config.MAIL_USERNAME:
        logger.warning("Email service not configured - verification emails will not be sent")
    
    logger.info("Starting Voxcord production server...")
    logger.info(f"Database: {Config.DATABASE_URL}")
    logger.info(f"Email service: {'Configured' if Config.MAIL_USERNAME else 'Not configured'}")
    logger.info(f"OAuth providers: Google {'✓' if Config.GOOGLE_CLIENT_ID else '✗'}, GitHub {'✓' if Config.GITHUB_CLIENT_ID else '✗'}")
    
    app.run(
        host='0.0.0.0', 
        port=Config.PORT, 
        debug=os.getenv('FLASK_ENV') != 'production'
    )
