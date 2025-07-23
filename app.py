#!/usr/bin/env python3
"""
Voxcord - AI Voice Assistant Platform
Enhanced version with phone number provisioning and AI customization
"""

import os
import hashlib
import secrets
import jwt
import json
import uuid
import time
import re
import logging
from datetime import datetime, timedelta
from functools import wraps

# Flask and extensions
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# External services
import httpx
from openai import OpenAI
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client
from sqlalchemy import text, func

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    
    # Database - Handle both PostgreSQL and SQLite
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///voxcord.db')
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20
    }
    
    # External APIs
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    
    # App settings
    PORT = int(os.getenv('PORT', 5000))

# =============================================================================
# APP INITIALIZATION
# =============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cors = CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# =============================================================================
# EXTERNAL SERVICES INITIALIZATION
# =============================================================================

def initialize_openai():
    """Initialize OpenAI client safely"""
    if not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY not set")
        return None
    
    try:
        # Clear proxy environment variables
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']:
            os.environ.pop(var, None)
        
        # Use httpx client with no proxies
        http_client = httpx.Client(proxies=None, timeout=30.0)
        client = OpenAI(api_key=Config.OPENAI_API_KEY, http_client=http_client)
        
        logger.info("✅ OpenAI client initialized")
        return client
    except Exception as e:
        logger.error(f"❌ OpenAI initialization failed: {e}")
        return None

# Initialize clients
openai_client = initialize_openai()
twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN) if Config.TWILIO_ACCOUNT_SID else None

if twilio_client:
    logger.info("✅ Twilio client initialized")
else:
    logger.warning("⚠️ Twilio not configured")

# =============================================================================
# DATABASE MODELS - Enhanced Schema
# =============================================================================

class User(db.Model):
    __tablename__ = 'vox_users'
    
    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Basic info
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.Text, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(200), default='')
    
    # Account status
    verified = db.Column(db.Boolean, default=True, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Subscription
    plan = db.Column(db.String(50), default='free', nullable=False)
    
    # Usage tracking
    monthly_calls = db.Column(db.Integer, default=0)
    monthly_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    
    # Settings as JSON text
    settings_json = db.Column(db.Text, default='{}')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_premium(self):
        return self.plan in ['professional', 'enterprise']
    
    @property
    def call_limit(self):
        limits = {'free': 100, 'professional': -1, 'enterprise': -1}  # -1 = unlimited
        return limits.get(self.plan, 100)
    
    @property
    def phone_number_limit(self):
        limits = {'free': 1, 'professional': 5, 'enterprise': -1}  # -1 = unlimited
        return limits.get(self.plan, 1)
    
    def reset_monthly_usage_if_needed(self):
        """Reset monthly usage if needed"""
        now = datetime.utcnow()
        if now >= self.monthly_reset_date:
            self.monthly_calls = 0
            # Set next reset date to next month
            if self.monthly_reset_date.month == 12:
                self.monthly_reset_date = self.monthly_reset_date.replace(year=self.monthly_reset_date.year + 1, month=1)
            else:
                self.monthly_reset_date = self.monthly_reset_date.replace(month=self.monthly_reset_date.month + 1)
            db.session.commit()
    
    def can_make_call(self):
        """Check if user can make a call within their limit"""
        self.reset_monthly_usage_if_needed()
        if self.call_limit == -1:  # Unlimited
            return True
        return self.monthly_calls < self.call_limit
    
    def increment_call_count(self):
        """Increment call count"""
        self.monthly_calls += 1
        db.session.commit()
    
    def get_settings(self):
        try:
            return json.loads(self.settings_json) if self.settings_json else {}
        except:
            return {}
    
    def set_settings(self, settings_dict):
        self.settings_json = json.dumps(settings_dict)

class PhoneNumber(db.Model):
    __tablename__ = 'vox_phone_numbers'
    
    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Phone number details
    phone_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    twilio_sid = db.Column(db.String(100), unique=True, nullable=False)
    friendly_name = db.Column(db.String(200))
    
    # Ownership
    user_id = db.Column(db.String(36), db.ForeignKey('vox_users.id'), nullable=False)
    
    # Status
    active = db.Column(db.Boolean, default=True, nullable=False)
    
    # AI Configuration
    ai_name = db.Column(db.String(100), default='Assistant')
    ai_voice = db.Column(db.String(50), default='alloy')  # OpenAI voice ID
    ai_instructions = db.Column(db.Text, default='You are a helpful customer service assistant.')
    business_info = db.Column(db.Text, default='{}')  # JSON with business details
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime)
    
    # Relationship
    user = db.relationship('User', backref='phone_numbers')
    
    def get_business_info(self):
        try:
            return json.loads(self.business_info) if self.business_info else {}
        except:
            return {}
    
    def set_business_info(self, info_dict):
        self.business_info = json.dumps(info_dict)

class CallSession(db.Model):
    __tablename__ = 'vox_calls'
    
    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Call info
    call_sid = db.Column(db.String(100), unique=True, nullable=False)
    caller_number = db.Column(db.String(50))
    phone_number_id = db.Column(db.String(36), db.ForeignKey('vox_phone_numbers.id'))
    user_id = db.Column(db.String(36), db.ForeignKey('vox_users.id'))
    
    # Call details
    status = db.Column(db.String(20), default='active', nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer, default=0)  # seconds
    
    # Conversation data
    conversation_json = db.Column(db.Text, default='[]')
    summary = db.Column(db.Text)
    satisfaction_rating = db.Column(db.Integer)  # 1-5 scale
    
    # Call metadata
    call_data = db.Column(db.Text, default='{}')
    
    # Relationships
    phone_number = db.relationship('PhoneNumber', backref='calls')
    user = db.relationship('User', backref='calls')
    
    def get_conversation(self):
        try:
            return json.loads(self.conversation_json) if self.conversation_json else []
        except:
            return []
    
    def set_conversation(self, conversation_list):
        self.conversation_json = json.dumps(conversation_list)

# =============================================================================
# SECURITY & UTILITIES
# =============================================================================

class SecurityManager:
    @staticmethod
    def hash_password(password):
        """Hash password securely"""
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{pwd_hash.hex()}"
    
    @staticmethod
    def verify_password(password, stored_hash):
        """Verify password"""
        try:
            salt, hash_value = stored_hash.split(':', 1)
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return pwd_hash.hex() == hash_value
        except:
            return False
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email.strip().lower()))

def create_jwt_token(user):
    """Create JWT token"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=30),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        return user if user and user.active else None
    except:
        return None

def login_required(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else ''
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = verify_jwt_token(token)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# TWILIO PHONE NUMBER MANAGEMENT
# =============================================================================

class PhoneNumberManager:
    @staticmethod
    def search_available_numbers(area_code=None, country='US', limit=10):
        """Search for available phone numbers"""
        if not twilio_client:
            return []
        
        try:
            search_params = {
                'country_code': country,
                'voice_enabled': True,
                'sms_enabled': True,
                'limit': limit
            }
            
            if area_code:
                search_params['area_code'] = area_code
            
            available_phone_numbers = twilio_client.available_phone_numbers(country).local.list(**search_params)
            
            return [{
                'phone_number': number.phone_number,
                'friendly_name': number.friendly_name,
                'locality': getattr(number, 'locality', ''),
                'region': getattr(number, 'region', ''),
                'monthly_cost': '1.00'  # Approximate cost
            } for number in available_phone_numbers]
            
        except Exception as e:
            logger.error(f"Error searching phone numbers: {e}")
            return []
    
    @staticmethod
    def purchase_phone_number(phone_number, user_id, friendly_name=None):
        """Purchase a phone number for a user"""
        if not twilio_client:
            return None, "Twilio not configured"
        
        try:
            # Purchase the number
            incoming_phone_number = twilio_client.incoming_phone_numbers.create(
                phone_number=phone_number,
                voice_url=f"{request.host_url}api/twilio/voice",
                voice_method='POST',
                friendly_name=friendly_name or f"Voxcord Line - {phone_number}"
            )
            
            # Save to database
            phone_record = PhoneNumber(
                phone_number=phone_number,
                twilio_sid=incoming_phone_number.sid,
                friendly_name=friendly_name or f"Support Line",
                user_id=user_id
            )
            
            db.session.add(phone_record)
            db.session.commit()
            
            logger.info(f"✅ Phone number purchased: {phone_number} for user {user_id}")
            return phone_record, None
            
        except Exception as e:
            logger.error(f"Error purchasing phone number: {e}")
            return None, str(e)
    
    @staticmethod
    def release_phone_number(phone_number_id, user_id):
        """Release a phone number"""
        if not twilio_client:
            return False, "Twilio not configured"
        
        try:
            # Find the phone number record
            phone_record = PhoneNumber.query.filter_by(
                id=phone_number_id,
                user_id=user_id
            ).first()
            
            if not phone_record:
                return False, "Phone number not found"
            
            # Release from Twilio
            twilio_client.incoming_phone_numbers(phone_record.twilio_sid).delete()
            
            # Remove from database
            db.session.delete(phone_record)
            db.session.commit()
            
            logger.info(f"✅ Phone number released: {phone_record.phone_number}")
            return True, None
            
        except Exception as e:
            logger.error(f"Error releasing phone number: {e}")
            return False, str(e)

# =============================================================================
# STATIC FILE ROUTES (Previous routes remain the same)
# =============================================================================

@app.route('/')
def index():
    """Serve landing page"""
    try:
        return send_from_directory('.', 'landing.html')
    except:
        return jsonify({'message': 'Voxcord API v2.0', 'status': 'running'})

@app.route('/signup')
def signup_page():
    """Serve signup page"""
    try:
        return send_from_directory('.', 'signup.html')
    except:
        return jsonify({'error': 'Signup page not found'}), 404

@app.route('/login')
def login_page():
    """Serve login page"""
    try:
        return send_from_directory('.', 'login.html')
    except:
        return jsonify({'error': 'Login page not found'}), 404

@app.route('/dashboard')
def dashboard_page():
    """Serve dashboard page"""
    try:
        return send_from_directory('.', 'dashboard.html')
    except:
        return jsonify({'error': 'Dashboard not found'}), 404

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    try:
        return send_from_directory('static', filename)
    except:
        return jsonify({'error': 'File not found'}), 404

# =============================================================================
# API ROUTES - AUTHENTICATION (Previous auth routes remain the same)
# =============================================================================

@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("10 per hour")
def signup():
    """User registration - BULLETPROOF"""
    try:
        data = request.get_json() or {}
        logger.info(f"Signup attempt for: {data.get('email', 'unknown')}")
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'password']
        missing_fields = [field for field in required_fields if not data.get(field, '').strip()]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Clean and validate email
        email = data['email'].strip().lower()
        if not SecurityManager.validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({
                'success': False,
                'error': 'An account with this email already exists'
            }), 400
        
        # Validate password
        password = data['password']
        if len(password) < 8:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }), 400
        
        # Create new user
        user = User(
            first_name=data['firstName'].strip(),
            last_name=data['lastName'].strip(),
            email=email,
            password_hash=SecurityManager.hash_password(password),
            company=data.get('company', '').strip(),
            plan=data.get('plan', 'free').strip()
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create token
        token = create_jwt_token(user)
        
        logger.info(f"✅ User registered successfully: {email}")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'fullName': user.full_name,
                'company': user.company,
                'plan': user.plan,
                'isVerified': user.verified,
                'callLimit': user.call_limit,
                'phoneNumberLimit': user.phone_number_limit
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Signup error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Registration failed. Please try again.'
        }), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per hour")
def login():
    """User login - BULLETPROOF"""
    try:
        data = request.get_json() or {}
        logger.info(f"Login attempt for: {data.get('email', 'unknown')}")
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({
                'success': False,
                'error': 'Email and password are required'
            }), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        if not user or not SecurityManager.verify_password(password, user.password_hash):
            return jsonify({
                'success': False,
                'error': 'Invalid email or password'
            }), 401
        
        if not user.active:
            return jsonify({
                'success': False,
                'error': 'Account is deactivated'
            }), 403
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Create token
        token = create_jwt_token(user)
        
        logger.info(f"✅ User logged in: {email}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'fullName': user.full_name,
                'company': user.company,
                'plan': user.plan,
                'isVerified': user.verified,
                'callLimit': user.call_limit,
                'phoneNumberLimit': user.phone_number_limit
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Login error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Login failed. Please try again.'
        }), 500

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    try:
        user = request.current_user
        user.reset_monthly_usage_if_needed()
        
        return jsonify({
            'user': {
                'id': user.id,
                'email': user.email,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'fullName': user.full_name,
                'company': user.company,
                'plan': user.plan,
                'isVerified': user.verified,
                'isPremium': user.is_premium,
                'callLimit': user.call_limit,
                'phoneNumberLimit': user.phone_number_limit,
                'monthlyCallUsage': user.monthly_calls,
                'createdAt': user.created_at.isoformat(),
                'lastLoginAt': user.last_login.isoformat() if user.last_login else None
            }
        })
    except Exception as e:
        logger.error(f"❌ Get user error: {str(e)}")
        return jsonify({'error': 'Failed to get user info'}), 500

# =============================================================================
# API ROUTES - PHONE NUMBER MANAGEMENT
# =============================================================================

@app.route('/api/phone-numbers', methods=['GET'])
@login_required
def get_user_phone_numbers():
    """Get user's phone numbers"""
    try:
        user = request.current_user
        
        phone_numbers = PhoneNumber.query.filter_by(
            user_id=user.id,
            active=True
        ).order_by(PhoneNumber.created_at.desc()).all()
        
        result = []
        for phone in phone_numbers:
            # Get call stats for this number
            total_calls = CallSession.query.filter_by(phone_number_id=phone.id).count()
            recent_calls = CallSession.query.filter(
                CallSession.phone_number_id == phone.id,
                CallSession.started_at >= datetime.utcnow() - timedelta(days=30)
            ).count()
            
            result.append({
                'id': phone.id,
                'phoneNumber': phone.phone_number,
                'friendlyName': phone.friendly_name,
                'aiName': phone.ai_name,
                'aiVoice': phone.ai_voice,
                'totalCalls': total_calls,
                'recentCalls': recent_calls,
                'createdAt': phone.created_at.isoformat(),
                'lastUsed': phone.last_used.isoformat() if phone.last_used else None
            })
        
        return jsonify({
            'phoneNumbers': result,
            'canAddMore': len(result) < user.phone_number_limit or user.phone_number_limit == -1
        })
        
    except Exception as e:
        logger.error(f"❌ Get phone numbers error: {str(e)}")
        return jsonify({'error': 'Failed to load phone numbers'}), 500

@app.route('/api/phone-numbers/search', methods=['GET'])
@login_required
def search_available_numbers():
    """Search for available phone numbers"""
    try:
        user = request.current_user
        
        # Check if user can add more numbers
        current_count = PhoneNumber.query.filter_by(user_id=user.id, active=True).count()
        if user.phone_number_limit != -1 and current_count >= user.phone_number_limit:
            return jsonify({
                'error': 'Phone number limit reached for your plan'
            }), 403
        
        area_code = request.args.get('areaCode')
        
        available_numbers = PhoneNumberManager.search_available_numbers(
            area_code=area_code,
            limit=20
        )
        
        return jsonify({
            'numbers': available_numbers
        })
        
    except Exception as e:
        logger.error(f"❌ Search numbers error: {str(e)}")
        return jsonify({'error': 'Failed to search phone numbers'}), 500

@app.route('/api/phone-numbers/purchase', methods=['POST'])
@login_required
def purchase_phone_number():
    """Purchase a phone number"""
    try:
        user = request.current_user
        data = request.get_json() or {}
        
        phone_number = data.get('phoneNumber')
        friendly_name = data.get('friendlyName', 'Support Line')
        
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        # Check if user can add more numbers
        current_count = PhoneNumber.query.filter_by(user_id=user.id, active=True).count()
        if user.phone_number_limit != -1 and current_count >= user.phone_number_limit:
            return jsonify({
                'error': 'Phone number limit reached for your plan'
            }), 403
        
        # Purchase the number
        phone_record, error = PhoneNumberManager.purchase_phone_number(
            phone_number, user.id, friendly_name
        )
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'phoneNumber': {
                'id': phone_record.id,
                'phoneNumber': phone_record.phone_number,
                'friendlyName': phone_record.friendly_name,
                'aiName': phone_record.ai_name,
                'aiVoice': phone_record.ai_voice,
                'createdAt': phone_record.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Purchase number error: {str(e)}")
        return jsonify({'error': 'Failed to purchase phone number'}), 500

@app.route('/api/phone-numbers/<phone_id>/release', methods=['DELETE'])
@login_required
def release_phone_number(phone_id):
    """Release a phone number"""
    try:
        user = request.current_user
        
        success, error = PhoneNumberManager.release_phone_number(phone_id, user.id)
        
        if not success:
            return jsonify({'error': error}), 400
        
        return jsonify({'success': True, 'message': 'Phone number released successfully'})
        
    except Exception as e:
        logger.error(f"❌ Release number error: {str(e)}")
        return jsonify({'error': 'Failed to release phone number'}), 500

@app.route('/api/phone-numbers/<phone_id>/configure', methods=['PUT'])
@login_required
def configure_phone_number(phone_id):
    """Configure AI settings for a phone number"""
    try:
        user = request.current_user
        data = request.get_json() or {}
        
        phone_record = PhoneNumber.query.filter_by(
            id=phone_id,
            user_id=user.id
        ).first()
        
        if not phone_record:
            return jsonify({'error': 'Phone number not found'}), 404
        
        # Update AI configuration
        if 'aiName' in data:
            phone_record.ai_name = data['aiName'][:100]
        
        if 'aiVoice' in data:
            # Validate OpenAI voice
            valid_voices = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer']
            if data['aiVoice'] in valid_voices:
                phone_record.ai_voice = data['aiVoice']
        
        if 'aiInstructions' in data:
            phone_record.ai_instructions = data['aiInstructions'][:2000]
        
        if 'friendlyName' in data:
            phone_record.friendly_name = data['friendlyName'][:200]
        
        if 'businessInfo' in data:
            phone_record.set_business_info(data['businessInfo'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'phoneNumber': {
                'id': phone_record.id,
                'phoneNumber': phone_record.phone_number,
                'friendlyName': phone_record.friendly_name,
                'aiName': phone_record.ai_name,
                'aiVoice': phone_record.ai_voice,
                'aiInstructions': phone_record.ai_instructions,
                'businessInfo': phone_record.get_business_info()
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Configure number error: {str(e)}")
        return jsonify({'error': 'Failed to configure phone number'}), 500

@app.route('/api/phone-numbers/<phone_id>', methods=['GET'])
@login_required
def get_phone_number_details(phone_id):
    """Get detailed phone number configuration"""
    try:
        user = request.current_user
        
        phone_record = PhoneNumber.query.filter_by(
            id=phone_id,
            user_id=user.id
        ).first()
        
        if not phone_record:
            return jsonify({'error': 'Phone number not found'}), 404
        
        # Get call statistics
        total_calls = CallSession.query.filter_by(phone_number_id=phone_id).count()
        recent_calls = CallSession.query.filter(
            CallSession.phone_number_id == phone_id,
            CallSession.started_at >= datetime.utcnow() - timedelta(days=30)
        ).count()
        
        # Get average call duration
        avg_duration_result = db.session.query(func.avg(CallSession.duration)).filter(
            CallSession.phone_number_id == phone_id,
            CallSession.duration > 0
        ).scalar()
        avg_duration = int(avg_duration_result) if avg_duration_result else 0
        
        return jsonify({
            'phoneNumber': {
                'id': phone_record.id,
                'phoneNumber': phone_record.phone_number,
                'friendlyName': phone_record.friendly_name,
                'aiName': phone_record.ai_name,
                'aiVoice': phone_record.ai_voice,
                'aiInstructions': phone_record.ai_instructions,
                'businessInfo': phone_record.get_business_info(),
                'stats': {
                    'totalCalls': total_calls,
                    'recentCalls': recent_calls,
                    'avgDuration': avg_duration
                },
                'createdAt': phone_record.created_at.isoformat(),
                'lastUsed': phone_record.last_used.isoformat() if phone_record.last_used else None
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Get phone number details error: {str(e)}")
        return jsonify({'error': 'Failed to get phone number details'}), 500

# =============================================================================
# API ROUTES - CALLS & ANALYTICS (Enhanced)
# =============================================================================

@app.route('/api/calls')
@login_required
def get_calls():
    """Get user's call history with filtering"""
    try:
        user = request.current_user
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        phone_number_id = request.args.get('phoneNumberId')
        status = request.args.get('status')
        date_from = request.args.get('dateFrom')
        date_to = request.args.get('dateTo')
        
        # Build query
        query = CallSession.query.filter_by(user_id=user.id)
        
        if phone_number_id:
            query = query.filter_by(phone_number_id=phone_number_id)
        
        if status:
            query = query.filter_by(status=status)
        
        if date_from:
            try:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query = query.filter(CallSession.started_at >= date_from_obj)
            except:
                pass
        
        if date_to:
            try:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                query = query.filter(CallSession.started_at <= date_to_obj)
            except:
                pass
        
        # Order and paginate
        query = query.order_by(CallSession.started_at.desc())
        calls = query.paginate(page=page, per_page=per_page, error_out=False)
        
        call_list = []
        for call in calls.items:
            conversation = call.get_conversation()
            preview = 'No conversation recorded'
            
            if conversation:
                # Get first user message as preview
                for msg in conversation:
                    if msg.get('user'):
                        preview = msg['user'][:100] + ('...' if len(msg['user']) > 100 else '')
                        break
            
            call_list.append({
                'id': call.id,
                'callSid': call.call_sid,
                'callerNumber': call.caller_number or 'Unknown',
                'phoneNumber': call.phone_number.phone_number if call.phone_number else 'Unknown',
                'phoneNumberName': call.phone_number.friendly_name if call.phone_number else 'Unknown',
                'status': call.status,
                'startedAt': call.started_at.isoformat(),
                'endedAt': call.ended_at.isoformat() if call.ended_at else None,
                'duration': call.duration,
                'preview': preview,
                'satisfactionRating': call.satisfaction_rating
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
        
    except Exception as e:
        logger.error(f"❌ Get calls error: {str(e)}")
        return jsonify({'error': 'Failed to load calls'}), 500

@app.route('/api/calls/<call_id>', methods=['GET'])
@login_required
def get_call_details(call_id):
    """Get detailed call information"""
    try:
        user = request.current_user
        
        call = CallSession.query.filter_by(
            id=call_id,
            user_id=user.id
        ).first()
        
        if not call:
            return jsonify({'error': 'Call not found'}), 404
        
        return jsonify({
            'call': {
                'id': call.id,
                'callSid': call.call_sid,
                'callerNumber': call.caller_number,
                'phoneNumber': call.phone_number.phone_number if call.phone_number else 'Unknown',
                'phoneNumberName': call.phone_number.friendly_name if call.phone_number else 'Unknown',
                'status': call.status,
                'startedAt': call.started_at.isoformat(),
                'endedAt': call.ended_at.isoformat() if call.ended_at else None,
                'duration': call.duration,
                'conversation': call.get_conversation(),
                'summary': call.summary,
                'satisfactionRating': call.satisfaction_rating
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Get call details error: {str(e)}")
        return jsonify({'error': 'Failed to get call details'}), 500

@app.route('/api/analytics/dashboard')
@login_required
def analytics_dashboard():
    """Get comprehensive dashboard analytics"""
    try:
        user = request.current_user
        days = request.args.get('days', 30, type=int)
        since = datetime.utcnow() - timedelta(days=days)
        
        # Reset monthly usage if needed
        user.reset_monthly_usage_if_needed()
        
        # Basic stats
        total_calls = CallSession.query.filter_by(user_id=user.id).count()
        recent_calls = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.started_at >= since
        ).count()
        
        # Phone number stats
        phone_count = PhoneNumber.query.filter_by(user_id=user.id, active=True).count()
        
        # Calculate metrics
        calls_with_duration = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.duration > 0
        ).all()
        
        avg_duration = 0
        if calls_with_duration:
            avg_duration = sum(call.duration for call in calls_with_duration) // len(calls_with_duration)
        
        # Success rate (calls longer than 10 seconds)
        successful_calls = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.duration > 10
        ).count()
        
        success_rate = (successful_calls / total_calls * 100) if total_calls > 0 else 0
        
        # Satisfaction rating
        satisfaction_calls = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.satisfaction_rating.isnot(None)
        ).all()
        
        avg_satisfaction = 0
        if satisfaction_calls:
            avg_satisfaction = sum(call.satisfaction_rating for call in satisfaction_calls) / len(satisfaction_calls)
        
        # Call volume by day (last 30 days)
        daily_calls = db.session.query(
            func.date(CallSession.started_at).label('date'),
            func.count(CallSession.id).label('count')
        ).filter(
            CallSession.user_id == user.id,
            CallSession.started_at >= datetime.utcnow() - timedelta(days=30)
        ).group_by(
            func.date(CallSession.started_at)
        ).all()
        
        # Phone number performance
        phone_performance = db.session.query(
            PhoneNumber.id,
            PhoneNumber.friendly_name,
            PhoneNumber.phone_number,
            func.count(CallSession.id).label('call_count'),
            func.avg(CallSession.duration).label('avg_duration')
        ).outerjoin(CallSession).filter(
            PhoneNumber.user_id == user.id,
            PhoneNumber.active == True
        ).group_by(PhoneNumber.id).all()
        
        return jsonify({
            'overview': {
                'totalCalls': total_calls,
                'recentCalls': recent_calls,
                'phoneNumbers': phone_count,
                'avgDuration': avg_duration,
                'successRate': round(success_rate, 1),
                'avgSatisfaction': round(avg_satisfaction, 1) if avg_satisfaction else None,
                'monthlyCallUsage': user.monthly_calls,
                'callLimit': user.call_limit,
                'phoneNumberLimit': user.phone_number_limit
            },
            'charts': {
                'dailyCalls': [
                    {
                        'date': str(call.date),
                        'calls': call.count
                    } for call in daily_calls
                ],
                'phonePerformance': [
                    {
                        'id': phone.id,
                        'name': phone.friendly_name,
                        'phoneNumber': phone.phone_number,
                        'calls': phone.call_count or 0,
                        'avgDuration': int(phone.avg_duration) if phone.avg_duration else 0
                    } for phone in phone_performance
                ]
            },
            'period': {
                'days': days,
                'since': since.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Analytics dashboard error: {str(e)}")
        return jsonify({
            'overview': {
                'totalCalls': 0,
                'recentCalls': 0,
                'phoneNumbers': 0,
                'avgDuration': 0,
                'successRate': 0,
                'avgSatisfaction': None,
                'monthlyCallUsage': 0,
                'callLimit': user.call_limit if hasattr(request, 'current_user') else 100,
                'phoneNumberLimit': user.phone_number_limit if hasattr(request, 'current_user') else 1
            },
            'charts': {
                'dailyCalls': [],
                'phonePerformance': []
            }
        })

# =============================================================================
# ENHANCED TWILIO VOICE ROUTES
# =============================================================================

@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio calls with enhanced AI"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"📞 Incoming call: {call_sid} from {from_number} to {to_number}")
        
        # Find the phone number record
        phone_record = PhoneNumber.query.filter_by(
            phone_number=to_number,
            active=True
        ).first()
        
        if not phone_record:
            logger.warning(f"No phone record found for {to_number}")
            response = VoiceResponse()
            response.say("I'm sorry, this number is not configured. Please try again later.", voice='alice')
            return str(response), 200, {'Content-Type': 'text/xml'}
        
        # Check if user can make calls
        user = phone_record.user
        if not user.can_make_call():
            response = VoiceResponse()
            response.say("I'm sorry, the call limit has been reached for this account.", voice='alice')
            return str(response), 200, {'Content-Type': 'text/xml'}
        
        # Create call session
        call_session = CallSession(
            call_sid=call_sid,
            caller_number=from_number,
            phone_number_id=phone_record.id,
            user_id=phone_record.user_id,
            call_data=json.dumps({
                'from': from_number,
                'to': to_number,
                'timestamp': datetime.utcnow().isoformat()
            })
        )
        db.session.add(call_session)
        
        # Update phone number last used
        phone_record.last_used = datetime.utcnow()
        
        # Increment user call count
        user.increment_call_count()
        
        db.session.commit()
        logger.info(f"✅ Call session created: {call_sid}")
        
        # Create personalized TwiML response
        business_info = phone_record.get_business_info()
        greeting = f"Hello! Thank you for calling {business_info.get('name', phone_record.ai_name)}. How can I help you today?"
        
        response = VoiceResponse()
        response.say(greeting, voice=phone_record.ai_voice)
        
        # Set up speech recognition
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Please tell me what you need assistance with.", voice=phone_record.ai_voice)
        response.append(gather)
        
        # Fallback
        response.say("I didn't hear anything. Please call back when you're ready to talk. Thank you!", voice=phone_record.ai_voice)
        
        return str(response), 200, {'Content-Type': 'text/xml'}
        
    except Exception as e:
        logger.error(f"❌ Voice call error: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, we're experiencing technical difficulties. Please try again later.", voice='alice')
        return str(response), 200, {'Content-Type': 'text/xml'}

@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech(call_sid):
    """Handle speech from caller with enhanced AI"""
    try:
        speech_result = request.form.get('SpeechResult', '').strip()
        confidence = float(request.form.get('Confidence', 0))
        
        logger.info(f"🗣️ Speech: {speech_result} (confidence: {confidence})")
        
        # Get call session
        call_session = CallSession.query.filter_by(call_sid=call_sid).first()
        if not call_session or not call_session.phone_number:
            response = VoiceResponse()
            response.say("I'm sorry, there was an error processing your call.", voice='alice')
            return str(response), 200, {'Content-Type': 'text/xml'}
        
        phone_record = call_session.phone_number
        
        if not speech_result or confidence < 0.5:
            response = VoiceResponse()
            response.say("I'm sorry, I didn't understand that clearly. Could you please repeat?", voice=phone_record.ai_voice)
            
            gather = Gather(
                input='speech',
                action=f'/api/twilio/gather/{call_sid}',
                method='POST',
                speech_timeout='auto'
            )
            gather.say("What can I help you with?", voice=phone_record.ai_voice)
            response.append(gather)
            
            return str(response), 200, {'Content-Type': 'text/xml'}
        
        # Generate enhanced AI response
        ai_response = generate_enhanced_ai_response(speech_result, call_session, phone_record)
        
        # Save conversation
        conversation = call_session.get_conversation()
        conversation.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': confidence
        })
        call_session.set_conversation(conversation)
        db.session.commit()
        
        # Create response
        response = VoiceResponse()
        response.say(ai_response, voice=phone_record.ai_voice)
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto'
        )
        gather.say("Is there anything else I can help you with?", voice=phone_record.ai_voice)
        response.append(gather)
        
        # End call option
        business_info = phone_record.get_business_info()
        business_name = business_info.get('name', 'us')
        response.say(f"Thank you for calling {business_name}. Have a great day!", voice=phone_record.ai_voice)
        
        return str(response), 200, {'Content-Type': 'text/xml'}
        
    except Exception as e:
        logger.error(f"❌ Speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble processing your request. Please try again.", voice='alice')
        return str(response), 200, {'Content-Type': 'text/xml'}

def generate_enhanced_ai_response(user_input, call_session, phone_record):
    """Generate enhanced AI response with business context"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Get conversation history
        conversation_history = call_session.get_conversation()[-3:]  # Last 3 exchanges
        
        # Get business information
        business_info = phone_record.get_business_info()
        
        # Build enhanced system prompt
        system_prompt = f"""You are {phone_record.ai_name}, a helpful AI assistant for {business_info.get('name', 'this business')}.

Business Information:
- Name: {business_info.get('name', 'Not specified')}
- Type: {business_info.get('type', 'Not specified')}
- Hours: {business_info.get('hours', 'Not specified')}
- Location: {business_info.get('location', 'Not specified')}
- Website: {business_info.get('website', 'Not specified')}
- Phone: {business_info.get('phone', phone_record.phone_number)}

Special Instructions:
{phone_record.ai_instructions}

Important Guidelines:
- Be friendly, professional, and helpful
- Keep responses under 50 words for phone conversations
- If you don't know something specific about the business, offer to connect them with a human
- Always try to be helpful and provide value
- Use the business information provided to answer questions accurately"""
        
        # Build messages
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        for exchange in conversation_history:
            if 'user' in exchange:
                messages.append({"role": "user", "content": exchange['user']})
            if 'assistant' in exchange:
                messages.append({"role": "assistant", "content": exchange['assistant']})
        
        # Add current input
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
        logger.error(f"❌ Enhanced AI response error: {e}")
        return "I apologize, but I'm having trouble processing your request right now. Please try again."

# =============================================================================
# DEMO API (Previous demo routes remain the same)
# =============================================================================

@app.route('/api/demo/chat', methods=['POST'])
@limiter.limit("20 per hour")
def demo_chat():
    """Demo chat for landing page"""
    try:
        data = request.get_json() or {}
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Simple demo responses
        demo_responses = {
            'hello': "Hello! I'm your AI voice assistant. I can handle customer calls 24/7!",
            'pricing': "Our pricing starts at $99/month for unlimited calls. Perfect for growing businesses!",
            'features': "I can answer questions, take messages, schedule appointments, and provide customer support.",
            'how': "I use advanced AI to understand speech and respond naturally, just like talking to a human assistant.",
            'phone': "You get a dedicated phone number that I'll answer professionally for your business."
        }
        
        # Find best response
        message_lower = message.lower()
        response_text = "Thanks for trying our demo! I'm an AI that handles phone calls for businesses. Sign up to get your own AI assistant!"
        
        for keyword, response in demo_responses.items():
            if keyword in message_lower:
                response_text = response
                break
        
        return jsonify({
            'success': True,
            'response': response_text,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"❌ Demo error: {e}")
        return jsonify({'error': 'Demo temporarily unavailable'}), 500

# =============================================================================
# HEALTH CHECK & MONITORING (Previous health check remains the same)
# =============================================================================

@app.route('/api/health')
def health_check():
    """System health check - BULLETPROOF"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
        
        # Get counts safely
        try:
            user_count = User.query.count()
            call_count = CallSession.query.count()
            phone_count = PhoneNumber.query.filter_by(active=True).count()
        except:
            user_count = call_count = phone_count = 0
        
        return jsonify({
            'status': 'healthy',
            'version': '2.1.0',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'services': {
                'openai': 'healthy' if openai_client else 'unavailable',
                'twilio': 'healthy' if twilio_client else 'unavailable'
            },
            'stats': {
                'totalUsers': user_count,
                'totalCalls': call_count,
                'activePhoneNumbers': phone_count
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Add this debug endpoint to your app.py temporarily

@app.route('/api/debug/database')
def debug_database():
    """Debug database information (REMOVE IN PRODUCTION)"""
    try:
        # Get database info
        db_url = Config.DATABASE_URL
        
        # Count users
        user_count = User.query.count()
        
        # Check if tables exist
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Get some sample data
        sample_users = User.query.limit(3).all()
        
        return jsonify({
            'database_url': db_url[:50] + '...' if len(db_url) > 50 else db_url,
            'database_type': 'PostgreSQL' if 'postgresql' in db_url else 'SQLite',
            'tables': tables,
            'user_count': user_count,
            'sample_users': [
                {
                    'id': user.id,
                    'email': user.email,
                    'created_at': user.created_at.isoformat()
                } for user in sample_users
            ],
            'database_file_location': db_url if 'sqlite' in db_url else 'N/A - PostgreSQL'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'database_url': Config.DATABASE_URL[:50] + '...'
        }), 500

# =============================================================================
# ERROR HANDLERS (Previous error handlers remain the same)
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    try:
        db.session.rollback()
    except:
        pass
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    """Handle rate limiting"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# Handle CORS
@app.after_request
def after_request(response):
    """Add CORS headers"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def init_database():
    """Initialize database tables safely"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            logger.info("✅ Database tables ensured")
            return True
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        return False

# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Initialize database
    if not init_database():
        logger.error("❌ Database initialization failed - exiting")
        exit(1)
    
    # Log startup information
    logger.info("🚀 Starting Enhanced Voxcord v2.1...")
    logger.info(f"📊 Database: {Config.DATABASE_URL.split('://')[0].upper()}")
    logger.info(f"🔑 OpenAI: {'✅ Configured' if openai_client else '❌ Not configured'}")
    logger.info(f"📞 Twilio: {'✅ Configured' if twilio_client else '❌ Not configured'}")
    logger.info(f"🌐 Port: {Config.PORT}")
    
    # Start the application
    try:
        app.run(
            host='0.0.0.0',
            port=Config.PORT,
            debug=os.getenv('FLASK_ENV') == 'development'
        )
    except Exception as e:
        logger.error(f"❌ Failed to start application: {e}")
        exit(1)
