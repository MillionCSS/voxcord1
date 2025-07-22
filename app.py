#!/usr/bin/env python3
"""
Voxcord - AI Voice Assistant Platform
Production-ready Flask application optimized for Digital Ocean App Platform
Fixes: OpenAI proxies issue, SQLAlchemy metadata conflict, and all deployment issues
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

# Import Flask and extensions
from flask import Flask, request, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import external services
import httpx
from openai import OpenAI
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client

# Load environment variables
from dotenv import load_dotenv
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

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    
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
    
    # External APIs
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    
    # App settings
    PORT = int(os.getenv('PORT', 5000))
    DOMAIN = os.getenv('DOMAIN', 'localhost:5000')
    BASE_URL = f"https://{DOMAIN}" if os.getenv('FLASK_ENV') == 'production' else f"http://localhost:{PORT}"

# =============================================================================
# APP INITIALIZATION
# =============================================================================

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

# =============================================================================
# EXTERNAL SERVICES INITIALIZATION (FIXED)
# =============================================================================

def initialize_openai_client():
    """Initialize OpenAI client with Digital Ocean compatibility"""
    if not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY not set - AI responses will be limited")
        return None
    
    try:
        # Clear any proxy environment variables that Digital Ocean might set
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']
        for var in proxy_vars:
            os.environ.pop(var, None)
        
        # Try httpx approach first (recommended)
        http_client = httpx.Client(
            proxies=None,  # Explicitly disable proxies
            timeout=30.0,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
        )
        
        client = OpenAI(
            api_key=Config.OPENAI_API_KEY,
            http_client=http_client
        )
        
        logger.info("✅ OpenAI client initialized successfully")
        return client
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize OpenAI client: {e}")
        # Fallback: try without httpx
        try:
            return OpenAI(api_key=Config.OPENAI_API_KEY)
        except:
            return None

# Initialize clients
openai_client = initialize_openai_client()
twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN) if Config.TWILIO_ACCOUNT_SID else None

# =============================================================================
# DATABASE MODELS (FIXED)
# =============================================================================

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
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    
    # Settings
    settings = db.Column(db.Text, default='{}')
    
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
    
    # FIXED: Renamed from 'metadata' to avoid SQLAlchemy conflict
    call_metadata = db.Column(db.Text, default='{}')

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

# =============================================================================
# SECURITY & UTILITIES
# =============================================================================

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
        return re.match(pattern, email.lower()) is not None

def create_jwt_token(user):
    """Create JWT token for user"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=30),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token and return user"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        return user if user and user.is_active else None
    except:
        return None

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user = verify_jwt_token(token)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def verified_required(f):
    """Decorator to require email verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.current_user.is_verified:
            return jsonify({'error': 'Email verification required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# STATIC FILE ROUTES
# =============================================================================

@app.route('/')
def landing_page():
    """Serve landing page"""
    return send_from_directory('.', 'landing.html')

@app.route('/signup')
def signup_page():
    """Serve signup page"""
    return send_from_directory('.', 'signup.html')

@app.route('/login')
def login_page():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/dashboard')
def dashboard_page():
    """Serve dashboard page"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# =============================================================================
# API ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("10 per hour")
def signup():
    """User registration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        email = data['email'].lower().strip()
        
        # Validate email format
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate password
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Create new user
        user = User(
            id=str(uuid.uuid4()),
            first_name=data['firstName'].strip(),
            last_name=data['lastName'].strip(),
            email=email,
            password_hash=SecurityManager.hash_password(data['password']),
            company=data.get('company', '').strip(),
            plan='free',
            is_verified=True  # Auto-verify for simplicity in demo
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create JWT token
        token = create_jwt_token(user)
        
        logger.info(f"New user registered: {email}")
        
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
                'isVerified': user.is_verified,
                'phoneNumber': '+1 (609) 507-3300'  # Shared number
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per hour")
def login():
    """User login"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        email = data['email'].lower().strip()
        user = User.query.filter_by(email=email).first()
        
        if not user or not SecurityManager.verify_password(data['password'], user.password_hash):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Update last login
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        
        # Create JWT token
        token = create_jwt_token(user)
        
        logger.info(f"User logged in: {email}")
        
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
                'isVerified': user.is_verified,
                'phoneNumber': '+1 (609) 507-3300'  # Shared number
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    user = request.current_user
    
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
            'phoneNumber': '+1 (609) 507-3300',  # Shared number
            'createdAt': user.created_at.isoformat(),
            'lastLoginAt': user.last_login_at.isoformat() if user.last_login_at else None
        }
    })

# =============================================================================
# API ROUTES - CALLS & ANALYTICS
# =============================================================================

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
            'preview': preview[:100],  # Limit preview length
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
        call_meta = json.loads(call.call_metadata) if call.call_metadata else {}
    except:
        conversation = []
        call_meta = {}
    
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
            'metadata': call_meta
        }
    })

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

# =============================================================================
# TWILIO VOICE ROUTES
# =============================================================================

@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio voice calls"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"Incoming call - CallSid: {call_sid}, From: {from_number}")
        
        # Create call session for tracking
        call_session = CallSession(
            id=str(uuid.uuid4()),
            call_sid=call_sid,
            caller_number=from_number,
            call_metadata=json.dumps({
                'from_number': from_number,
                'to_number': to_number,
                'timestamp': datetime.utcnow().isoformat()
            })
        )
        
        try:
            db.session.add(call_session)
            db.session.commit()
            logger.info(f"Call session created: {call_sid}")
        except Exception as e:
            logger.warning(f"Could not create call session: {e}")
        
        # Create TwiML response
        response = VoiceResponse()
        
        # Greeting
        greeting = "Hello! Thank you for calling Voxcord, your AI voice assistant platform. How can I help you today?"
        response.say(greeting, voice='alice')
        
        # Set up conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Please tell me what you need assistance with.", voice='alice')
        response.append(gather)
        
        # Fallback
        response.say("I didn't hear anything. Please call back when you're ready to talk. Thank you!", voice='alice')
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Voice call error: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, we're experiencing technical difficulties. Please try again later.", voice='alice')
        return str(response)

@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech(call_sid):
    """Handle speech input from Twilio"""
    try:
        speech_result = request.form.get('SpeechResult', '').strip()
        confidence = float(request.form.get('Confidence', 0))
        
        logger.info(f"Speech received - CallSid: {call_sid}, Speech: {speech_result}, Confidence: {confidence}")
        
        if not speech_result or confidence < 0.5:
            response = VoiceResponse()
            response.say("I'm sorry, I didn't understand that. Could you please repeat?", voice='alice')
            
            gather = Gather(
                input='speech',
                action=f'/api/twilio/gather/{call_sid}',
                method='POST',
                speech_timeout='auto'
            )
            gather.say("What can I help you with?", voice='alice')
            response.append(gather)
            
            return str(response)
        
        # Generate AI response
        ai_response = generate_ai_response(speech_result, call_sid)
        
        # Update call session with conversation
        try:
            call = CallSession.query.filter_by(call_sid=call_sid).first()
            if call:
                conversation = json.loads(call.conversation) if call.conversation else []
                conversation.append({
                    'user': speech_result,
                    'assistant': ai_response,
                    'timestamp': datetime.utcnow().isoformat(),
                    'confidence': confidence
                })
                call.conversation = json.dumps(conversation)
                db.session.commit()
        except Exception as e:
            logger.warning(f"Could not update conversation: {e}")
        
        # Create response
        response = VoiceResponse()
        response.say(ai_response, voice='alice')
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto'
        )
        gather.say("Is there anything else I can help you with?", voice='alice')
        response.append(gather)
        
        # End call option
        response.say("Thank you for calling Voxcord. Have a great day!", voice='alice')
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble understanding. Please try again.", voice='alice')
        return str(response)

def generate_ai_response(user_input, call_sid):
    """Generate AI response using OpenAI"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Get conversation history
        conversation_history = []
        try:
            call = CallSession.query.filter_by(call_sid=call_sid).first()
            if call and call.conversation:
                conversation_history = json.loads(call.conversation)
        except:
            pass
        
        # Build context
        messages = [
            {
                "role": "system", 
                "content": "You are a helpful customer service assistant for Voxcord, an AI voice platform. Be friendly, professional, and concise. Keep responses under 50 words for phone conversations."
            }
        ]
        
        # Add recent conversation history (last 3 exchanges)
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
        logger.error(f"AI response error: {e}")
        return "I apologize, but I'm having trouble processing your request right now."

# =============================================================================
# DEMO API (Landing Page)
# =============================================================================

@app.route('/api/demo/chat', methods=['POST'])
@limiter.limit("20 per hour")
def demo_chat():
    """Handle demo chat from landing page"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        business_config = data.get('config', {})
        
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Generate AI response for demo
        ai_response = generate_demo_ai_response(user_message, business_config)
        
        # Track demo session
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        try:
            demo_session = DemoSession(
                session_ip=client_ip,
                user_agent=request.headers.get('User-Agent', ''),
                business_config=json.dumps(business_config),
                messages_count=1
            )
            db.session.add(demo_session)
            db.session.commit()
        except:
            pass  # Don't fail if demo tracking fails
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Demo chat error: {e}")
        return jsonify({
            'success': False, 
            'error': 'Demo temporarily unavailable'
        }), 500

def generate_demo_ai_response(user_message, business_config):
    """Generate AI response for demo"""
    if not openai_client:
        # Fallback responses for demo
        fallback_responses = {
            "hello": "Hello! I'm your AI voice assistant. How can I help you today?",
            "pricing": "Our pricing starts at $99/month for unlimited AI voice calls. Would you like to know more?",
            "features": "I can handle customer calls, answer questions, take messages, and provide 24/7 support for your business.",
            "default": "Thank you for trying our demo! I'm an AI assistant that can help with customer service calls. Sign up to get your own AI voice assistant!"
        }
        
        message_lower = user_message.lower()
        for key, response in fallback_responses.items():
            if key in message_lower:
                return response
        return fallback_responses["default"]
    
    try:
        # Extract business details
        business_name = business_config.get('businessName', 'your business')
        business_type = business_config.get('businessType', 'business')
        
        # Build system prompt for demo
        system_prompt = f"""You are a professional AI customer service assistant for {business_name}, a {business_type}. 
        
Key guidelines:
- Be friendly, helpful, and professional
- Keep responses under 40 words for phone conversations
- Focus on being helpful and informative
- If asked about Voxcord, explain it's an AI voice platform that handles customer calls
- This is a demo, so encourage them to sign up for the full service

Business context: {business_name} is a {business_type}."""

        # Generate response
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            max_tokens=80,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Demo AI response error: {e}")
        return "Thanks for trying our demo! Sign up to get your own AI voice assistant that can handle all your customer calls professionally."

# =============================================================================
# HEALTH CHECK & MONITORING
# =============================================================================

@app.route('/api/health')
def health_check():
    """System health check"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        # Check external services
        services_status = {
            'database': 'healthy',
            'openai': 'healthy' if openai_client else 'unavailable',
            'twilio': 'healthy' if twilio_client else 'unavailable'
        }
        
        # Get basic stats
        total_users = User.query.count()
        total_calls = CallSession.query.count()
        active_calls = CallSession.query.filter_by(status='active').count()
        
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat(),
            'services': services_status,
            'stats': {
                'totalUsers': total_users,
                'totalCalls': total_calls,
                'activeCalls': active_calls
            }
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limiting"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# Handle CORS preflight requests
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

def init_db():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            logger.info("✅ Database tables created successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")

# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Validate required environment variables
    if not Config.OPENAI_API_KEY:
        logger.warning("⚠️  OPENAI_API_KEY not set - AI responses will be limited")
    
    if not Config.TWILIO_ACCOUNT_SID:
        logger.warning("⚠️  Twilio not configured - voice calls will not work")
    
    # Log startup information
    logger.info("🚀 Starting Voxcord production server...")
    logger.info(f"📊 Database: {Config.DATABASE_URL[:50]}...")
    logger.info(f"🔑 OpenAI: {'Configured' if openai_client else 'Not configured'}")
    logger.info(f"📞 Twilio: {'Configured' if twilio_client else 'Not configured'}")
    logger.info(f"🌐 Base URL: {Config.BASE_URL}")
    logger.info(f"🎯 Environment: {os.getenv('FLASK_ENV', 'development')}")
    
    # Start the application
    app.run(
        host='0.0.0.0', 
        port=Config.PORT, 
        debug=os.getenv('FLASK_ENV') != 'production'
    )
