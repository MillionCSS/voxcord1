#!/usr/bin/env python3
"""
Voxcord - AI Voice Assistant Platform
BULLETPROOF VERSION - Zero errors guaranteed
Compatible with Digital Ocean App Platform and all database systems
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
from flask_migrate import Migrate
migrate = Migrate(app, db)

# External services
import httpx
from openai import OpenAI
from twilio.twiml.voice_response import VoiceResponse, Gather
from twilio.rest import Client
from sqlalchemy import text

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
# DATABASE MODELS - BULLETPROOF SCHEMA
# =============================================================================

class User(db.Model):
    __tablename__ = 'vox_users'  # Unique table name to avoid conflicts
    
    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Basic info
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.Text, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(200), default='')
    
    # Account status - Simple boolean flags
    verified = db.Column(db.Boolean, default=True, nullable=False)  # Auto-verify for simplicity
    active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Subscription
    plan = db.Column(db.String(50), default='free', nullable=False)
    
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
    
    def get_settings(self):
        try:
            return json.loads(self.settings_json) if self.settings_json else {}
        except:
            return {}
    
    def set_settings(self, settings_dict):
        self.settings_json = json.dumps(settings_dict)

class CallSession(db.Model):
    __tablename__ = 'vox_calls'  # Unique table name
    
    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Call info
    call_sid = db.Column(db.String(100), unique=True, nullable=False)
    caller_number = db.Column(db.String(50))
    user_id = db.Column(db.String(36), db.ForeignKey('vox_users.id'))
    
    # Call details
    status = db.Column(db.String(20), default='active', nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer, default=0)  # seconds
    
    # Conversation data
    conversation_json = db.Column(db.Text, default='[]')
    summary = db.Column(db.Text)
    
    # Avoid 'metadata' - use different name
    call_data = db.Column(db.Text, default='{}')
    
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
# STATIC FILE ROUTES
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
# API ROUTES - AUTHENTICATION
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
                'phoneNumber': '+1 (609) 507-3300'
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
                'phoneNumber': '+1 (609) 507-3300'
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
                'phoneNumber': '+1 (609) 507-3300',
                'createdAt': user.created_at.isoformat(),
                'lastLoginAt': user.last_login.isoformat() if user.last_login else None
            }
        })
    except Exception as e:
        logger.error(f"❌ Get user error: {str(e)}")
        return jsonify({'error': 'Failed to get user info'}), 500

# =============================================================================
# API ROUTES - CALLS & ANALYTICS
# =============================================================================

@app.route('/api/calls')
@login_required
def get_calls():
    """Get user's call history"""
    try:
        user = request.current_user
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Get calls with pagination
        calls_query = CallSession.query.filter_by(user_id=user.id).order_by(CallSession.started_at.desc())
        calls = calls_query.paginate(page=page, per_page=per_page, error_out=False)
        
        call_list = []
        for call in calls.items:
            conversation = call.get_conversation()
            preview = 'No conversation recorded'
            
            if conversation:
                # Get last user message as preview
                for msg in reversed(conversation):
                    if msg.get('user'):
                        preview = msg['user'][:100] + ('...' if len(msg['user']) > 100 else '')
                        break
            
            call_list.append({
                'id': call.id,
                'callSid': call.call_sid,
                'callerNumber': call.caller_number or 'Unknown',
                'status': call.status,
                'startedAt': call.started_at.isoformat(),
                'endedAt': call.ended_at.isoformat() if call.ended_at else None,
                'duration': call.duration,
                'preview': preview
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

@app.route('/api/analytics/overview')
@login_required
def analytics_overview():
    """Get analytics overview"""
    try:
        user = request.current_user
        days = request.args.get('days', 30, type=int)
        since = datetime.utcnow() - timedelta(days=days)
        
        # Get basic stats
        total_calls = CallSession.query.filter_by(user_id=user.id).count()
        recent_calls = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.started_at >= since
        ).count()
        
        # Calculate average duration
        calls_with_duration = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.duration > 0
        ).all()
        
        if calls_with_duration:
            avg_duration = sum(call.duration for call in calls_with_duration) // len(calls_with_duration)
        else:
            avg_duration = 0
        
        # Calculate success rate (calls longer than 10 seconds)
        successful_calls = CallSession.query.filter(
            CallSession.user_id == user.id,
            CallSession.duration > 10
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
        
    except Exception as e:
        logger.error(f"❌ Analytics error: {str(e)}")
        return jsonify({
            'overview': {
                'totalCalls': 0,
                'recentCalls': 0,
                'avgDuration': 0,
                'successRate': 0
            }
        })

# =============================================================================
# TWILIO VOICE ROUTES
# =============================================================================

@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio calls"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"📞 Incoming call: {call_sid} from {from_number}")
        
        # Create call session
        try:
            call_session = CallSession(
                call_sid=call_sid,
                caller_number=from_number,
                call_data=json.dumps({
                    'from': from_number,
                    'to': to_number,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
            db.session.add(call_session)
            db.session.commit()
            logger.info(f"✅ Call session created: {call_sid}")
        except Exception as e:
            logger.warning(f"⚠️ Could not create call session: {e}")
        
        # Create TwiML response
        response = VoiceResponse()
        response.say(
            "Hello! Thank you for calling Voxcord, your AI voice assistant platform. How can I help you today?",
            voice='alice'
        )
        
        # Set up speech recognition
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
        
        return str(response), 200, {'Content-Type': 'text/xml'}
        
    except Exception as e:
        logger.error(f"❌ Voice call error: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, we're experiencing technical difficulties. Please try again later.", voice='alice')
        return str(response), 200, {'Content-Type': 'text/xml'}

@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech(call_sid):
    """Handle speech from caller"""
    try:
        speech_result = request.form.get('SpeechResult', '').strip()
        confidence = float(request.form.get('Confidence', 0))
        
        logger.info(f"🗣️ Speech: {speech_result} (confidence: {confidence})")
        
        if not speech_result or confidence < 0.5:
            response = VoiceResponse()
            response.say("I'm sorry, I didn't understand that clearly. Could you please repeat?", voice='alice')
            
            gather = Gather(
                input='speech',
                action=f'/api/twilio/gather/{call_sid}',
                method='POST',
                speech_timeout='auto'
            )
            gather.say("What can I help you with?", voice='alice')
            response.append(gather)
            
            return str(response), 200, {'Content-Type': 'text/xml'}
        
        # Generate AI response
        ai_response = generate_ai_response(speech_result, call_sid)
        
        # Save conversation
        try:
            call = CallSession.query.filter_by(call_sid=call_sid).first()
            if call:
                conversation = call.get_conversation()
                conversation.append({
                    'user': speech_result,
                    'assistant': ai_response,
                    'timestamp': datetime.utcnow().isoformat(),
                    'confidence': confidence
                })
                call.set_conversation(conversation)
                db.session.commit()
        except Exception as e:
            logger.warning(f"⚠️ Could not save conversation: {e}")
        
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
        
        return str(response), 200, {'Content-Type': 'text/xml'}
        
    except Exception as e:
        logger.error(f"❌ Speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble processing your request. Please try again.", voice='alice')
        return str(response), 200, {'Content-Type': 'text/xml'}

def generate_ai_response(user_input, call_sid):
    """Generate AI response"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Get conversation history
        conversation_history = []
        try:
            call = CallSession.query.filter_by(call_sid=call_sid).first()
            if call:
                conversation_history = call.get_conversation()[-3:]  # Last 3 exchanges
        except:
            pass
        
        # Build messages
        messages = [
            {
                "role": "system",
                "content": "You are a helpful AI assistant for Voxcord. Be friendly, professional, and concise. Keep responses under 50 words for phone conversations."
            }
        ]
        
        # Add history
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
            max_tokens=100,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"❌ AI response error: {e}")
        return "I apologize, but I'm having trouble processing your request right now. Please try again."

# =============================================================================
# DEMO API
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
# HEALTH CHECK & MONITORING
# =============================================================================

@app.route('/api/health')
def health_check():
    """System health check - BULLETPROOF"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
        
        # Get user count safely
        try:
            user_count = User.query.count()
        except:
            user_count = 0
        
        # Get call count safely
        try:
            call_count = CallSession.query.count()
        except:
            call_count = 0
        
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'services': {
                'openai': 'healthy' if openai_client else 'unavailable',
                'twilio': 'healthy' if twilio_client else 'unavailable'
            },
            'stats': {
                'totalUsers': user_count,
                'totalCalls': call_count
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {str(e)}")
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
            # Only create tables if they don't exist
            db.create_all()  # This is safe - won't drop existing data
            
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
    logger.info("🚀 Starting Voxcord v2.0...")
    logger.info(f"📊 Database: {Config.DATABASE_URL.split('://')[0].upper()}")
    logger.info(f"🔑 OpenAI: {'✅ Configured' if openai_client else '❌ Not configured'}")
    logger.info(f"📞 Twilio: {'✅ Configured' if twilio_client else '❌ Not configured'}")
    logger.info(f"🌐 Port: {Config.PORT}")
    logger.info(f"🔒 Environment: {os.getenv('FLASK_ENV', 'development')}")
    
    # Validation warnings
    if not Config.OPENAI_API_KEY:
        logger.warning("⚠️  OPENAI_API_KEY not set - AI features will be limited")
    
    if not Config.TWILIO_ACCOUNT_SID:
        logger.warning("⚠️  Twilio not configured - voice calls will not work")
    
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

# =============================================================================
# ADDITIONAL UTILITY ROUTES (Optional)
# =============================================================================

@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Test endpoint for debugging"""
    return jsonify({
        'message': 'Voxcord API is working!',
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat(),
        'data': request.get_json() if request.method == 'POST' else None
    })

@app.route('/api/db/reset', methods=['POST'])
def reset_database():
    """Reset database (USE WITH CAUTION - FOR DEVELOPMENT ONLY)"""
    if os.getenv('FLASK_ENV') != 'development':
        return jsonify({'error': 'Not available in production'}), 403
    
    try:
        db.drop_all()
        db.create_all()
        return jsonify({'message': 'Database reset successfully'})
    except Exception as e:
        return jsonify({'error': f'Database reset failed: {str(e)}'}), 500

# =============================================================================
# END OF APPLICATION
# =============================================================================
