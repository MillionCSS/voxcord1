import os
import json
import sqlite3
import hashlib
import secrets
import logging
import uuid
from datetime import datetime, timedelta
from functools import wraps
import re

from flask import Flask, request, jsonify, send_file, send_from_directory
from twilio.twiml.voice_response import VoiceResponse, Gather
import jwt

# Handle CORS manually if flask-cors is not available
try:
    from flask_cors import CORS
    cors_available = True
except ImportError:
    cors_available = False
    CORS = None

# OpenAI import with error handling
try:
    from openai import OpenAI
    openai_available = True
except ImportError:
    openai_available = False
    OpenAI = None

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL', 'database.db')
    PORT = int(os.getenv('PORT', 5000))
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Setup CORS - handle both with and without flask-cors
if cors_available:
    CORS(app)
else:
    # Manual CORS handling
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response
    
    @app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
    @app.route('/<path:path>', methods=['OPTIONS'])
    def handle_options(path):
        response = jsonify({'status': 'OK'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

# Shared phone number for all users
SHARED_PHONE_NUMBER = "+16095073300"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize OpenAI client
openai_client = None
if openai_available and Config.OPENAI_API_KEY:
    try:
        openai_client = OpenAI(api_key=Config.OPENAI_API_KEY)
    except Exception as e:
        logger.warning(f"OpenAI initialization failed: {e}")

# Database Manager
class DatabaseManager:
    def __init__(self, db_path=Config.DATABASE_URL):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    plan TEXT DEFAULT 'free',
                    settings TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Call sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS call_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_sid TEXT UNIQUE NOT NULL,
                    user_id INTEGER,
                    from_number TEXT,
                    conversation TEXT DEFAULT '[]',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Demo sessions table for analytics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS demo_sessions (
                    id TEXT PRIMARY KEY,
                    session_ip TEXT,
                    business_config TEXT DEFAULT '{}',
                    conversation TEXT DEFAULT '[]',
                    messages_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def create_user(self, first_name, last_name, email, password_hash):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, password_hash)
                VALUES (?, ?, ?, ?)
            ''', (first_name, last_name, email, password_hash))
            conn.commit()
            return cursor.lastrowid
    
    def get_user_by_email(self, email):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def create_call_session(self, call_sid, user_id, from_number):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO call_sessions (call_sid, user_id, from_number)
                VALUES (?, ?, ?)
            ''', (call_sid, user_id, from_number))
            conn.commit()
    
    def update_call_conversation(self, call_sid, conversation):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE call_sessions SET conversation = ? WHERE call_sid = ?
            ''', (json.dumps(conversation), call_sid))
            conn.commit()
    
    def get_recent_calls(self, limit=10):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM call_sessions 
                ORDER BY started_at DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def create_demo_session(self, session_data):
        """Create a demo session for analytics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO demo_sessions (id, session_ip, business_config, conversation, messages_count)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session_data['id'], 
                session_data['session_ip'], 
                json.dumps(session_data.get('business_config', {})), 
                json.dumps(session_data.get('conversation', [])),
                len(session_data.get('conversation', []))
            ))
            conn.commit()
    
    def update_demo_session(self, session_id, messages_count, conversation):
        """Update demo session with new messages"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE demo_sessions 
                SET messages_count = ?, conversation = ? 
                WHERE id = ?
            ''', (messages_count, json.dumps(conversation), session_id))
            conn.commit()

# Initialize database
db = DatabaseManager()

# Security utilities
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

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            request.current_user = payload
            return f(*args, **kwargs)
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated_function

# Memory storage for active calls
active_calls = {}

# Routes - Static Pages
@app.route('/')
def index():
    try:
        return send_file('landing.html')
    except:
        # If landing.html doesn't exist, return the integrated version
        return send_file('Voxcord - Integrated Landing Page with Working Demo.html')

@app.route('/signup')
def signup_page():
    return send_file('signup.html')

@app.route('/login') 
def login_page():
    return send_file('login.html')

@app.route('/dashboard')
def dashboard_page():
    return send_file('dashboard.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/audio/<filename>')
def serve_audio(filename):
    """Serve generated audio files"""
    try:
        return send_from_directory('audio_files', filename)
    except:
        return "Audio not found", 404

# API Routes
@app.route('/api/health')
def health_check():
    """Health check for monitoring"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM users')
            user_count = cursor.fetchone()['count']
    except:
        user_count = 0
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'users': user_count,
        'services': {
            'openai': bool(openai_client),
            'database': True
        }
    })

# DEMO API ENDPOINT - FIXED VERSION
@app.route('/api/demo/chat', methods=['POST'])
def demo_chat():
    """Handle demo chat requests from landing page"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
        
        user_message = data.get('message', '').strip()
        business_config = data.get('config', {})
        conversation_history = data.get('conversationHistory', [])
        
        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400
        
        # Get client IP for session tracking
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Generate AI response
        try:
            ai_response = generate_demo_ai_response(user_message, business_config, conversation_history)
        except Exception as e:
            logger.error(f"AI response generation failed: {e}")
            ai_response = generate_fallback_response(user_message, business_config)
        
        # Track demo usage (optional analytics)
        try:
            session_id = str(uuid.uuid4())
            session_data = {
                'id': session_id,
                'session_ip': client_ip,
                'business_config': business_config,
                'conversation': conversation_history + [
                    {'role': 'user', 'content': user_message},
                    {'role': 'assistant', 'content': ai_response}
                ]
            }
            db.create_demo_session(session_data)
        except Exception as e:
            logger.warning(f"Demo session tracking failed: {e}")
        
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

def generate_demo_ai_response(user_message, business_config, conversation_history):
    """Generate AI response using OpenAI for demo"""
    if not openai_client:
        return generate_fallback_response(user_message, business_config)
    
    try:
        # Extract business details
        business_name = business_config.get('businessName', 'our company')
        business_type = business_config.get('businessType', 'business')
        business_hours = business_config.get('businessHours', 'regular business hours')
        custom_instructions = business_config.get('instructions', '')
        phone_number = business_config.get('phoneNumber', '(555) 123-4567')
        
        # Build system prompt with business context
        system_prompt = f"""You are a helpful customer service AI assistant for {business_name}, a {business_type}. 

Business Details:
- Company: {business_name}
- Type: {business_type}  
- Hours: {business_hours}
- Phone: {phone_number}

Instructions: {custom_instructions}

Guidelines:
- Be friendly, professional, and helpful
- Keep responses concise (under 100 words) since this is a demo
- Reference the business name and type naturally in responses
- Offer to escalate to human agents when appropriate
- Ask clarifying questions to better assist customers
- If asked about specific products/services, provide general helpful information

Respond as if you're answering a real customer inquiry for this business."""
        
        # Build conversation messages
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add recent conversation history (last 3 exchanges)
        for exchange in conversation_history[-6:]:  # Last 3 user-assistant pairs
            if exchange.get('role') == 'user':
                messages.append({"role": "user", "content": exchange['content']})
            elif exchange.get('role') == 'assistant':
                messages.append({"role": "assistant", "content": exchange['content']})
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        # Generate response
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=150,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return generate_fallback_response(user_message, business_config)

def generate_fallback_response(user_message, business_config):
    """Generate fallback response when OpenAI is unavailable"""
    business_name = business_config.get('businessName', 'our company')
    business_type = business_config.get('businessType', 'business')
    
    # Simple keyword-based responses
    message_lower = user_message.lower()
    
    if any(word in message_lower for word in ['hours', 'open', 'time']):
        return f"Hi! {business_name} is typically open during regular business hours. For specific hours, please call us directly or visit our website."
    
    elif any(word in message_lower for word in ['price', 'cost', 'fee']):
        return f"Thanks for asking about pricing! {business_name} offers competitive rates for our {business_type} services. I'd be happy to connect you with someone who can provide detailed pricing information."
    
    elif any(word in message_lower for word in ['help', 'support', 'problem']):
        return f"I'm here to help! As {business_name}'s AI assistant, I can assist with general questions about our {business_type} services. What specific issue can I help you with today?"
    
    elif any(word in message_lower for word in ['hello', 'hi', 'hey']):
        return f"Hello! Welcome to {business_name}. I'm your AI assistant, ready to help with any questions about our {business_type} services. How can I assist you today?"
    
    else:
        return f"Thank you for contacting {business_name}! I understand you're asking about: '{user_message}'. While I'd love to provide more specific information, I'd recommend speaking with one of our team members who can give you detailed assistance with our {business_type} services."

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """User registration"""
    try:
        data = request.get_json()
        
        # Extract and validate fields
        first_name = data.get('firstName', '').strip()
        last_name = data.get('lastName', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Validation
        if not all([first_name, last_name, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if db.get_user_by_email(email):
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        password_hash = SecurityManager.hash_password(password)
        user_id = db.create_user(first_name, last_name, email, password_hash)
        
        logger.info(f"User created: {email}")
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'phoneNumber': SHARED_PHONE_NUMBER
        })
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """User login"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = db.get_user_by_email(email)
        if not user or not SecurityManager.verify_password(password, user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
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

@app.route('/api/user/settings', methods=['GET', 'POST'])
@require_auth
def user_settings():
    """Get or update user settings"""
    user_id = request.current_user['user_id']
    
    if request.method == 'GET':
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT settings FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            settings = json.loads(row['settings']) if row and row['settings'] else {}
            return jsonify(settings)
    
    elif request.method == 'POST':
        settings = request.get_json()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET settings = ? WHERE id = ?', 
                         (json.dumps(settings), user_id))
            conn.commit()
            return jsonify({'success': True})

# Twilio Voice Routes
@app.route('/api/twilio/voice', methods=['POST'])
def handle_incoming_call():
    """Handle incoming Twilio voice calls"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        
        # Store call session
        db.create_call_session(call_sid, None, from_number)
        
        # Initialize conversation in memory
        active_calls[call_sid] = []
        
        response = VoiceResponse()
        
        # Welcome message
        response.say(
            "Hello! You've reached Voxcord's AI-powered support line. "
            "I'm here to help with any questions you may have. "
            "Please tell me how I can assist you today.",
            voice='Polly.Joanna'
        )
        
        # Gather speech input
        gather = Gather(
            input='speech',
            timeout=10,
            speechTimeout='auto',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST'
        )
        
        gather.say("Please speak after the tone, and I'll do my best to help you.", voice='Polly.Joanna')
        response.append(gather)
        
        # Fallback if no speech detected
        response.say("I didn't hear anything. Please call back when you're ready to talk. Thank you!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Voice call error: {e}")
        
        # Always return a valid TwiML response
        response = VoiceResponse()
        response.say("I'm sorry, there was a technical issue. Please try calling back in a few minutes.")
        return str(response)

@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech(call_sid):
    """Handle speech input from call with OpenAI voice responses"""
    try:
        speech_result = request.form.get('SpeechResult')
        
        if not speech_result:
            response = VoiceResponse()
            response.say("I didn't catch that. Please try again.", voice='Polly.Joanna')
            return str(response)
        
        # Get or initialize conversation history
        conversation = active_calls.get(call_sid, [])
        
        # Generate AI response
        ai_response = generate_ai_response(speech_result, conversation)
        
        # Update conversation history
        conversation.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        active_calls[call_sid] = conversation
        
        # Update database
        db.update_call_conversation(call_sid, conversation)
        
        # Create TwiML response
        response = VoiceResponse()
        response.say(ai_response, voice='Polly.Joanna')
        
        # Continue conversation
        gather = Gather(
            input='speech',
            timeout=10,
            speechTimeout='auto',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST'
        )
        
        gather.say("Is there anything else I can help you with?", voice='Polly.Joanna')
        response.append(gather)
        
        # End call option
        response.say("Thank you for calling. Have a great day!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble understanding. Please try again.", voice='Polly.Joanna')
        return str(response)

def generate_ai_response(user_input, conversation_history):
    """Generate AI response using OpenAI for phone calls"""
    try:
        if not openai_client:
            return "I'm sorry, I'm currently unavailable. Please try again later."
        
        # Build context
        messages = [
            {
                "role": "system", 
                "content": "You are a helpful customer service assistant. Be friendly, professional, and concise. Keep responses under 50 words for phone conversations."
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
        logger.error(f"AI response error: {e}")
        return "I apologize, but I'm having trouble processing your request right now."

# Dashboard API Routes
@app.route('/api/dashboard/stats')
@require_auth
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        calls = db.get_recent_calls(30)  # Last 30 calls
        
        return jsonify({
            'totalCalls': len(calls),
            'recentCalls': calls[:10],
            'phoneNumber': SHARED_PHONE_NUMBER
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to load stats'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Validate required environment variables
    if not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY not set - AI responses will be limited")
    
    logger.info("Starting Voxcord server...")
    logger.info(f"Shared phone number: {SHARED_PHONE_NUMBER}")
    
    app.run(host='0.0.0.0', port=Config.PORT, debug=False)
