#!/usr/bin/env python3
"""
Voxcord - Simplified AI Voice Assistant Platform
Clean, minimal production-ready version for Digital Ocean App Platform
Updated to work with Integrated Frontend Landing Page
"""

import os
import hashlib
import secrets
import jwt
import json
import sqlite3
import uuid
import time
import re
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_file, send_from_directory
from twilio.twiml.voice_response import VoiceResponse, Gather
from openai import OpenAI

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID') 
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    PORT = int(os.getenv('PORT', 5000))

app.config['SECRET_KEY'] = Config.SECRET_KEY

# Simple CORS handling for frontend integration
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Initialize OpenAI
openai_client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None

# Constants
SHARED_PHONE_NUMBER = "+16095073300"

# Create directories
AUDIO_DIR = Path("audio_files")
AUDIO_DIR.mkdir(exist_ok=True)

# Database Manager
class DatabaseManager:
    def __init__(self):
        self.db_path = 'voxcord.db'
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
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
                    company TEXT DEFAULT '',
                    plan TEXT DEFAULT 'free',
                    verified BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    settings TEXT DEFAULT '{}'
                )
            ''')
            
            # Call sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS call_sessions (
                    id TEXT PRIMARY KEY,
                    call_sid TEXT UNIQUE,
                    caller_number TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    conversation TEXT DEFAULT '[]'
                )
            ''')
            
            # Demo sessions table for landing page analytics
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
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, user_data):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (id, first_name, last_name, email, password_hash, company, plan)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_data['id'], user_data['first_name'], user_data['last_name'],
                user_data['email'], user_data['password_hash'], 
                user_data.get('company', ''), user_data.get('plan', 'free')
            ))
            conn.commit()
    
    def get_user_by_email(self, email):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def create_call_session(self, call_data):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO call_sessions (id, call_sid, caller_number)
                VALUES (?, ?, ?)
            ''', (call_data['id'], call_data['call_sid'], call_data.get('caller_number', '')))
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
        """Create demo session for landing page analytics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO demo_sessions (id, session_ip, business_config, conversation, messages_count)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session_data['id'],
                session_data.get('session_ip', ''),
                json.dumps(session_data.get('business_config', {})),
                json.dumps(session_data.get('conversation', [])),
                session_data.get('messages_count', 0)
            ))
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

# Routes
@app.route('/')
def index():
    # Try to serve the integrated landing page first, fallback to simple landing
    try:
        return send_file('Voxcord - Integrated Landing Page with Working Demo.html')
    except:
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

# DEMO API ENDPOINT FOR INTEGRATED FRONTEND
@app.route('/api/demo/chat', methods=['POST'])
def demo_chat():
    """Handle demo chat requests from the integrated landing page"""
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
        
        # Track demo usage for analytics
        try:
            session_id = str(uuid.uuid4())
            updated_conversation = conversation_history + [
                {'role': 'user', 'content': user_message},
                {'role': 'assistant', 'content': ai_response}
            ]
            
            session_data = {
                'id': session_id,
                'session_ip': client_ip,
                'business_config': business_config,
                'conversation': updated_conversation,
                'messages_count': len(updated_conversation)
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
    """Generate AI response using OpenAI for the landing page demo"""
    if not openai_client:
        logger.warning("OpenAI client not available, using fallback")
        return generate_fallback_response(user_message, business_config)
    
    try:
        # Extract business details from config
        business_name = business_config.get('businessName', 'our company')
        business_type = business_config.get('businessType', 'business')
        business_hours = business_config.get('businessHours', 'regular business hours')
        phone_number = business_config.get('phoneNumber', '(555) 123-4567')
        custom_instructions = business_config.get('instructions', '')
        
        # Build comprehensive system prompt
        system_prompt = f"""You are a professional AI customer service assistant for {business_name}, a {business_type}.

Business Information:
- Company Name: {business_name}
- Business Type: {business_type}
- Operating Hours: {business_hours}
- Phone Number: {phone_number}
- Special Instructions: {custom_instructions}

Your Role:
- Provide helpful, friendly, and professional customer service
- Keep responses conversational and concise (under 100 words for demos)
- Reference the business naturally in your responses
- Offer to connect customers with human agents when appropriate
- Ask clarifying questions to better understand customer needs
- Provide general information about the business type and services

Guidelines:
- Always be polite and empathetic
- If you don't have specific information, offer to find out or escalate
- Maintain the conversation flow naturally
- Show that you understand the business context"""
        
        # Build conversation messages for OpenAI
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add recent conversation history (last 6 messages for context)
        for exchange in conversation_history[-6:]:
            if exchange.get('role') and exchange.get('content'):
                messages.append({
                    "role": exchange['role'],
                    "content": exchange['content']
                })
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        # Generate response with OpenAI
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=150,
            temperature=0.7,
            presence_penalty=0.1,
            frequency_penalty=0.1
        )
        
        ai_response = response.choices[0].message.content.strip()
        logger.info(f"Generated OpenAI response for {business_name}")
        return ai_response
        
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return generate_fallback_response(user_message, business_config)

def generate_fallback_response(user_message, business_config):
    """Generate intelligent fallback responses when OpenAI is unavailable"""
    business_name = business_config.get('businessName', 'our company')
    business_type = business_config.get('businessType', 'business')
    business_hours = business_config.get('businessHours', 'regular business hours')
    phone_number = business_config.get('phoneNumber', '(555) 123-4567')
    
    message_lower = user_message.lower()
    
    # Greeting responses
    if any(word in message_lower for word in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        return f"Hello! Welcome to {business_name}. I'm your AI customer service assistant, ready to help with any questions about our {business_type} services. How can I assist you today?"
    
    # Hours and availability
    elif any(word in message_lower for word in ['hours', 'open', 'close', 'time', 'when', 'available']):
        return f"Great question! {business_name} operates during {business_hours}. You can also reach us at {phone_number}. For urgent matters outside business hours, I'm here 24/7 to help with basic questions. What specific information do you need?"
    
    # Pricing and costs
    elif any(word in message_lower for word in ['price', 'cost', 'fee', 'charge', 'rate', 'expensive', 'cheap', 'how much']):
        return f"I'd be happy to help with pricing information for {business_name}'s {business_type} services. For accurate quotes and current rates, I recommend speaking with our team directly at {phone_number}. Can you tell me what specific service you're interested in?"
    
    # Help and support
    elif any(word in message_lower for word in ['help', 'support', 'problem', 'issue', 'trouble', 'assistance']):
        return f"I'm here to help! As {business_name}'s AI assistant, I can provide information about our {business_type} services and help resolve common questions. What specific issue or question can I assist you with today?"
    
    # Services and products
    elif any(word in message_lower for word in ['service', 'product', 'offer', 'provide', 'do you have', 'what do you']):
        return f"{business_name} specializes in {business_type} services. While I can provide general information, our team can give you detailed information about all our offerings. What specific service are you interested in learning about?"
    
    # Location and contact
    elif any(word in message_lower for word in ['location', 'address', 'where', 'contact', 'phone', 'call']):
        return f"You can contact {business_name} at {phone_number}. We're a {business_type} and are available during {business_hours}. Is there something specific you'd like to know or discuss with our team?"
    
    # Complaints or concerns
    elif any(word in message_lower for word in ['complaint', 'unhappy', 'disappointed', 'wrong', 'bad', 'terrible']):
        return f"I'm sorry to hear you're having concerns. At {business_name}, we take customer feedback seriously. I'd like to help resolve this issue. Can you tell me more about what happened, or would you prefer to speak directly with a manager at {phone_number}?"
    
    # Thank you responses
    elif any(word in message_lower for word in ['thank', 'thanks', 'appreciate']):
        return f"You're very welcome! I'm glad I could help. {business_name} is always here to assist with your {business_type} needs. If you have any other questions, feel free to ask or contact us at {phone_number}."
    
    # Default comprehensive response
    else:
        return f"Thank you for contacting {business_name}! I understand you're asking about: \"{user_message}\". While I'd love to provide detailed information, I want to make sure you get the most accurate answer. Our {business_type} specialists at {phone_number} would be the best resource for this question. Is there anything else I can help you with in the meantime?"

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """User registration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['firstName', 'lastName', 'email', 'password']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Validate email
        if not SecurityManager.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user exists
        if db.get_user_by_email(email):
            return jsonify({'error': 'Email already registered'}), 400
        
        # Validate password
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        user_data = {
            'id': user_id,
            'first_name': data['firstName'],
            'last_name': data['lastName'],
            'email': email,
            'password_hash': SecurityManager.hash_password(data['password']),
            'company': data.get('company', ''),
            'plan': data.get('plan', 'free')
        }
        
        db.create_user(user_data)
        
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

@app.route('/api/calls')
@require_auth  
def get_calls():
    """Get recent calls for dashboard"""
    calls = db.get_recent_calls()
    
    # Format calls for frontend
    formatted_calls = []
    for call in calls:
        conversation = json.loads(call.get('conversation', '[]'))
        formatted_calls.append({
            'id': call['call_sid'],
            'time': call['started_at'],
            'duration': '2m 15s',  # TODO: Calculate actual duration
            'status': call['status'],
            'preview': conversation[-1].get('user', 'No conversation') if conversation else 'No conversation'
        })
    
    return jsonify(formatted_calls)

# Twilio Voice Webhook
@app.route('/api/twilio/voice', methods=['POST'])
def handle_voice_call():
    """Handle incoming Twilio voice calls with OpenAI voices"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        
        logger.info(f"Incoming call: {call_sid} from {from_number}")
        
        # Create call session
        call_data = {
            'id': str(uuid.uuid4()),
            'call_sid': call_sid,
            'caller_number': from_number
        }
        db.create_call_session(call_data)
        
        # Initialize conversation in memory
        active_calls[call_sid] = []
        
        # Default greeting
        greeting_text = "Hello! Welcome to Voxcord. How can I help you today?"
        
        response = VoiceResponse()
        response.say(greeting_text, voice='Polly.Joanna', language='en-US')
        
        # Gather user input
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Please tell me what you need assistance with.", voice='Polly.Joanna')
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
    """Handle speech input from call"""
    try:
        speech_result = request.form.get('SpeechResult')
        
        if not speech_result:
            response = VoiceResponse()
            response.say("I didn't catch that. Please try again.", voice='Polly.Joanna')
            return str(response)
        
        # Get conversation from memory
        conversation = active_calls.get(call_sid, [])
        
        # Generate AI response
        ai_response = generate_ai_response(speech_result, conversation)
        
        # Update conversation
        conversation.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': time.time()
        })
        active_calls[call_sid] = conversation
        
        # Save to database
        db.update_call_conversation(call_sid, conversation)
        
        response = VoiceResponse()
        response.say(ai_response, voice='Polly.Joanna')
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# Handle OPTIONS requests for CORS
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return '', 200

if __name__ == '__main__':
    # Validate required environment variables
    if not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY not set - AI responses will be limited")
    
    logger.info("Starting Voxcord server...")
    logger.info(f"Shared phone number: {SHARED_PHONE_NUMBER}")
    
    app.run(host='0.0.0.0', port=Config.PORT, debug=False)
