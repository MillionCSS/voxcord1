#!/usr/bin/env python3
"""
Enhanced Voxcord Backend with:
- PostgreSQL for persistent accounts
- Individual phone number purchasing
- Per-number AI customization
- Comprehensive debugging
"""

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
import psycopg2
import hashlib
import secrets
import jwt
import re

# Import our custom database and phone managers
# (The PersistentDatabaseManager and PhoneNumberManager classes would be in separate files)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    DATABASE_URL = os.getenv('DATABASE_URL')  # Digital Ocean provides this
    PORT = int(os.getenv('PORT', 5000))
    WEBHOOK_BASE_URL = os.getenv('WEBHOOK_BASE_URL', 'https://voxcord.com')

app.config['SECRET_KEY'] = Config.SECRET_KEY

# Initialize OpenAI
openai_client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None

# Initialize our enhanced database manager
from persistent_database import PersistentDatabaseManager  # This would be imported
from phone_manager import PhoneNumberManager  # This would be imported

db = PersistentDatabaseManager()
phone_manager = PhoneNumberManager(db)

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
    try:
        return send_file('landing.html')
    except:
        return jsonify({
            'message': 'Voxcord API is running',
            'status': 'healthy',
            'database': 'postgresql' if db.database_url else 'sqlite'
        })

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

# DEBUGGING ROUTES
@app.route('/debug/database')
def debug_database():
    """Debug database connection and users"""
    try:
        user_count = db.debug_user_count()
        recent_users = db.debug_list_users()
        
        return jsonify({
            'database_type': db.db_type,
            'database_url_set': bool(db.database_url),
            'total_users': user_count,
            'recent_users': recent_users,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'database_type': getattr(db, 'db_type', 'unknown')
        }), 500

@app.route('/debug/test-user')
def debug_test_user():
    """Create a test user to verify persistence"""
    try:
        test_user_data = {
            'id': str(uuid.uuid4()),
            'first_name': 'Debug',
            'last_name': 'User',
            'email': f'debug-{int(time.time())}@voxcord.com',
            'password_hash': SecurityManager.hash_password('test123'),
            'company': 'Test Company',
            'plan': 'free'
        }
        
        user_id = db.create_user(test_user_data)
        
        # Verify the user was created
        created_user = db.get_user_by_email(test_user_data['email'])
        
        return jsonify({
            'success': True,
            'message': 'Test user created and verified',
            'user_id': user_id,
            'email': test_user_data['email'],
            'database_type': db.db_type,
            'user_verified': bool(created_user)
        })
    except Exception as e:
        logger.error(f"Test user creation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'database_type': db.db_type
        }), 500

# API Routes
@app.route('/api/health')
def health_check():
    """Enhanced health check with database status"""
    try:
        user_count = db.debug_user_count()
        
        # Test database connection
        db_status = 'connected'
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1')
        except:
            db_status = 'error'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': {
                'type': db.db_type,
                'status': db_status,
                'users': user_count
            },
            'services': {
                'openai': bool(openai_client),
                'twilio': bool(phone_manager.twilio_client),
                'database': db_status == 'connected'
            },
            'environment': {
                'database_url_set': bool(Config.DATABASE_URL),
                'openai_key_set': bool(Config.OPENAI_API_KEY),
                'twilio_configured': bool(Config.TWILIO_ACCOUNT_SID and Config.TWILIO_AUTH_TOKEN)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Enhanced user registration with proper persistence"""
    try:
        data = request.get_json()
        logger.info(f"Signup attempt for: {data.get('email', 'no-email')}")
        
        # Validate required fields
        required = ['firstName', 'lastName', 'email', 'password']
        for field in required:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Validate email
        if not SecurityManager.validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        # Check if user exists
        existing_user = db.get_user_by_email(email)
        if existing_user:
            logger.warning(f"Signup attempt with existing email: {email}")
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Validate password
        if len(data['password']) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        user_data = {
            'id': user_id,
            'first_name': data['firstName'],
            'last_name': data['lastName'],
            'email': email,
            'password_hash': SecurityManager.hash_password(data['password']),
            'company': data.get('company', ''),
            'industry': data.get('industry', ''),
            'plan': data.get('plan', 'free')
        }
        
        # Create user in database
        created_user_id = db.create_user(user_data)
        
        # Verify user was created
        verification = db.get_user_by_email(email)
        if not verification:
            logger.error(f"User creation verification failed for {email}")
            return jsonify({'success': False, 'error': 'Account creation failed - please try again'}), 500
        
        logger.info(f"User successfully created: {email} (ID: {created_user_id})")
        
        # Create JWT token for immediate login
        token = create_jwt_token(verification)
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'token': token,
            'user': {
                'id': verification['id'],
                'firstName': verification['first_name'],
                'lastName': verification['last_name'],
                'email': verification['email'],
                'plan': verification['plan']
            }
        })
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed - please try again'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """Enhanced user login with debugging"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        logger.info(f"Login attempt for: {email}")
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'}), 400
        
        user = db.get_user_by_email(email)
        if not user:
            logger.warning(f"Login failed - user not found: {email}")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        if not SecurityManager.verify_password(password, user['password_hash']):
            logger.warning(f"Login failed - wrong password: {email}")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        token = create_jwt_token(user)
        
        logger.info(f"Login successful: {email}")
        
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
        return jsonify({'success': False, 'error': 'Login failed'}), 500

# PHONE NUMBER MANAGEMENT ROUTES
@app.route('/api/phone/search', methods=['POST'])
@require_auth
def search_phone_numbers():
    """Search for available phone numbers"""
    try:
        data = request.get_json()
        area_code = data.get('area_code')
        country_code = data.get('country_code', 'US')
        limit = min(int(data.get('limit', 10)), 20)  # Max 20 results
        
        result = phone_manager.search_available_numbers(
            country_code=country_code,
            area_code=area_code,
            limit=limit
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Phone search error: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/phone/purchase', methods=['POST'])
@require_auth
def purchase_phone_number():
    """Purchase a phone number"""
    try:
        data = request.get_json()
        user_id = request.current_user['user_id']
        phone_number = data.get('phone_number')
        friendly_name = data.get('friendly_name')
        
        if not phone_number:
            return jsonify({'success': False, 'error': 'Phone number is required'}), 400
        
        # Check user's plan limits
        user = db.get_user_by_id(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Check current phone count
        current_phones = phone_manager.get_user_phone_summary(user_id)
        
        # Plan limits
        plan_limits = {
            'free': 1,
            'professional': 5,
            'enterprise': -1  # unlimited
        }
        
        max_phones = plan_limits.get(user['plan'], 1)
        if max_phones != -1 and current_phones['total_numbers'] >= max_phones:
            return jsonify({
                'success': False, 
                'error': f'{user["plan"].title()} plan allows maximum {max_phones} phone numbers'
            }), 400
        
        # Purchase the number
        result = phone_manager.purchase_phone_number(
            user_id=user_id,
            phone_number=phone_number,
            friendly_name=friendly_name
        )
        
        if result['success']:
            logger.info(f"Phone number {phone_number} purchased by user {user_id}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Phone purchase error: {e}")
        return jsonify({'success': False, 'error': 'Purchase failed'}), 500

@app.route('/api/phone/list')
@require_auth
def list_user_phone_numbers():
    """Get user's phone numbers"""
    try:
        user_id = request.current_user['user_id']
        summary = phone_manager.get_user_phone_summary(user_id)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Phone list error: {e}")
        return jsonify({'error': 'Failed to get phone numbers'}), 500

@app.route('/api/phone/<int:phone_id>/ai-settings', methods=['GET', 'POST'])
@require_auth
def phone_ai_settings(phone_id):
    """Get or update AI settings for a phone number"""
    user_id = request.current_user['user_id']
    
    if request.method == 'GET':
        try:
            # Get current settings
            user_phones = db.get_user_phone_numbers(user_id)
            phone_record = next((p for p in user_phones if p['id'] == phone_id), None)
            
            if not phone_record:
                return jsonify({'error': 'Phone number not found'}), 404
            
            # Parse AI settings
            if db.db_type == 'postgresql':
                ai_settings = phone_record.get('ai_settings', {})
                if isinstance(ai_settings, str):
                    ai_settings = json.loads(ai_settings)
            else:
                ai_settings_str = phone_record.get('ai_settings', '{}')
                ai_settings = json.loads(ai_settings_str) if ai_settings_str else {}
            
            return jsonify(ai_settings)
            
        except Exception as e:
            logger.error(f"Get AI settings error: {e}")
            return jsonify({'error': 'Failed to get settings'}), 500
    
    elif request.method == 'POST':
        try:
            ai_settings = request.get_json()
            
            result = phone_manager.update_ai_settings(user_id, phone_id, ai_settings)
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Update AI settings error: {e}")
            return jsonify({'success': False, 'error': 'Failed to update settings'}), 500

@app.route('/api/phone/<int:phone_id>/release', methods=['POST'])
@require_auth
def release_phone_number(phone_id):
    """Release a phone number"""
    try:
        user_id = request.current_user['user_id']
        result = phone_manager.release_phone_number(user_id, phone_id)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Phone release error: {e}")
        return jsonify({'success': False, 'error': 'Release failed'}), 500

# ENHANCED VOICE WEBHOOK with USER-SPECIFIC ROUTING
@app.route('/api/twilio/voice/<user_id>', methods=['POST'])
def handle_user_voice_call(user_id):
    """Handle voice calls for a specific user's phone number"""
    try:
        call_sid = request.form.get('CallSid')
        from_number = request.form.get('From')
        to_number = request.form.get('To')
        
        logger.info(f"User voice call: {call_sid} for user {user_id} from {from_number} to {to_number}")
        
        # Get phone context for this user
        phone_context = phone_manager.get_phone_context_by_webhook(user_id)
        
        if not phone_context:
            logger.warning(f"No phone context found for user {user_id}")
            response = VoiceResponse()
            response.say("I'm sorry, this number is temporarily unavailable.")
            return str(response)
        
        # Create call session
        call_data = {
            'id': str(uuid.uuid4()),
            'call_sid': call_sid,
            'caller_number': from_number
        }
        
        # Store in memory with context
        active_calls[call_sid] = {
            'conversation': [],
            'phone_context': phone_context,
            'user_id': user_id
        }
        
        # Create personalized greeting
        business_name = phone_context['business_context'].get('business_name', 'our company')
        greeting = phone_context['business_context'].get('greeting') or f"Hello! Thank you for calling {business_name}. How can I help you today?"
        voice = phone_context['business_context'].get('voice', 'Polly.Joanna')
        
        response = VoiceResponse()
        response.say(greeting, voice=voice, language='en-US')
        
        # Gather user input
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say("Please tell me what you need assistance with.", voice=voice)
        response.append(gather)
        
        response.say("I didn't hear anything. Please call back when you're ready to talk. Thank you!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"User voice call error: {e}")
        response = VoiceResponse()
        response.say("I'm sorry, there was a technical issue. Please try calling back in a few minutes.")
        return str(response)

@app.route('/api/twilio/gather/<call_sid>', methods=['POST'])
def handle_speech_with_context(call_sid):
    """Enhanced speech handler with user context"""
    try:
        speech_result = request.form.get('SpeechResult')
        
        if not speech_result:
            response = VoiceResponse()
            response.say("I didn't catch that. Could you please repeat that?", voice='Polly.Joanna')
            return str(response)
        
        # Get call context
        call_data = active_calls.get(call_sid)
        if not call_data:
            logger.warning(f"No call context found for {call_sid}")
            response = VoiceResponse()
            response.say("I'm sorry, there was an issue with your call.")
            return str(response)
        
        conversation = call_data['conversation']
        phone_context = call_data['phone_context']
        user_id = call_data['user_id']
        
        # Generate AI response with full context
        ai_response = generate_contextual_ai_response(speech_result, conversation, phone_context)
        
        # Update conversation
        conversation.append({
            'user': speech_result,
            'assistant': ai_response,
            'timestamp': time.time()
        })
        
        # Create response
        voice = phone_context['business_context'].get('voice', 'Polly.Joanna')
        business_name = phone_context['business_context'].get('business_name', 'us')
        
        response = VoiceResponse()
        response.say(ai_response, voice=voice)
        
        # Continue conversation
        gather = Gather(
            input='speech',
            action=f'/api/twilio/gather/{call_sid}',
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say(f"Is there anything else I can help you with regarding {business_name}?", voice=voice)
        response.append(gather)
        
        response.say(f"Thank you for calling {business_name}. Have a great day!")
        
        return str(response)
        
    except Exception as e:
        logger.error(f"Contextual speech handling error: {e}")
        response = VoiceResponse()
        response.say("I'm having trouble understanding. Could you please try again?", voice='Polly.Joanna')
        return str(response)

def generate_contextual_ai_response(user_input, conversation_history, phone_context):
    """Generate AI response with full business context"""
    try:
        if not openai_client:
            return generate_contextual_fallback(user_input, phone_context['business_context'])
        
        business = phone_context['business_context']
        
        system_prompt = f"""You are a professional customer service assistant for {business['business_name']}.

Business Context:
- Company: {business['business_name']}
- Type: {business.get('business_type', 'Company')}
- Instructions: {business.get('instructions', 'Be helpful and professional')}

Guidelines:
- Keep responses under 50 words for phone calls
- Be friendly, professional, and helpful
- Reference the business naturally in responses
- If you don't know something specific, offer to connect them with someone who can help
- Stay in character as {business['business_name']}'s assistant"""

        messages = [{"role": "system", "content": system_prompt}]
        
        # Add recent conversation
        for exchange in conversation_history[-3:]:
            messages.append({"role": "user", "content": exchange['user']})
            messages.append({"role": "assistant", "content": exchange['assistant']})
        
        messages.append({"role": "user", "content": user_input})
        
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=100,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Contextual AI response error: {e}")
        return generate_contextual_fallback(user_input, phone_context['business_context'])

def generate_contextual_fallback(user_input, business_context):
    """Generate business-aware fallback responses"""
    business_name = business_context.get('business_name', 'our company')
    
    message_lower = user_input.lower()
    
    if any(word in message_lower for word in ['hours', 'open', 'close']):
        return f"{business_name} customer service is here to help. What specific information do you need?"
    elif any(word in message_lower for word in ['help', 'support']):
        return f"I'm here to help with any {business_name} questions. What can I assist you with?"
    else:
        return f"Thank you for calling {business_name}. I'm here to help with any questions you may have."

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Enhanced Voxcord server...")
    logger.info(f"Database: {db.db_type}")
    logger.info(f"OpenAI configured: {bool(openai_client)}")
    logger.info(f"Twilio configured: {bool(phone_manager.twilio_client)}")
    
    # Test database connection
    try:
        user_count = db.debug_user_count()
        logger.info(f"Database connection successful - {user_count} users found")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
    
    app.run(host='0.0.0.0', port=Config.PORT, debug=False)
