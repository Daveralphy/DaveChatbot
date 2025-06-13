import os
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai
from functools import wraps
import json
# REMOVED: from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import boto3
import logging

# --- ADD THESE IMPORTS FOR LAMBDA HANDLER ---
from werkzeug.wrappers import Request, Response
from io import BytesIO
import base64
from werkzeug.datastructures import Headers
# --- END ADDITIONS ---

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file (for local development)
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
logging.info(f"DEBUG: Flask secret key being used: {app.secret_key}")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable not set. Please add it to your .env file.")

# Set session to be permanent (e.g., lasts for 7 days)
app.permanent_session_lifetime = timedelta(days=7)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set.")
genai.configure(api_key=GEMINI_API_KEY)

# --- AWS Service Clients ---
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
S3_PERSONA_KEY = 'persona.json' # The object key/path to your persona file in S3
USERS_TABLE_NAME = os.getenv('USERS_TABLE_NAME') # DynamoDB table for users
CHAT_HISTORY_TABLE_NAME = os.getenv('CHAT_HISTORY_TABLE_NAME') # DynamoDB table for chat history
AWS_REGION = os.getenv('AWS_REGION') # Get AWS region from environment variable

# Ensure AWS_REGION is set before initializing boto3 clients
if not AWS_REGION:
    raise ValueError("AWS_REGION environment variable not set. Boto3 cannot initialize.")

s3_client = boto3.client('s3', region_name=AWS_REGION) # Pass region_name explicitly
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION) # Pass region_name explicitly


# Initialize DynamoDB tables (will load table objects when names are available)
users_table = None
chat_history_table = None

def init_db_tables():
    global users_table, chat_history_table
    if USERS_TABLE_NAME:
        users_table = dynamodb.Table(USERS_TABLE_NAME)
        logging.info(f"DynamoDB Users Table initialized: {USERS_TABLE_NAME}")
    else:
        logging.error("USERS_TABLE_NAME environment variable not set. User authentication will not work.")

    if CHAT_HISTORY_TABLE_NAME:
        chat_history_table = dynamodb.Table(CHAT_HISTORY_TABLE_NAME)
        logging.info(f"DynamoDB Chat History Table initialized: {CHAT_HISTORY_TABLE_NAME}")
    else:
        logging.error("CHAT_HISTORY_TABLE_NAME environment variable not set. Persistent chat history will not work.")

# Call initialization when app starts (important for Lambda cold starts)
# This `with app.app_context():` block should be *after* `app = Flask(__name__)`
# and before any routes are defined.
with app.app_context():
    init_db_tables()


# --- Persona Loading from S3 ---
def load_persona_from_s3():
    if not S3_BUCKET_NAME:
        logging.warning("S3_BUCKET_NAME environment variable not set. Persona history will not be loaded from S3.")
        return []
    try:
        logging.info(f"Attempting to load persona.json from s3://{S3_BUCKET_NAME}/{S3_PERSONA_KEY}")
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=S3_PERSONA_KEY)
        persona_data = response['Body'].read().decode('utf-8')
        return json.loads(persona_data)
    except s3_client.exceptions.NoSuchKey:
        logging.warning(f"Persona file '{S3_PERSONA_KEY}' not found in bucket '{S3_BUCKET_NAME}'. Chatbot will start without pre-defined persona.")
        return []
    except Exception as e:
        logging.error(f"Error loading persona from S3: {e}. Chatbot will start without pre-defined persona.")
        return []

# Load persona at app startup from S3
persona_history = load_persona_from_s3()

# Initialize the Generative Model
model = genai.GenerativeModel('gemini-1.5-flash-latest')

# --- Persona instruction moved into the beginning of the history ---
initial_persona_prompt = [
    {
        "role": "user",
        "parts": ["You are Dave, a helpful chat assistant created by Raphael Daveal. You will always respond as Dave and adhere to the persona provided in your training data."],
    },
    {
        "role": "model",
        "parts": ["Okay, I understand. I am Dave, and I will respond as a helpful chat assistant created by Raphael Daveal, adhering to my defined persona."]
    }
]

# --- Helper functions for DynamoDB Chat History ---
def load_user_chat_history(user_id):
    if not chat_history_table:
        logging.error("Chat history table not initialized. Cannot load history.")
        return []
    try:
        response = chat_history_table.get_item(Key={'user_id': str(user_id)})
        if 'Item' in response and 'history' in response['Item']:
            # DynamoDB stores list of maps, ensure it's loaded as list of dictionaries
            loaded_history_json = response['Item']['history']
            loaded_history = json.loads(loaded_history_json) if isinstance(loaded_history_json, str) else loaded_history_json
            logging.info(f"Loaded chat history for user {user_id}. Length: {len(loaded_history)}")
            return loaded_history
        return []
    except Exception as e:
        logging.error(f"Error loading chat history for user {user_id} from DynamoDB: {e}", exc_info=True)
        return []

def save_user_chat_history(user_id, history):
    if not chat_history_table:
        logging.error("Chat history table not initialized. Cannot save history.")
        return
    try:
        # DynamoDB doesn't directly support nested lists of varied types perfectly
        # Best practice is to JSON dump complex objects before saving
        history_to_save_json = json.dumps(history)
        chat_history_table.put_item(
            Item={
                'user_id': str(user_id),
                'history': history_to_save_json
            }
        )
        logging.info(f"Saved chat history for user {user_id}.")
    except Exception as e:
        logging.error(f"Error saving chat history for user {user_id} to DynamoDB: {e}", exc_info=True)

# Helper function to get/initialize chat session history for a user
def get_gemini_chat_session():
    user_id = session.get('user_id')
    if user_id:
        # Attempt to load history from DynamoDB first
        user_chat_history = load_user_chat_history(user_id)
        if not user_chat_history: # If no history in DB, initialize with persona
            user_chat_history = initial_persona_prompt + persona_history
            logging.info(f"Initialized new chat session (no DB history) for user: {session.get('username', 'Guest')}")
        else:
            logging.info(f"Loaded chat session from DB for user: {session.get('username', 'Guest')}")
        session['user_chat_history'] = user_chat_history
    elif 'user_chat_history' not in session: # For guests or if no user_id
        session['user_chat_history'] = initial_persona_prompt + persona_history
        logging.info(f"Initialized new chat session for anonymous/guest user.")

    return model.start_chat(history=session['user_chat_history'])


# --- Authentication Decorator and Routes with DynamoDB ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning("Unauthorized access attempt (no user_id in session).")
            return jsonify({"error": "Unauthorized"}), 401
        if not users_table:
            logging.error("Users table not initialized. Authentication disabled.")
            return jsonify({"error": "Authentication system not configured."}), 500 # Added error for uninitialized DB
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if not users_table:
        logging.error("Users table not initialized. Registration disabled.")
        return jsonify({"error": "Registration system not configured."}), 500

    username = request.json.get('username')
    email = request.json.get('email') # Get email from request
    password = request.json.get('password')

    if not username or not email or not password: # Ensure email is also required for registration
        logging.warning("Registration attempt with missing username, email, or password.")
        return jsonify({"error": "Username, email, and password are required"}), 400

    try:
        # Check if username already exists
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            logging.warning(f"Registration attempt for existing username: {username}.")
            return jsonify({"error": "Username already exists"}), 409 # 409 Conflict

        # Hash password
        password_hash = generate_password_hash(password)

        # For simplicity, let's use the username itself as user_id as it's unique PK
        user_id = username 

        users_table.put_item(
            Item={
                'username': username,
                'password_hash': password_hash,
                'user_id': user_id, # Store an ID for session tracking, but username is PK
                'email': email # Store the email
            }
        )
        logging.info(f"User '{username}' registered successfully with user_id: {user_id}")
        return jsonify({"message": "Registration successful"}), 201 # 201 Created
    except Exception as e:
        logging.error(f"Error during registration for user '{username}': {e}", exc_info=True)
        return jsonify({"error": "Registration failed due to server error."}), 500


@app.route('/login', methods=['POST'])
def login():
    if not users_table:
        logging.error("Users table not initialized. Login disabled.")
        return jsonify({"error": "Login system not configured."}), 500

    username = request.json.get('username')
    password = request.json.get('password')

    try:
        response = users_table.get_item(Key={'username': username})
        user_data = response.get('Item')

        if user_data and check_password_hash(user_data['password_hash'], password):
            session['logged_in'] = True
            session['username'] = user_data['username']
            session['user_id'] = user_data['user_id'] # Use the user_id stored in DynamoDB
            session.permanent = True

            # Load chat history for the logged-in user from DynamoDB
            session['user_chat_history'] = load_user_chat_history(user_data['user_id'])
            if not session['user_chat_history']: # If no history from DB, initialize with persona
                session['user_chat_history'] = initial_persona_prompt + persona_history
            
            logging.info(f"User '{username}' logged in. Chat history initialized/loaded.")
            return jsonify({"message": "Login successful", "username": user_data['username'], "email": user_data.get('email')}), 200 # Include email in response
        else:
            logging.warning(f"Login failed for user '{username}'. Invalid credentials.")
            session['logged_in'] = False
            session.pop('username', None)
            session.pop('user_id', None)
            session.pop('user_chat_history', None)
            session.permanent = False
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        logging.error(f"Error during login for user '{username}': {e}", exc_info=True)
        return jsonify({"error": "Login failed due to server error."}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id = session.get('user_id')
    if user_id and 'user_chat_history' in session:
        # Save current chat history to DynamoDB before logging out
        save_user_chat_history(user_id, session['user_chat_history'])

    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('user_chat_history', None)
    session.permanent = False
    logging.info(f"User '{session.get('username', 'Anonymous')}' logged out. Chat history cleared/saved.")
    return jsonify({"message": "Logged out"}), 200

@app.route('/check_login_status', methods=['GET'])
def check_login_status():
    if 'user_id' in session:
        user_id = session['user_id']
        # Fetch full user data from DynamoDB to get the latest username and email
        try:
            user_response = users_table.get_item(Key={'username': user_id}) # Assuming user_id is the username for lookup
            user_data = user_response.get('Item', {})
        except Exception as e:
            logging.error(f"Error fetching user data for check_login_status for user {user_id}: {e}", exc_info=True)
            user_data = {} # Fallback to empty dict if lookup fails

        # Ensure chat history is initialized if not already present (for hot reloads)
        if 'user_chat_history' not in session:
            # This case might happen if session state was restored but history wasn't loaded from DB yet
            session['user_chat_history'] = load_user_chat_history(user_id)
            if not session['user_chat_history']:
                session['user_chat_history'] = initial_persona_prompt + persona_history
            
        # Calculate the length of the non-conversational history (persona + persona.json)
        persona_base_length = len(initial_persona_prompt) + len(persona_history)
        
        # Extract only the actual conversation messages (user and model turns)
        conversation_messages = session['user_chat_history'][persona_base_length:]

        logging.info(f"Login status check: User '{user_data.get('username')}' is logged in.")
        return jsonify({
            "logged_in": True, 
            "username": user_data.get('username'),
            "email": user_data.get('email'), # Include email in response
            "chat_history": conversation_messages
        }), 200
    else:
        logging.info("Login status check: User is not logged in.")
        return jsonify({"logged_in": False}), 401

@app.route('/chat', methods=['POST'])
@login_required
def chat_endpoint():
    try:
        user_message = request.json.get('message')
        if not user_message:
            logging.warning("Chat attempt with no message provided.")
            return jsonify({"error": "No message provided"}), 400

        user_id = session.get('user_id')
        username = session.get('username', 'Anonymous')
        logging.info(f"User '{username}' (ID: {user_id}) message: {user_message}")
        
        chat_session = get_gemini_chat_session() # This loads/initia.lizes history
        
        response = chat_session.send_message(user_message)
        bot_response = response.text
        
        # Append new messages to the session history
        session['user_chat_history'].append({"role": "user", "parts": [user_message]})
        session['user_chat_history'].append({"role": "model", "parts": [bot_response]})
        session.modified = True # Tell Flask the session data has been modified

        # Save updated history to DynamoDB after each turn (or periodically)
        if user_id:
            save_user_chat_history(user_id, session['user_chat_history'])

        logging.info(f"Bot response for user '{username}': {bot_response}")

        return jsonify({"response": bot_response})

    except Exception as e:
        logging.error(f"Error during chat for user '{session.get('username', 'Anonymous')}': {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/new_chat')
@login_required
def new_chat():
    user_id = session.get('user_id')
    if user_id and 'user_chat_history' in session:
        # Save current history before clearing for new chat
        save_user_chat_history(user_id, session['user_chat_history'])

    session.pop('user_chat_history', None) # Clear the current user's chat history
    session.modified = True # Indicate session modified
    logging.info(f"User '{session.get('username', 'Anonymous')}' started a new chat.")
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=session.get('username'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')


# --- LAMBDA HANDLER FOR WSGI APPLICATIONS (REPLACES wsgi-aws-lambda) ---
# This function receives the event from API Gateway and calls your Flask app
def lambda_handler(event, context):
    logging.info(f"Lambda event received: {json.dumps(event)}") # Log the incoming event

    # Binary types for API Gateway
    # You might need to add more if your app handles other binary data (e.g., images)
    binary_types = [
        'image/png', 'image/jpeg', 'image/gif', 'image/webp',
        'application/octet-stream', 'application/pdf'
    ]

    # Reconstruct the WSGI environment from the API Gateway event
    environ = {
        'REQUEST_METHOD': event['httpMethod'],
        'PATH_INFO': event['path'],
        'SERVER_NAME': event['headers'].get('Host', ''),
        'SERVER_PORT': event['headers'].get('X-Forwarded-Port', '80'),
        'QUERY_STRING': event.get('queryStringParameters', ''),
        'RAW_URI': event['path'],
        'CONTENT_TYPE': event['headers'].get('Content-Type', ''),
        'CONTENT_LENGTH': event['headers'].get('Content-Length', '0'),
        'REMOTE_ADDR': event['requestContext']['identity']['sourceIp'],
        'SCRIPT_NAME': '',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': event['headers'].get('X-Forwarded-Proto', 'http'),
        'wsgi.input': BytesIO(), # Placeholder, populated below
        'wsgi.errors': BytesIO(), # Errors will be logged to CloudWatch by Lambda anyway
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
    }

    # Add headers to environ
    headers = Headers()
    for key, value in event['headers'].items():
        environ[f'HTTP_{key.upper().replace("-", "_")}'] = value # WSGI expects HTTP_ prefixed headers
        headers.add(key, value) # Werkzeug Headers object

    environ['wsgi.input'] = BytesIO(event['body'].encode('utf-8')) if event['body'] else BytesIO(b'')
    if event.get('isBase64Encoded'):
        try:
            body = base64.b64decode(event['body'])
            environ['wsgi.input'] = BytesIO(body)
        except Exception as e:
            logging.error(f"Error decoding base64 body: {e}")
            environ['wsgi.input'] = BytesIO(b'') # Fallback to empty body

    # Call the Flask application
    response = app.wsgi_app(environ, lambda status, headers: None) # start_response is a placeholder

    # Prepare the API Gateway response
    status_code = 200
    headers_dict = {}
    response_body = ""
    is_base64_encoded = False

    # Werkzeug response object is iterable. Consume it.
    response_list = []
    for item in response:
        response_list.append(item.decode('utf-8')) # Assuming UTF-8 for text responses
    
    # Extract status and headers if start_response was fully implemented
    # For a simple WSGI app, Flask's app.response_class should give us enough
    # If the response is a Response object from Flask directly, we can get status and headers
    if isinstance(response, Response):
        status_code = response.status_code
        for key, value in response.headers:
            headers_dict[key] = value
        response_body = response.get_data().decode('utf-8')
        # Check if the response type requires base64 encoding
        if response.content_type and any(mime in response.content_type for mime in binary_types):
            is_base64_encoded = True
            response_body = base64.b64encode(response.get_data()).decode('utf-8')
    else: # Fallback for simpler iterable WSGI response
        response_body = "".join(response_list)

    # AWS Lambda Proxy Integration Response format
    # Need to handle cookies separately if using them
    multi_value_headers = {}
    if 'set-cookie' in headers_dict:
        multi_value_headers['Set-Cookie'] = headers_dict.pop('set-cookie').split(', ') # Split multiple cookies
        logging.info(f"Set-Cookie header processed: {multi_value_headers['Set-Cookie']}")


    api_gateway_response = {
        'statusCode': status_code,
        'headers': headers_dict,
        'body': response_body,
        'isBase64Encoded': is_base64_encoded,
    }
    if multi_value_headers:
        api_gateway_response['multiValueHeaders'] = multi_value_headers


    logging.info(f"Lambda response: {json.dumps(api_gateway_response)}")
    return api_gateway_response


# This is for local development/testing ONLY
if __name__ == '__main__':
    logging.info("WARNING: Running Flask locally.")
    logging.info("For local testing, ensure AWS credentials (e.g., via ~/.aws/credentials) and DynamoDB Local (optional) are set up.")
    app.run(debug=False, port=5000)
