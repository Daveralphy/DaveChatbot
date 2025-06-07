import os
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai
from functools import wraps
import json
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta # <--- ADD THIS IMPORT

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
print(f"DEBUG: Flask secret key being used: {app.secret_key}")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable not set. Please add it to your .env file.")

# Set session to be permanent (e.g., lasts for 7 days)
app.permanent_session_lifetime = timedelta(days=7) # <--- ADD THIS LINE

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set.")
genai.configure(api_key=GEMINI_API_KEY)

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # SQLite database named site.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable tracking modifications for performance
db = SQLAlchemy(app)

# User Model Definition
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
# --- END Database Configuration ---


# Load persona from persona.json file
persona_history = []
try:
    persona_file_path = os.path.join(app.root_path, 'persona.json')
    with open(persona_file_path, 'r', encoding='utf-8') as f:
        persona_history = json.load(f)
    print(f"Loaded persona history from {persona_file_path}")
except FileNotFoundError:
    print("Warning: persona.json not found. Chatbot will start without pre-defined persona.")
except json.JSONDecodeError as e:
    print(f"Error decoding persona.json: {e}. Chatbot will start without pre-defined persona.")

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

# Helper function to get/initialize chat session history for a user
def get_gemini_chat_session():
    # If the user's chat history is not in the session, initialize it
    if 'user_chat_history' not in session:
        session['user_chat_history'] = initial_persona_prompt + persona_history
        print(f"Initialized new chat session for user: {session.get('username', 'Guest')}")
    
    return model.start_chat(history=session['user_chat_history'])


# --- Authentication Decorator and Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: # Check for user_id in session
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409 # 409 Conflict

    new_user = User(username=username)
    new_user.set_password(password) # Hash the password
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registration successful"}), 201 # 201 Created

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session['logged_in'] = True
        session['username'] = user.username # Store username in session
        session['user_id'] = user.id # Store user ID in session
        session.permanent = True # <--- MAKE SESSION PERMANENT ON LOGIN
        # Initialize chat history for the logged-in user if not already present
        if 'user_chat_history' not in session:
            session['user_chat_history'] = initial_persona_prompt + persona_history
        print(f"User '{username}' logged in. Chat history initialized/loaded.")
        return jsonify({"message": "Login successful", "username": user.username}), 200
    else:
        print(f"Login failed for user '{username}'.")
        session['logged_in'] = False
        session.pop('username', None)
        session.pop('user_id', None)
        session.pop('user_chat_history', None) # Clear history on failed login
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None) # Remove user_id from session
    session.pop('user_chat_history', None) # Clear user's chat history on logout
    session.permanent = False # <--- Make session non-permanent on logout
    print(f"User logged out. Chat history cleared.")
    return jsonify({"message": "Logged out"}), 200

@app.route('/check_login_status', methods=['GET'])
def check_login_status():
    if 'user_id' in session:
        # Ensure chat history is initialized if not already present
        if 'user_chat_history' not in session:
            session['user_chat_history'] = initial_persona_prompt + persona_history
        
        # Calculate the length of the non-conversational history (persona + persona.json)
        persona_base_length = len(initial_persona_prompt) + len(persona_history)
        
        # Extract only the actual conversation messages (user and model turns)
        conversation_messages = session['user_chat_history'][persona_base_length:]

        return jsonify({
            "logged_in": True, 
            "username": session['username'],
            "chat_history": conversation_messages # Send the actual conversation history
        }), 200
    else:
        return jsonify({"logged_in": False}), 401

@app.route('/chat', methods=['POST'])
@login_required
def chat_endpoint():
    try:
        user_message = request.json.get('message')
        if not user_message:
            return jsonify({"error": "No message provided"}), 400

        print(f"User '{session.get('username', 'Anonymous')}' message: {user_message}")
        
        chat_session = get_gemini_chat_session()
        
        response = chat_session.send_message(user_message)
        bot_response = response.text
        
        session['user_chat_history'].append({"role": "user", "parts": [user_message]})
        session['user_chat_history'].append({"role": "model", "parts": [bot_response]})
        session.modified = True # Tell Flask the session data has been modified

        print(f"Bot response: {bot_response}")

        return jsonify({"response": bot_response})

    except Exception as e:
        print(f"Error during chat: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/new_chat')
@login_required
def new_chat():
    session.pop('user_chat_history', None) # Clear the current user's chat history
    session.modified = True # Indicate session modified
    print(f"User '{session.get('username', 'Anonymous')}' started a new chat.")
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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created (if they didn't exist).")
    app.run(debug=False, port=5000)