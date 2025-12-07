import sqlite3
import hashlib
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
# Use environment variable for secret key in production, fallback for dev
app.secret_key = os.environ.get('SECRET_KEY', 'super_secure_random_key_for_pulse_chat')

# --- GOOGLE AUTH CONFIGURATION ---
# Use Env Vars first (Production), fallback to hardcoded (Local Dev)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', "2505746137-bnr2ajof0jeqcu4uq6nj9chu5609592q.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', "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")

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- DATABASE SETUP ---
DB_NAME = "pulse_chat.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Users Table with auth_provider
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE NOT NULL, 
                  password_hash TEXT, 
                  auth_provider TEXT DEFAULT 'local')''')
    # Messages Table
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT NOT NULL, 
                  content TEXT NOT NULL, 
                  timestamp TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Initialize on start
init_db()

# --- HELPER FUNCTIONS ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# --- ROUTES ---

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash("Username and Password required.")
        return redirect(url_for('index'))
        
    pwd_hash = hash_password(password)
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password_hash, auth_provider) VALUES (?, ?, 'local')", (username, pwd_hash))
        conn.commit()
        session['username'] = username
        return redirect(url_for('chat'))
    except sqlite3.IntegrityError:
        flash("Username already taken!")
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    pwd_hash = hash_password(password)
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, pwd_hash)).fetchone()
    conn.close()
    
    if user:
        session['username'] = username
        return redirect(url_for('chat'))
    else:
        flash("Invalid Username or Password.")
        return redirect(url_for('index'))

# --- GOOGLE ROUTES ---
@app.route('/google/login')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        if not user_info:
            flash("Failed to fetch user info from Google.")
            return redirect(url_for('index'))
            
        # Use email prefix as username for simplicity
        email = user_info['email']
        username = email.split('@')[0]
        
        # Check if user exists, else create
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if not user:
            # Create Google user (no password needed)
            try:
                conn.execute("INSERT INTO users (username, auth_provider) VALUES (?, 'google')", (username,))
                conn.commit()
            except sqlite3.IntegrityError:
                # Fallback if name taken by local user
                username = f"{username}_{hashlib.sha256(email.encode()).hexdigest()[:4]}"
                conn.execute("INSERT INTO users (username, auth_provider) VALUES (?, 'google')", (username,))
                conn.commit()
        conn.close()
        
        session['username'] = username
        return redirect(url_for('chat'))
    except Exception as e:
        print(f"OAuth Error: {e}")
        flash("Google Login Failed. Check Console.")
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('chat.html', username=session['username'])

# --- API ROUTES ---

@app.route('/api/messages')
def get_messages():
    conn = get_db_connection()
    msgs = conn.execute("SELECT username, content, timestamp FROM messages ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(row) for row in msgs][::-1])

@app.route('/api/send', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    content = data.get('content')
    username = session['username']
    
    if content:
        timestamp = datetime.now().strftime('%H:%M')
        conn = get_db_connection()
        conn.execute("INSERT INTO messages (username, content, timestamp) VALUES (?, ?, ?)", 
                     (username, content, timestamp))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    
    return jsonify({'error': 'Empty message'}), 400

if __name__ == '__main__':
    # Cloud platforms set the PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
