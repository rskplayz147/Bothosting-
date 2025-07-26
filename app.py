from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import subprocess
import threading
import sqlite3
import bcrypt
import aiofiles
import zipfile
import json
import psutil
import logging
import time
import schedule
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import smtplib
from email.mime.text import MIMEText

# Initialize Flask app
# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', '/var/data/user_bots')  # (optional: fix if needed)
os.makedirs(os.path.join(os.getcwd(), 'instance'), exist_ok=True)  # ensure folder exists
app.config['DATABASE'] = os.path.join(os.getcwd(), 'fck', 'bot_data.db')  # ✅ safe path
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB max file size
app.config['MAX_FILES_PER_USER'] = 10
app.config['ALLOWED_EXTENSIONS'] = {'py', 'js', 'zip'}
CORS(app)  # Enable CORS for API access

# Configure logging
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

# Configure rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Process management globals
running_processes = {}  # {file_id: subprocess.Popen}
process_logs = {}       # {file_id: list of logs}
process_locks = {}      # {file_id: threading.Lock}
scheduled_jobs = {}     # {file_id: schedule.Job}

# Database setup
def init_db():
    """Initialize SQLite database with tables for users, files, processes, and analytics."""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password TEXT,
                 email TEXT,
                 role TEXT DEFAULT 'user',
                 created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 filename TEXT,
                 filetype TEXT,
                 upload_date TEXT,
                 settings TEXT,
                 status TEXT,
                 locked INTEGER,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS processes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 file_id INTEGER,
                 pid INTEGER,
                 start_time TEXT,
                 last_checked TEXT,
                 cpu_usage REAL,
                 memory_usage REAL,
                 FOREIGN KEY(file_id) REFERENCES files(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS analytics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 file_id INTEGER,
                 action TEXT,
                 timestamp TEXT,
                 details TEXT,
                 FOREIGN KEY(user_id) REFERENCES users(id),
                 FOREIGN KEY(file_id) REFERENCES files(id))''')
    conn.commit()
    conn.close()
    logging.info("Database initialized")

init_db()

# Utility functions
def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def hash_password(password):
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

async def install_dependencies(filepath, filetype, user_id):
    """Install dependencies for Python or Node.js files."""
    user_folder = os.path.dirname(filepath)
    try:
        if filetype == 'py':
            req_file = os.path.join(user_folder, 'requirements.txt')
            if os.path.exists(req_file):
                logging.info(f"Installing Python dependencies from {req_file} for user {user_id}")
                subprocess.run(['pip', 'install', '-r', req_file, '--user'], check=True)
            else:
                logging.info(f"No requirements.txt found for {filepath}. Installing common dependencies.")
                subprocess.run(['pip', 'install', 'requests', 'numpy', '--user'], check=False)
        elif filetype == 'js':
            pkg_file = os.path.join(user_folder, 'package.json')
            if os.path.exists(pkg_file):
                logging.info(f"Installing Node.js dependencies from {pkg_file} for user {user_id}")
                subprocess.run(['npm', 'install', '--prefix', user_folder], check=True)
    except Exception as e:
        logging.error(f"Dependency installation failed for {filepath}: {str(e)}")
        flash(f"Dependency installation failed: {str(e)}", 'error')

def collect_logs(file_id, process):
    """Collect logs from a running process."""
    process_logs[file_id] = []
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            process_logs[file_id].append(output.strip())
            logging.info(f"Log for file_id {file_id}: {output.strip()}")

def monitor_process(file_id, process, filepath, filetype, user_id):
    """Monitor process health and restart if crashed."""
    while True:
        if process.poll() is not None:
            logging.warning(f"Process {file_id} crashed with code {process.poll()}. Restarting...")
            try:
                cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
                new_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                running_processes[file_id] = new_process
                threading.Thread(target=collect_logs, args=(file_id, new_process)).start()
                update_process_status(file_id, 'running')
                notify_user(user_id, f"Process {file_id} restarted due to crash")
            except Exception as e:
                logging.error(f"Failed to restart process {file_id}: {str(e)}")
                update_process_status(file_id, f'error: {str(e)}')
                notify_user(user_id, f"Failed to restart process {file_id}: {str(e)}")
                break
        try:
            p = psutil.Process(process.pid)
            cpu_usage = p.cpu_percent(interval=1)
            memory_usage = p.memory_info().rss / 1024 / 1024  # MB
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            c.execute('UPDATE processes SET cpu_usage = ?, memory_usage = ?, last_checked = ? WHERE file_id = ?',
                      (cpu_usage, memory_usage, datetime.now().isoformat(), file_id))
            conn.commit()
            conn.close()
        except psutil.NoSuchProcess:
            break
        time.sleep(5)

def update_process_status(file_id, status):
    """Update file status in database."""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('UPDATE files SET status = ? WHERE id = ?', (status, file_id))
    c.execute('UPDATE processes SET last_checked = ? WHERE file_id = ?',
              (datetime.now().isoformat(), file_id))
    conn.commit()
    conn.close()

def notify_user(user_id, message):
    """Send notification to user (placeholder for email or in-app)."""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    email = c.fetchone()
    conn.close()
    if email and os.getenv('SMTP_HOST'):
        try:
            msg = MIMEText(message)
            msg['Subject'] = 'VIP Script Hosting Notification'
            msg['From'] = os.getenv('SMTP_FROM')
            msg['To'] = email[0]
            with smtplib.SMTP(os.getenv('SMTP_HOST'), os.getenv('SMTP_PORT')) as server:
                server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASS'))
                server.send_message(msg)
        except Exception as e:
            logging.error(f"Failed to send notification to user {user_id}: {str(e)}")
    logging.info(f"Notification for user {user_id}: {message}")

def log_analytics(user_id, file_id, action, details):
    """Log user actions for analytics."""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('INSERT INTO analytics (user_id, file_id, action, timestamp, details) VALUES (?, ?, ?, ?, ?)',
              (user_id, file_id, action, datetime.now().isoformat(), details))
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def index():
    """Render main dashboard with user files and analytics."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT id, filename, filetype, status, locked FROM files WHERE user_id = ?', 
              (session['user_id'],))
    files = [{'id': row[0], 'name': row[1], 'type': row[2], 'status': row[3], 'locked': bool(row[4])} 
             for row in c.fetchall()]
    c.execute('SELECT action, timestamp, details FROM analytics WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100',
              (session['user_id'],))
    analytics = [{'action': row[0], 'timestamp': row[1], 'details': row[2]} for row in c.fetchall()]
    conn.close()
    
    return render_template('index.html', 
                         files=files, 
                         username=session.get('username'),
                         role=session.get('role'),
                         analytics=analytics)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password(password, user[2]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            log_analytics(user[0], None, 'login', f"User {username} logged in")
            notify_user(user[0], f"User {username} logged in")
            return redirect(url_for('index'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        try:
            hashed = hash_password(password)
            c.execute('INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)',
                      (username, hashed, email, datetime.now().isoformat()))
            conn.commit()
            log_analytics(None, None, 'register', f"User {username} registered")
            notify_user(c.lastrowid, f"User {username} registered")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    user_id = session.get('user_id')
    username = session.get('username')
    session.clear()
    if user_id:
        log_analytics(user_id, None, 'logout', f"User {username} logged out")
        notify_user(user_id, f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@limiter.limit("10 per minute")
async def upload_file():
    """Handle file uploads with dependency installation."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (session['user_id'],))
    if c.fetchone()[0] >= app.config['MAX_FILES_PER_USER']:
        conn.close()
        flash(f'Max {app.config["MAX_FILES_PER_USER"]} files allowed', 'error')
        return redirect(url_for('index'))
    
    if 'file' not in request.files or request.files['file'].filename == '':
        conn.close()
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if not allowed_file(file.filename):
        conn.close()
        flash('Invalid file type. Only .py, .js, and .zip allowed', 'error')
        return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    filetype = filename.rsplit('.', 1)[1].lower()
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    os.makedirs(user_folder, exist_ok=True)
    filepath = os.path.join(user_folder, filename)
    
    async with aiofiles.open(filepath, 'wb') as f:
        await f.write(file.read())
    
    if filetype == 'zip':
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            zip_ref.extractall(user_folder)
        os.remove(filepath)
        extracted_files = [f for f in os.listdir(user_folder) if allowed_file(f)]
        for extracted in extracted_files:
            extracted_filetype = extracted.rsplit('.', 1)[1].lower()
            c.execute('INSERT INTO files (user_id, filename, filetype, upload_date, status, locked) VALUES (?, ?, ?, ?, ?, ?)',
                      (session['user_id'], extracted, extracted_filetype, datetime.now().isoformat(), 'stopped', 0))
            await install_dependencies(os.path.join(user_folder, extracted), extracted_filetype, session['user_id'])
    else:
        c.execute('INSERT INTO files (user_id, filename, filetype, upload_date, status, locked) VALUES (?, ?, ?, ?, ?, ?)',
                  (session['user_id'], filename, filetype, datetime.now().isoformat(), 'stopped', 0))
        await install_dependencies(filepath, filetype, session['user_id'])
    
    conn.commit()
    conn.close()
    log_analytics(session['user_id'], c.lastrowid, 'upload', f"Uploaded {filename}")
    notify_user(session['user_id'], f"File {filename} uploaded")
    flash('File uploaded successfully', 'success')
    return redirect(url_for('index'))

@app.route('/control/<int:file_id>/<action>')
@limiter.limit("20 per minute")
def control_file(file_id, action):
    """Control file actions (start, stop, restart, lock, unlock)."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, filetype, locked, settings FROM files WHERE id = ? AND user_id = ?', 
              (file_id, session['user_id']))
    file = c.fetchone()
    if not file:
        conn.close()
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    filename, filetype, locked, settings = file
    if locked and action not in ['unlock', 'stop']:
        conn.close()
        flash('File is locked', 'error')
        return redirect(url_for('index'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), filename)
    
    if action == 'start':
        if file_id in running_processes and running_processes[file_id].poll() is None:
            conn.close()
            flash('File is already running', 'error')
            return redirect(url_for('index'))
        try:
            cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
            env = os.environ.copy()
            if settings:
                settings_dict = json.loads(settings)
                env.update(settings_dict.get('env', {}))
                cmd.extend(settings_dict.get('args', []))
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env
            )
            running_processes[file_id] = process
            process_logs[file_id] = []
            process_locks[file_id] = threading.Lock()
            
            threading.Thread(target=collect_logs, args=(file_id, process)).start()
            threading.Thread(target=monitor_process, args=(file_id, process, filepath, filetype, session['user_id'])).start()
            
            c.execute('INSERT INTO processes (file_id, pid, start_time, last_checked) VALUES (?, ?, ?, ?)',
                      (file_id, process.pid, datetime.now().isoformat(), datetime.now().isoformat()))
            c.execute('UPDATE files SET status = ? WHERE id = ?', ('running', file_id))
            conn.commit()
            log_analytics(session['user_id'], file_id, 'start', f"Started {filename}")
            notify_user(session['user_id'], f"Script {filename} started")
            flash('Script started successfully', 'success')
        except Exception as e:
            flash(f'Error starting script: {str(e)}', 'error')
            log_analytics(session['user_id'], file_id, 'error', f"Start failed: {str(e)}")
    
    elif action == 'stop':
        if file_id not in running_processes:
            conn.close()
            flash('Script is not running', 'error')
            return redirect(url_for('index'))
        
        with process_locks.get(file_id, threading.Lock()):
            process = running_processes[file_id]
            try:
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.terminate()
                parent.terminate()
                process.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                logging.error(f"Error stopping file_id {file_id}: {str(e)}")
            
            del running_processes[file_id]
            if file_id in process_logs:
                del process_logs[file_id]
            if file_id in process_locks:
                del process_locks[file_id]
            
            c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
            c.execute('UPDATE files SET status = ? WHERE id = ?', ('stopped', file_id))
            conn.commit()
            log_analytics(session['user_id'], file_id, 'stop', f"Stopped {filename}")
            notify_user(session['user_id'], f"Script {filename} stopped")
            flash('Script stopped successfully', 'success')
    
    elif action == 'restart':
        control_file(file_id, 'stop')
        time.sleep(1)
        control_file(file_id, 'start')
        flash('Script restarted successfully', 'success')
    
    elif action == 'lock':
        c.execute('UPDATE files SET locked = 1 WHERE id = ?', (file_id,))
        conn.commit()
        log_analytics(session['user_id'], file_id, 'lock', f"Locked {filename}")
        notify_user(session['user_id'], f"File {filename} locked")
        flash('File locked successfully', 'success')
    
    elif action == 'unlock':
        c.execute('UPDATE files SET locked = 0 WHERE id = ?', (file_id,))
        conn.commit()
        log_analytics(session['user_id'], file_id, 'unlock', f"Unlocked {filename}")
        notify_user(session['user_id'], f"File {filename} unlocked")
        flash('File unlocked successfully', 'success')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/logs/<int:file_id>')
@limiter.limit("30 per minute")
def get_logs(file_id):
    """Retrieve logs for a file."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    conn.close()
    return jsonify(process_logs.get(file_id, [])[-100:])

@app.route('/delete/<int:file_id>', methods=['POST'])
@limiter.limit("10 per minute")
def delete_file(file_id):
    """Delete a file and stop its process."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, locked FROM files WHERE id = ? AND user_id = ?', 
              (file_id, session['user_id']))
    file = c.fetchone()
    if not file:
        conn.close()
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    filename, locked = file
    if locked:
        conn.close()
        flash('Cannot delete locked file', 'error')
        return redirect(url_for('index'))
    
    if file_id in running_processes:
        control_file(file_id, 'stop')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    c.execute('DELETE FROM files WHERE id = ?', (file_id,))
    c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
    conn.commit()
    conn.close()
    log_analytics(session['user_id'], file_id, 'delete', f"Deleted {filename}")
    notify_user(session['user_id'], f"File {filename} deleted")
    flash('File deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/settings/<int:file_id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def file_settings(file_id):
    """Manage file settings (env vars, args)."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, settings FROM files WHERE id = ? AND user_id = ?', 
              (file_id, session['user_id']))
    file = c.fetchone()
    if not file:
        conn.close()
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    filename, settings = file
    settings_dict = json.loads(settings) if settings else {'env': {}, 'args': []}
    
    if request.method == 'POST':
        env_vars = request.form.get('env_vars', '')
        args = request.form.get('args', '')
        settings_dict['env'] = dict(line.split('=') for line in env_vars.split('\n') if '=' in line)
        settings_dict['args'] = args.split()
        c.execute('UPDATE files SET settings = ? WHERE id = ?', 
                  (json.dumps(settings_dict), file_id))
        conn.commit()
        log_analytics(session['user_id'], file_id, 'update_settings', f"Updated settings for {filename}")
        notify_user(session['user_id'], f"Settings updated for {filename}")
        flash('Settings updated successfully', 'success')
        conn.close()
        return redirect(url_for('index'))
    
    conn.close()
    return render_template('settings.html', file_id=file_id, filename=filename, settings=settings_dict)

@app.route('/api/status/<int:file_id>', methods=['GET'])
@limiter.limit("30 per minute")
def api_file_status(file_id):
    """API endpoint to check file status."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT status FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
    status = c.fetchone()
    conn.close()
    if not status:
        return jsonify({'error': 'File not found'}), 404
    return jsonify({'status': status[0]})

@app.route('/api/analytics', methods=['GET'])
@limiter.limit("10 per minute")
def api_analytics():
    """API endpoint for user analytics."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT action, timestamp, details FROM analytics WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100',
              (session['user_id'],))
    analytics = [{'action': row[0], 'timestamp': row[1], 'details': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(analytics)

@app.route('/schedule/<int:file_id>', methods=['POST'])
@limiter.limit("10 per minute")
def schedule_file(file_id):
    """Schedule a file to run at a specific time."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT filename, filetype FROM files WHERE id = ? AND user_id = ?', 
              (file_id, session['user_id']))
    file = c.fetchone()
    if not file:
        conn.close()
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    schedule_str = request.form.get('schedule')
    try:
        job = schedule.every().day.at(schedule_str).do(
            lambda: control_file(file_id, 'start')
        )
        scheduled_jobs[file_id] = job
        log_analytics(session['user_id'], file_id, 'schedule', f"Scheduled {file[0]} at {schedule_str}")
        notify_user(session['user_id'], f"Scheduled {file[0]} at {schedule_str}")
        flash('Task scheduled successfully', 'success')
    except Exception as e:
        flash(f'Error scheduling task: {str(e)}', 'error')
        log_analytics(session['user_id'], file_id, 'error', f"Schedule failed: {str(e)}")
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/admin/users', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def admin_users():
    """Admin panel for user management."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = int(request.form.get('user_id'))
        if action == 'promote':
            c.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', user_id))
            flash('User promoted to admin', 'success')
            log_analytics(session['user_id'], None, 'admin_promote', f"Promoted user {user_id}")
        elif action == 'demote':
            c.execute('UPDATE users SET role = ? WHERE id = ?', ('user', user_id))
            flash('User demoted to user', 'success')
            log_analytics(session['user_id'], None, 'admin_demote', f"Demoted user {user_id}")
        elif action == 'delete':
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))
            c.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
            c.execute('DELETE FROM processes WHERE file_id IN (SELECT id FROM files WHERE user_id = ?)', (user_id,))
            flash('User deleted', 'success')
            log_analytics(session['user_id'], None, 'admin_delete', f"Deleted user {user_id}")
        conn.commit()
    
    c.execute('SELECT id, username, email, role, created_at FROM users')
    users = [{'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3], 'created_at': row[4]} 
             for row in c.fetchall()]
    conn.close()
    return render_template('admin_users.html', users=users)

def restore_processes():
    """Restore running processes on startup."""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT file_id, filename, filetype, user_id FROM files WHERE status = ?', ('running',))
    running_files = c.fetchall()
    
    for file_id, filename, filetype, user_id in running_files:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id), filename)
        try:
            cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            running_processes[file_id] = process
            process_logs[file_id] = []
            process_locks[file_id] = threading.Lock()
            threading.Thread(target=collect_logs, args=(file_id, process)).start()
            threading.Thread(target=monitor_process, args=(file_id, process, filepath, filetype, user_id)).start()
            logging.info(f"Restored process for file_id {file_id}")
        except Exception as e:
            logging.error(f"Failed to restore process for file_id {file_id}: {str(e)}")
    conn.close()

def run_scheduler():
    """Run scheduled tasks in a separate thread."""
    while True:
        schedule.run_pending()
        time.sleep(1)

# Startup tasks
def startup_tasks():
    """Initialize app with startup tasks."""
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    restore_processes()
    threading.Thread(target=run_scheduler, daemon=True).start()
    logging.info("Startup tasks completed")

if __name__ == '__main__':
    startup_tasks()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), threaded=True)
