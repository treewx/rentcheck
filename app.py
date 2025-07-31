from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import requests
from contextlib import contextmanager
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import secrets

# Production-ready imports
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, EmailField, FloatField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from decouple import config
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

# Production Configuration
app.config['SECRET_KEY'] = config('SECRET_KEY', default=secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['SESSION_COOKIE_SECURE'] = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
app.config['SESSION_COOKIE_HTTPONLY'] = config('SESSION_COOKIE_HTTPONLY', default=True, cast=bool)
app.config['SESSION_COOKIE_SAMESITE'] = config('SESSION_COOKIE_SAMESITE', default='Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config('PERMANENT_SESSION_LIFETIME', default=3600, cast=int))

# Security Extensions - disabled for now due to JSON API issues
# csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=config('RATELIMIT_STORAGE_URL', default="memory://"),
    on_breach=lambda: None  # Don't crash on rate limit storage issues
)

# Database configuration
DATABASE = config('DATABASE_URL', default='rentcheck.db').replace('sqlite:///', '')
# Ensure database directory exists for Railway
db_dir = os.path.dirname(DATABASE) if os.path.dirname(DATABASE) else '.'
if not os.path.exists(db_dir):
    os.makedirs(db_dir, exist_ok=True)

# Logging Configuration
if not app.debug and not os.environ.get('RAILWAY_ENVIRONMENT'):
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/rentcheck.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('RentCheck startup')
else:
    # Railway/production logging to stdout
    import sys
    app.logger.addHandler(logging.StreamHandler(sys.stdout))
    app.logger.setLevel(logging.INFO)
    app.logger.info('RentCheck startup')

# Akahu API Configuration - No defaults for security
AKAHU_CONFIG = {}

# Email Configuration - Use environment variables
EMAIL_CONFIG = {
    "smtp_server": config('SMTP_SERVER', default='smtp.gmail.com'),
    "smtp_port": config('SMTP_PORT', default=587, cast=int),
    "sender_email": config('EMAIL_SENDER', default=''),
    "sender_password": config('EMAIL_PASSWORD', default=''),
}

@contextmanager
def get_db():
    """Database connection context manager"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
    try:
        with get_db() as conn:
            conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                subscription_tier TEXT DEFAULT 'starter',
                subscription_status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS properties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                property_name TEXT NOT NULL,
                tenant_name TEXT NOT NULL,
                rent_amount REAL NOT NULL,
                due_day TEXT NOT NULL,
                payment_frequency TEXT DEFAULT '1 week',
                payment_keyword TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS payment_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                property_id INTEGER,
                payment_date DATE,
                amount REAL,
                status TEXT,
                transaction_description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (property_id) REFERENCES properties (id)
            );
            
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                setting_key TEXT NOT NULL,
                setting_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, setting_key)
            );
            
            CREATE TABLE IF NOT EXISTS akahu_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_id TEXT NOT NULL,
                account_name TEXT NOT NULL,
                bank_name TEXT,
                account_type TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, account_id)
            );
        ''')
        
            # Migration: Add user_id columns to existing tables
            migrations = [
                ('properties', 'user_id', 'INTEGER'),
                ('payment_history', 'user_id', 'INTEGER'),
                ('user_settings', 'user_id', 'INTEGER'),
                ('akahu_accounts', 'user_id', 'INTEGER'),
                ('properties', 'payment_frequency', 'TEXT DEFAULT "1 week"')
            ]
            
            for table, column, column_type in migrations:
                try:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {column_type}')
                    conn.commit()
                except sqlite3.OperationalError:
                    # Column already exists
                    pass
            
            conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Try to continue anyway
        pass

def hash_password(password):
    """Hash a password using bcrypt"""
    return generate_password_hash(password)

def verify_password(password, password_hash):
    """Verify a password against its hash"""
    return check_password_hash(password_hash, password)

def get_current_user():
    """Get the current logged-in user"""
    if 'user_id' in session:
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', 
                (session['user_id'],)
            ).fetchone()
            return dict(user) if user else None
    return None

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_setting(key, default=None, user_id=None):
    """Get a user setting value"""
    if user_id is None:
        current_user = get_current_user()
        if not current_user:
            return default
        user_id = current_user['id']
    
    with get_db() as conn:
        result = conn.execute(
            'SELECT setting_value FROM user_settings WHERE user_id = ? AND setting_key = ?', 
            (user_id, key)
        ).fetchone()
        return result['setting_value'] if result else default

def set_setting(key, value, user_id=None):
    """Set a user setting value"""
    if user_id is None:
        current_user = get_current_user()
        if not current_user:
            return
        user_id = current_user['id']
    
    with get_db() as conn:
        conn.execute('''
            INSERT OR REPLACE INTO user_settings (user_id, setting_key, setting_value, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, key, value))
        conn.commit()

def get_akahu_config(user_id=None):
    """Get Akahu API configuration from database"""
    app_token = get_setting('akahu_app_token', user_id=user_id)
    user_token = get_setting('akahu_user_token', user_id=user_id)
    
    if app_token and user_token:
        return {
            "app_token": app_token,
            "user_token": user_token
        }
    else:
        # No credentials configured
        return None

def get_active_account_ids(user_id=None):
    """Get list of active Akahu account IDs for a user"""
    if user_id is None:
        current_user = get_current_user()
        if not current_user:
            return []
        user_id = current_user['id']
    
    with get_db() as conn:
        accounts = conn.execute(
            'SELECT account_id FROM akahu_accounts WHERE user_id = ? AND is_active = 1',
            (user_id,)
        ).fetchall()
        return [acc['account_id'] for acc in accounts] if accounts else []

# WTForms for Input Validation
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])

class PropertyForm(FlaskForm):
    property_name = StringField('Property Name', validators=[DataRequired(), Length(min=2, max=100)])
    tenant_name = StringField('Tenant Name', validators=[DataRequired(), Length(min=2, max=100)])
    rent_amount = FloatField('Rent Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    due_day = SelectField('Due Day', choices=[
        ('Monday', 'Monday'), ('Tuesday', 'Tuesday'), ('Wednesday', 'Wednesday'),
        ('Thursday', 'Thursday'), ('Friday', 'Friday'), ('Saturday', 'Saturday'),
        ('Sunday', 'Sunday')
    ], validators=[DataRequired()])
    payment_frequency = SelectField('Payment Frequency', choices=[
        ('1 week', 'Weekly'), ('2 weeks', 'Bi-weekly'), ('1 month', 'Monthly')
    ], validators=[DataRequired()])
    payment_keyword = StringField('Payment Keyword', validators=[DataRequired(), Length(min=2, max=50)])

def validate_email_address(email):
    """Validate email address format"""
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """User login with rate limiting and validation"""
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data
        
        # Additional email validation
        if not validate_email_address(email):
            flash('Invalid email format', 'error')
            return render_template('login.html', form=form)
        
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE email = ?', (email,)
            ).fetchone()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session.permanent = True
                # Update last login
                conn.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                    (user['id'],)
                )
                conn.commit()
                app.logger.info(f'User {email} logged in successfully')
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f'Failed login attempt for {email}')
                flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    """User registration with validation and rate limiting"""
    form = RegisterForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data
        first_name = form.first_name.data.strip()
        last_name = form.last_name.data.strip()
        
        # Additional email validation
        if not validate_email_address(email):
            flash('Invalid email format', 'error')
            return render_template('register.html', form=form)
        
        # Password strength validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html', form=form)
        
        with get_db() as conn:
            # Check if user already exists
            existing_user = conn.execute(
                'SELECT id FROM users WHERE email = ?', (email,)
            ).fetchone()
            
            if existing_user:
                flash('Email already registered', 'error')
                app.logger.warning(f'Registration attempt with existing email: {email}')
            else:
                # Create new user
                password_hash = hash_password(password)
                conn.execute('''
                    INSERT INTO users (email, password_hash, first_name, last_name)
                    VALUES (?, ?, ?, ?)
                ''', (email, password_hash, first_name, last_name))
                conn.commit()
                app.logger.info(f'New user registered: {email}')
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('error.html', error_code=500, error_message='Internal server error'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f'Rate limit exceeded: {request.remote_addr}')
    return jsonify(error="Rate limit exceeded", message=str(e.description)), 429

# Security Headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/')
@login_required
def dashboard():
    """Main dashboard showing rent status overview"""
    current_user = get_current_user()
    if not current_user:
        # Session exists but user record doesn't - clear session and redirect to login
        session.clear()
        return redirect(url_for('login'))
    user_id = current_user['id']
    
    with get_db() as conn:
        properties = conn.execute('''
            SELECT * FROM properties WHERE user_id = ? ORDER BY property_name
        ''', (user_id,)).fetchall()
        
        # Get recent payment history
        recent_payments = conn.execute('''
            SELECT ph.*, p.property_name, p.tenant_name 
            FROM payment_history ph 
            JOIN properties p ON ph.property_id = p.id 
            WHERE ph.user_id = ?
            ORDER BY ph.payment_date DESC 
            LIMIT 10
        ''', (user_id,)).fetchall()
    
    # Check if API is configured
    api_configured = get_akahu_config() is not None
    accounts_configured = len(get_active_account_ids()) > 0
    
    return render_template('dashboard.html', 
                         properties=properties, 
                         recent_payments=recent_payments,
                         api_configured=api_configured,
                         accounts_configured=accounts_configured,
                         current_user=current_user)

@app.route('/properties')
@login_required
def properties():
    """Property management page"""
    current_user = get_current_user()
    if not current_user:
        session.clear()
        return redirect(url_for('login'))
    user_id = current_user['id']
    
    with get_db() as conn:
        properties = conn.execute('''
            SELECT * FROM properties WHERE user_id = ? ORDER BY property_name
        ''', (user_id,)).fetchall()
    
    return render_template('properties.html', properties=properties, current_user=current_user)

@app.route('/settings')
@login_required
def settings():
    """Settings page for API configuration"""
    current_user = get_current_user()
    if not current_user:
        session.clear()
        return redirect(url_for('login'))
    user_id = current_user['id']
    
    # Get current settings
    akahu_app_token = get_setting('akahu_app_token', '')
    akahu_user_token = get_setting('akahu_user_token', '')
    email_recipient = get_setting('email_recipient', '')
    
    # Get configured accounts
    with get_db() as conn:
        accounts = conn.execute('''
            SELECT * FROM akahu_accounts WHERE user_id = ? ORDER BY account_name
        ''', (user_id,)).fetchall()
    
    return render_template('settings.html', 
                         akahu_app_token=akahu_app_token,
                         akahu_user_token=akahu_user_token,
                         email_recipient=email_recipient,
                         accounts=accounts,
                         current_user=current_user)

@app.route('/save_settings', methods=['POST'])
@login_required
def save_settings():
    """Save API configuration settings"""
    try:
        # Skip CSRF validation for this route since it's JSON API behind login
        app.logger.info(f"Save settings request received - Content-Type: {request.content_type}")
        app.logger.info(f"Request data: {request.data}")
        
        data = request.get_json()
        app.logger.info(f"Parsed JSON data: {data}")
        
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'success': False, 'error': 'No data received'}), 400
        
        # Save Akahu credentials
        if 'akahu_app_token' in data:
            set_setting('akahu_app_token', data['akahu_app_token'])
            app.logger.info("Saved akahu_app_token")
        if 'akahu_user_token' in data:
            set_setting('akahu_user_token', data['akahu_user_token'])
            app.logger.info("Saved akahu_user_token")
        
        # Save email recipient (sender credentials are hardcoded)
        if 'email_recipient' in data:
            set_setting('email_recipient', data['email_recipient'])
            app.logger.info("Saved email_recipient")
        
        app.logger.info("Settings saved successfully")
        return jsonify({'success': True, 'message': 'Settings saved successfully'})
    except Exception as e:
        app.logger.error(f"Error saving settings: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# CSRF exemption no longer needed - CSRF disabled globally

@app.route('/test_akahu_connection')
@login_required
def test_akahu_connection():
    """Test Akahu API connection"""
    try:
        config = get_akahu_config()
        if not config:
            return jsonify({
                'success': False, 
                'error': 'No Akahu API credentials configured. Please set up your API tokens first.'
            })
        
        headers = {
            "Authorization": f"Bearer {config['user_token']}",
            "X-Akahu-Id": config['app_token']
        }
        
        # Test connection by fetching accounts
        response = requests.get("https://api.akahu.io/v1/accounts", headers=headers)
        
        if response.status_code == 200:
            accounts_data = response.json().get('items', [])
            return jsonify({
                'success': True, 
                'message': f'Connection successful! Found {len(accounts_data)} accounts.',
                'accounts': accounts_data
            })
        else:
            return jsonify({
                'success': False, 
                'error': f'API returned status {response.status_code}: {response.text}'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/fetch_accounts')
@login_required
def fetch_accounts():
    """Fetch and save accounts from Akahu API"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False, 
                'error': 'User session invalid. Please login again.'
            })
        user_id = current_user['id']
        
        config = get_akahu_config()
        if not config:
            return jsonify({
                'success': False, 
                'error': 'No Akahu API credentials configured. Please set up your API tokens first.'
            })
        
        headers = {
            "Authorization": f"Bearer {config['user_token']}",
            "X-Akahu-Id": config['app_token']
        }
        
        response = requests.get("https://api.akahu.io/v1/accounts", headers=headers)
        response.raise_for_status()
        
        accounts_data = response.json().get('items', [])
        
        # Save accounts to database
        with get_db() as conn:
            for account in accounts_data:
                conn.execute('''
                    INSERT OR REPLACE INTO akahu_accounts 
                    (user_id, account_id, account_name, bank_name, account_type, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                ''', (
                    user_id,
                    account['_id'],
                    account.get('name', 'Unknown Account'),
                    account.get('connection', {}).get('name', 'Unknown Bank'),
                    account.get('type', 'Unknown')
                ))
            conn.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Successfully fetched and saved {len(accounts_data)} accounts',
            'accounts': accounts_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/toggle_account/<account_id>')
@login_required
def toggle_account(account_id):
    """Toggle account active status"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'error': 'User session invalid'})
        user_id = current_user['id']
        
        with get_db() as conn:
            # Get current status for user's account
            current = conn.execute(
                'SELECT is_active FROM akahu_accounts WHERE account_id = ? AND user_id = ?', 
                (account_id, user_id)
            ).fetchone()
            
            if current:
                new_status = 0 if current['is_active'] else 1
                conn.execute(
                    'UPDATE akahu_accounts SET is_active = ? WHERE account_id = ? AND user_id = ?',
                    (new_status, account_id, user_id)
                )
                conn.commit()
                
                return jsonify({
                    'success': True, 
                    'message': f'Account {"activated" if new_status else "deactivated"}'
                })
            else:
                return jsonify({'success': False, 'error': 'Account not found'})
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/add_property', methods=['POST'])
@login_required
def add_property():
    """Add a new property"""
    data = request.get_json()
    current_user = get_current_user()
    if not current_user:
        return jsonify({'success': False, 'error': 'User session invalid'})
    user_id = current_user['id']
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO properties (user_id, property_name, tenant_name, rent_amount, due_day, payment_frequency, payment_keyword)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, data['property_name'], data['tenant_name'], data['rent_amount'], 
              data['due_day'], data['payment_frequency'], data['payment_keyword']))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/update_property/<int:property_id>', methods=['POST'])
@login_required
def update_property(property_id):
    """Update an existing property"""
    data = request.get_json()
    current_user = get_current_user()
    if not current_user:
        return jsonify({'success': False, 'error': 'User session invalid'})
    user_id = current_user['id']
    
    with get_db() as conn:
        # Verify user owns this property
        property_check = conn.execute(
            'SELECT id FROM properties WHERE id = ? AND user_id = ?',
            (property_id, user_id)
        ).fetchone()
        
        if not property_check:
            return jsonify({'success': False, 'error': 'Property not found'})
        
        conn.execute('''
            UPDATE properties 
            SET property_name=?, tenant_name=?, rent_amount=?, due_day=?, payment_frequency=?, payment_keyword=?
            WHERE id=? AND user_id=?
        ''', (data['property_name'], data['tenant_name'], data['rent_amount'], 
              data['due_day'], data['payment_frequency'], data['payment_keyword'], property_id, user_id))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/delete_property/<int:property_id>', methods=['POST'])
@login_required
def delete_property(property_id):
    """Delete a property"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({'success': False, 'error': 'User session invalid'})
    user_id = current_user['id']
    
    with get_db() as conn:
        # Verify user owns this property
        property_check = conn.execute(
            'SELECT id FROM properties WHERE id = ? AND user_id = ?',
            (property_id, user_id)
        ).fetchone()
        
        if not property_check:
            return jsonify({'success': False, 'error': 'Property not found'})
        
        conn.execute('DELETE FROM properties WHERE id=? AND user_id=?', (property_id, user_id))
        conn.execute('DELETE FROM payment_history WHERE property_id=? AND user_id=?', (property_id, user_id))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/check_payments')
@login_required
def check_payments():
    """Check for recent rent payments via Akahu API"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False, 
                'error': 'User session invalid. Please login again.'
            })
        user_id = current_user['id']
        
        # Check if API is configured
        config = get_akahu_config()
        if not config:
            return jsonify({
                'success': False, 
                'error': 'Akahu API not configured. Please set up your API credentials in Settings.'
            })
        
        # Get user's properties
        with get_db() as conn:
            properties = conn.execute('SELECT * FROM properties WHERE user_id = ?', (user_id,)).fetchall()
        
        if not properties:
            return jsonify({
                'success': True,
                'results': [],
                'total_transactions': 0,
                'message': 'No properties configured'
            })
        
        # Fetch recent transactions from Akahu
        transactions = get_akahu_transactions()
        
        if not transactions:
            return jsonify({
                'success': True,
                'results': [{'property_name': prop['property_name'], 'tenant_name': prop['tenant_name'], 
                           'payment_found': False, 'expected_amount': prop['rent_amount'], 'status': 'No Data'} 
                          for prop in properties],
                'total_transactions': 0,
                'message': 'No transactions found. Check your API credentials and account configuration.'
            })
        
        # Check each property for payments
        payment_results = []
        for prop in properties:
            result = check_property_payment(prop, transactions)
            payment_results.append(result)
            
            # Update payment history if payment found
            if result['payment_found']:
                with get_db() as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO payment_history 
                        (user_id, property_id, payment_date, amount, status, transaction_description)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (user_id, prop['id'], result['payment_date'], result['amount'], 
                          'Paid', result['description']))
                    conn.commit()
        
        return jsonify({
            'success': True,
            'results': payment_results,
            'total_transactions': len(transactions)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def get_akahu_transactions():
    """Fetch recent transactions from Akahu API"""
    config = get_akahu_config()
    if not config:
        print("[WARNING] No Akahu API credentials configured")
        return []
    
    headers = {
        "Authorization": f"Bearer {config['user_token']}",
        "X-Akahu-Id": config['app_token']
    }
    
    # Get active account IDs
    account_ids = get_active_account_ids()
    if not account_ids:
        print("[WARNING] No active accounts configured")
        return []
    
    # Get transactions from last 7 days
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    
    all_transactions = []
    
    # Fetch transactions for each active account
    for account_id in account_ids:
        try:
            params = {
                "account": account_id,
                "start": start_date.isoformat() + "Z",
                "end": end_date.isoformat() + "Z"
            }
            
            response = requests.get("https://api.akahu.io/v1/transactions", 
                                  headers=headers, params=params)
            response.raise_for_status()
            
            transactions = response.json().get("items", [])
            all_transactions.extend(transactions)
            print(f"[INFO] Fetched {len(transactions)} transactions from account {account_id}")
            
        except Exception as e:
            print(f"[ERROR] Failed to fetch transactions for account {account_id}: {e}")
            continue
    
    return all_transactions

def check_property_payment(property_row, transactions):
    """Check if a specific property has received rent payment"""
    keyword = property_row['payment_keyword'].lower()
    expected_amount = property_row['rent_amount']
    
    for txn in transactions:
        description = txn.get('description', '').lower()
        amount = abs(float(txn.get('amount', 0)))
        date = txn.get('date', '')
        
        # Check if transaction matches the property keyword and amount
        if keyword in description and amount >= expected_amount * 0.9:  # 90% match tolerance
            return {
                'property_name': property_row['property_name'],
                'tenant_name': property_row['tenant_name'],
                'payment_found': True,
                'amount': amount,
                'expected_amount': expected_amount,
                'payment_date': date[:10],  # Extract date part
                'description': txn.get('description', ''),
                'status': 'On Time' if amount >= expected_amount else 'Partial'
            }
    
    return {
        'property_name': property_row['property_name'],
        'tenant_name': property_row['tenant_name'],
        'payment_found': False,
        'expected_amount': expected_amount,
        'status': 'Missing'
    }

@app.route('/payment_history/<int:property_id>')
def payment_history(property_id):
    """Get payment history for a specific property"""
    with get_db() as conn:
        history = conn.execute('''
            SELECT ph.*, p.property_name, p.tenant_name
            FROM payment_history ph
            JOIN properties p ON ph.property_id = p.id
            WHERE ph.property_id = ?
            ORDER BY ph.payment_date DESC
        ''', (property_id,)).fetchall()
    
    return jsonify([dict(row) for row in history])

def get_email_config():
    """Get email configuration from environment variables and user settings"""
    recipient_email = get_setting('email_recipient')
    
    if recipient_email and EMAIL_CONFIG['sender_email'] and EMAIL_CONFIG['sender_password']:
        return {
            "smtp_server": EMAIL_CONFIG['smtp_server'],
            "smtp_port": EMAIL_CONFIG['smtp_port'],
            "sender_email": EMAIL_CONFIG['sender_email'],
            "sender_password": EMAIL_CONFIG['sender_password'],
            "recipient_email": recipient_email
        }
    else:
        return None

def send_email_notification(subject, message):
    """Send email notification for rent alerts"""
    try:
        email_config = get_email_config()
        if not email_config:
            print("[EMAIL ERROR] Email not configured. Please set up email credentials in Settings.")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = email_config['sender_email']
        msg['To'] = email_config['recipient_email']
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
        server.starttls()
        server.login(email_config['sender_email'], email_config['sender_password'])
        server.sendmail(email_config['sender_email'], email_config['recipient_email'], msg.as_string())
        server.quit()
        
        print(f"[EMAIL] Notification sent: {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send notification: {e}")
        return False

def check_overdue_payments():
    """Check for overdue rent payments and send notifications"""
    try:
        with get_db() as conn:
            properties = conn.execute('SELECT * FROM properties').fetchall()
        
        if not properties:
            return
        
        # Get current day of the week
        current_day = datetime.now().strftime('%A')
        
        # Get transactions for checking
        transactions = get_akahu_transactions()
        
        overdue_properties = []
        
        for prop in properties:
            # Check if rent is due today
            if prop['due_day'] == current_day:
                result = check_property_payment(prop, transactions)
                if not result['payment_found']:
                    overdue_properties.append(prop)
        
        # Send notification if there are overdue payments
        if overdue_properties:
            subject = f"🚨 Rent Alert: {len(overdue_properties)} Overdue Payment(s)"
            message = f"The following properties have overdue rent payments as of {datetime.now().strftime('%Y-%m-%d')}:\n\n"
            
            for prop in overdue_properties:
                message += f"• {prop['property_name']} - {prop['tenant_name']}: ${prop['rent_amount']}\n"
            
            message += f"\nPlease follow up with tenants or check your bank statements.\n\nRentCheck Dashboard: http://localhost:5001"
            
            send_email_notification(subject, message)
        else:
            print("[SCHEDULER] No overdue payments found")
            
    except Exception as e:
        print(f"[SCHEDULER ERROR] Error checking overdue payments: {e}")

@app.route('/send_test_email')
def send_test_email():
    """Test endpoint for sending email notifications"""
    success = send_email_notification(
        "RentCheck Test Email", 
        "This is a test email from your RentCheck application. Email notifications are working correctly!"
    )
    return jsonify({'success': success})

@app.route('/manual_check_overdue')
def manual_check_overdue():
    """Manual endpoint to check for overdue payments"""
    check_overdue_payments()
    return jsonify({'success': True, 'message': 'Overdue payment check completed'})

# Set up scheduler for daily checks
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_overdue_payments,
    trigger="cron",
    hour=9,  # Check at 9 AM daily
    minute=0,
    id='rent_check',
    replace_existing=True
)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Initialize database when module loads (for both dev and production)
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=config('DEBUG', default=False, cast=bool), host='0.0.0.0', port=port)