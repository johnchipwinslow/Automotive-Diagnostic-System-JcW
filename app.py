from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import json
import datetime
import hashlib
import sqlite3
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.url_map.strict_slashes = False

@dataclass
class User:
    user_id: int
    username: str
    email: str
    role: str
    created_date: str
    last_login: str
    is_active: bool

class UserManager:
    def __init__(self, db_path: str = "diagnostic_system.db"):
        self.db_path = db_path
        self._initialize_database()
        self._create_default_admin()

    def _initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'technician',
                created_date TEXT NOT NULL,
                last_login TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS diagnostic_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                vehicle_info TEXT,
                dtc_codes TEXT,
                diagnosis_result TEXT,
                timestamp TEXT,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')

        conn.commit()
        conn.close()

    def _create_default_admin(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count == 0:
            admin_password = "admin123"
            password_hash = self._hash_password(admin_password)

            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role, created_date, is_active)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ("admin", password_hash, "admin@shop.com", "admin", 
                  datetime.datetime.now().isoformat(), True))

        conn.commit()
        conn.close()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        password_hash = self._hash_password(password)

        cursor.execute('''
            SELECT user_id, username, email, role, created_date, is_active
            FROM users 
            WHERE username = ? AND password_hash = ? AND is_active = 1
        ''', (username, password_hash))

        user_data = cursor.fetchone()

        if user_data:
            cursor.execute('''
                UPDATE users SET last_login = ? WHERE user_id = ?
            ''', (datetime.datetime.now().isoformat(), user_data[0]))

            user = User(
                user_id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                role=user_data[3],
                created_date=user_data[4],
                last_login=datetime.datetime.now().isoformat(),
                is_active=user_data[5]
            )

            conn.commit()
            conn.close()
            return user

        conn.close()
        return None

    def get_user_permissions(self, user_id: int) -> Dict[str, bool]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT role FROM users WHERE user_id = ?', (user_id,))
        role_result = cursor.fetchone()
        if not role_result:
            conn.close()
            return {}

        role = role_result[0]
        base_permissions = {
            "admin": {
                "can_diagnose": True,
                "can_manage_users": True,
                "can_view_logs": True,
                "can_export_reports": True,
                "can_edit_dtc_db": True
            },
            "technician": {
                "can_diagnose": True,
                "can_manage_users": False,
                "can_view_logs": True,
                "can_export_reports": False,
                "can_edit_dtc_db": False
            },
            "viewer": {
                "can_diagnose": False,
                "can_manage_users": False,
                "can_view_logs": True,
                "can_export_reports": False,
                "can_edit_dtc_db": False
            }
        }.get(role, {})

        conn.close()
        return base_permissions

class DiagnosticSystem:
    def __init__(self):
        self.user_manager = UserManager()
        self.dtc_database = self._initialize_dtc_database()

    def _initialize_dtc_database(self) -> Dict:
        return {
            "P0300": {
                "description": "Random/Multiple Cylinder Misfire Detected",
                "system": "Engine",
                "severity": "High",
                "possible_causes": [
                    "Faulty spark plugs or ignition coils",
                    "Fuel injector problems",
                    "Low fuel pressure",
                    "Vacuum leaks"
                ],
                "diagnostic_steps": [
                    "Check spark plugs and ignition coils",
                    "Test fuel pressure and injectors",
                    "Perform compression test",
                    "Check for vacuum leaks"
                ],
                "tools_needed": ["OBD scanner", "Compression tester", "Fuel pressure gauge"]
            },
            "P0171": {
                "description": "System Too Lean (Bank 1)",
                "system": "Fuel System",
                "severity": "Medium",
                "possible_causes": [
                    "Vacuum leak",
                    "Faulty MAF sensor",
                    "Clogged fuel filter",
                    "Weak fuel pump"
                ],
                "diagnostic_steps": [
                    "Check for vacuum leaks using smoke test",
                    "Test MAF sensor readings",
                    "Check fuel pressure",
                    "Inspect oxygen sensor data"
                ],
                "tools_needed": ["Smoke machine", "Multimeter", "Fuel pressure gauge"]
            },
            "P0420": {
                "description": "Catalyst System Efficiency Below Threshold (Bank 1)",
                "system": "Emissions",
                "severity": "Medium",
                "possible_causes": [
                    "Faulty catalytic converter",
                    "Faulty oxygen sensors",
                    "Engine misfire",
                    "Exhaust leaks"
                ],
                "diagnostic_steps": [
                    "Check oxygen sensor readings",
                    "Test catalytic converter efficiency",
                    "Check for exhaust leaks",
                    "Verify engine performance"
                ],
                "tools_needed": ["OBD scanner", "Exhaust gas analyzer", "Multimeter"]
            }
        }

    def diagnose_vehicle(self, vehicle_info: Dict, dtc_codes: List[str], user_id: int) -> Dict:
        diagnosis = {
            "vehicle": vehicle_info,
            "timestamp": datetime.datetime.now().isoformat(),
            "codes_found": [],
            "priority_codes": [],
            "estimated_time": 0,
            "tools_needed": set()
        }

        for code in dtc_codes:
            dtc_info = self.dtc_database.get(code.upper())
            if dtc_info:
                code_data = {"code": code, "info": dtc_info}
                diagnosis["codes_found"].append(code_data)

                if dtc_info["severity"] == "High":
                    diagnosis["priority_codes"].append(code)

                diagnosis["tools_needed"].update(dtc_info["tools_needed"])

        diagnosis["tools_needed"] = list(diagnosis["tools_needed"])
        diagnosis["estimated_time"] = len(dtc_codes) * 30 + len(diagnosis["priority_codes"]) * 60

        self._log_diagnosis(diagnosis, user_id)

        return diagnosis

    def _log_diagnosis(self, diagnosis: Dict, user_id: int):
        conn = sqlite3.connect(self.user_manager.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO diagnostic_logs (user_id, vehicle_info, dtc_codes, diagnosis_result, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id,
            json.dumps(diagnosis["vehicle"]),
            json.dumps([code["code"] for code in diagnosis["codes_found"]]),
            json.dumps(diagnosis),
            diagnosis["timestamp"]
        ))

        conn.commit()
        conn.close()

# Initialize the diagnostic system
diagnostic_system = DiagnosticSystem()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))

            permissions = diagnostic_system.user_manager.get_user_permissions(session['user_id'])
            if not permissions.get(permission, False):
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
@app.route('/login/', methods=['GET', 'POST'])
def login():
    ...
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = diagnostic_system.user_manager.authenticate_user(username, password)
        if user:
            session['user_id'] = user.user_id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    permissions = diagnostic_system.user_manager.get_user_permissions(session['user_id'])
    return render_template('dashboard.html', permissions=permissions)

@app.route('/diagnose', methods=['GET', 'POST'])
@login_required
@permission_required('can_diagnose')
def diagnose():
    if request.method == 'POST':
        vehicle_info = {
            'year': request.form['year'],
            'make': request.form['make'],
            'model': request.form['model'],
            'vin': request.form['vin'],
            'mileage': request.form['mileage']
        }

        dtc_codes = [code.strip().upper() for code in request.form['dtc_codes'].split(',') if code.strip()]

        diagnosis = diagnostic_system.diagnose_vehicle(vehicle_info, dtc_codes, session['user_id'])

        return render_template('diagnosis_result.html', diagnosis=diagnosis)

    return render_template('diagnose.html')

@app.route('/logs')
@login_required
@permission_required('can_view_logs')
def view_logs():
    conn = sqlite3.connect(diagnostic_system.user_manager.db_path)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT dl.timestamp, u.username, dl.vehicle_info, dl.dtc_codes
        FROM diagnostic_logs dl
        JOIN users u ON dl.user_id = u.user_id
        ORDER BY dl.timestamp DESC
        LIMIT 50
    ''')

    logs = []
    for row in cursor.fetchall():
        vehicle_info = json.loads(row[2])
        dtc_codes = json.loads(row[3])
        logs.append({
            'timestamp': row[0],
            'technician': row[1],
            'vehicle': f"{vehicle_info.get('year', '')} {vehicle_info.get('make', '')} {vehicle_info.get('model', '')}",
            'codes': ', '.join(dtc_codes)
        })

    conn.close()
    return render_template('logs.html', logs=logs)
    
# Admin Routes
@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if session['username'] != 'admin':
        flash('Only admin can change this password.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        user_manager = diagnostic_system.user_manager
        password_hash = user_manager._hash_password(new_password)
        conn = sqlite3.connect(user_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (password_hash,))
        conn.commit()
        conn.close()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_users')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        
        user_manager = diagnostic_system.user_manager
        password_hash = user_manager._hash_password(password)
        
        try:
            conn = sqlite3.connect(user_manager.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role, created_date, is_active)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, email, role, datetime.datetime.now().isoformat(), True))
            conn.commit()
            conn.close()
            flash(f'User {username} added successfully!', 'success')
            return redirect(url_for('manage_users'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
    
    return render_template('add_user.html')

@app.route('/admin/manage_users')
@login_required
@permission_required('can_manage_users')
def manage_users():
    conn = sqlite3.connect(diagnostic_system.user_manager.db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_id, username, email, role, created_date, last_login, is_active
        FROM users
        ORDER BY created_date DESC
    ''')
    
    users = []
    for row in cursor.fetchall():
        users.append({
            'user_id': row[0],
            'username': row[1],
            'email': row[2],
            'role': row[3],
            'created_date': row[4][:19] if row[4] else '',
            'last_login': row[5][:19] if row[5] else 'Never',
            'is_active': row[6]
        })
    
    conn.close()
    return render_template('manage_users.html', users=users)
    
    
if __name__ == '__main__':
    app.run(debug=True)
