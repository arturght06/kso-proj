from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Host, LogEntry, MonitoringRule, User, Severity, MonitoringRule
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from sqlalchemy import func

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY', 'super_secret_key_for_kso_monitor')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:secret_kso_password@localhost:5432/kso_monitor')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

last_processed_log_id = 0
host_status_cache = {}  # {host_id: boolean_is_online}

def init_globals():
    """Ustawia początkowy ID logów na max, żeby nie wysyłać starych logów przy restarcie."""
    global last_processed_log_id
    with app.app_context():
        max_id = db.session.query(func.max(LogEntry.id)).scalar()
        last_processed_log_id = max_id if max_id else 0
        print(f"[*] Monitoring starts from Log ID: {last_processed_log_id}")

def background_monitor():
    """Wątek monitorujący zmiany w bazie danych i wysyłający powiadomienia WS."""
    global last_processed_log_id
    
    with app.app_context():
        while True:
            try:
                # 1. SPRAWDZANIE STATUSU HOSTÓW (ONLINE/OFFLINE)
                hosts = Host.query.all()
                now = datetime.now(timezone.utc)

                for host in hosts:
                    # Logika online: heartbeat młodszy niż 60 sekund
                    is_online = False
                    if host.last_heartbeat:
                        last_hb = host.last_heartbeat
                        if last_hb.tzinfo is None:
                            last_hb = last_hb.replace(tzinfo=timezone.utc)
                        delta = (now - last_hb).total_seconds()
                        is_online = delta < 60
                    
                    # Sprawdź czy stan się zmienił względem cache
                    previous_state = host_status_cache.get(host.id)
                    
                    if previous_state is None or previous_state != is_online:
                        # state changed, emit update
                        print(f"[WS] Host {host.hostname} state changed: {previous_state} -> {is_online}")
                        socketio.emit('host_status_update', {
                            'host_id': host.id,
                            'hostname': host.hostname,
                            'is_online': is_online,
                            'last_seen': host.last_heartbeat.strftime('%H:%M:%S') if host.last_heartbeat else "Never"
                        })
                        
                        host_status_cache[host.id] = is_online

                # 2. SPRAWDZANIE NOWYCH LOGÓW
                # Pobierz logi, które mają ID większe niż ostatnio przetworzone
                new_logs = LogEntry.query.filter(LogEntry.id > last_processed_log_id).order_by(LogEntry.id.asc()).all()
                
                if new_logs:
                    for log in new_logs:
                        payload = {
                            'timestamp': log.timestamp.strftime('%H:%M:%S'),
                            'hostname': log.host.hostname,
                            'program': log.program,
                            'message': log.message,
                            'severity': log.severity.value
                        }
                        socketio.emit('new_log', payload)
                        # Przesuwamy wskaźnik
                        last_processed_log_id = log.id

            except Exception as e:
                print(f"[Monitor Error] {e}")
                db.session.rollback() # Ważne przy błędach DB w pętli
            
            # Odczekaj chwilę przed następnym sprawdzeniem bazy
            socketio.sleep(2)





# --- SETUP LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')

    return render_template('login.html')

@app.route('/')
@login_required
def dashboard():
    hosts = Host.query.all()
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(20).all()
    return render_template('dashboard.html', hosts=hosts, logs=recent_logs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/host/<int:host_id>')
@login_required
def host_details(host_id):
    host = Host.query.get_or_404(host_id)
    # last 50 logs for this host
    logs = LogEntry.query.filter_by(host_id=host.id).order_by(LogEntry.timestamp.desc()).limit(50).all()
    return render_template('host_details.html', host=host, logs=logs)

@app.route('/host/<int:host_id>/add_rule', methods=['POST'])
@login_required
def add_rule_to_host(host_id):
    host = Host.query.get_or_404(host_id)
    
    path = request.form.get('path')
    permissions = request.form.get('permissions')
    key = request.form.get('key_label')
    
    # check if rule already exists
    rule = MonitoringRule.query.filter_by(path=path, permissions=permissions, key_label=key).first()
    
    if not rule:
        rule = MonitoringRule(path=path, permissions=permissions, key_label=key)
        db.session.add(rule)
    
    # associate rule with host
    if rule not in host.rules:
        host.rules.append(rule)
        db.session.commit()
        flash('Rule added successfully. Agent will sync shortly.', 'success')
    else:
        flash('Rule already active on this host.', 'info')
        
    return redirect(url_for('host_details', host_id=host_id))

@app.route('/host/<int:host_id>/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule_from_host(host_id, rule_id):
    host = Host.query.get_or_404(host_id)
    rule = MonitoringRule.query.get_or_404(rule_id)
    
    if rule in host.rules:
        host.rules.remove(rule)
        db.session.commit()
        flash('Rule removed. Agent will stop tracking this path.', 'warning')
        
    return redirect(url_for('host_details', host_id=host_id))



if __name__ == '__main__':
    init_globals()
    socketio.start_background_task(target=background_monitor)

    print("Starting Web Interface on port 5000...")
    app.run(host='0.0.0.0', port=5002, debug=True)
