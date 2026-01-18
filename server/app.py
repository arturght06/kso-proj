from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Host, LogEntry, MonitoringRule, User, Severity
import datetime
from datetime import timedelta
import os
from dotenv import load_dotenv
from sqlalchemy import func
from reporter import generate_host_chart, generate_pdf_report


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'super_secret_key_for_kso_monitor')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:secret_kso_password@localhost:5432/kso_monitor')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Increase pool size to prevent TimeoutError under load
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_recycle": 1800,
}

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- WEBSOCKET HANDLER ---

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    print(f"[WS] Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[WS] Client disconnected: {request.sid}")

@socketio.on('start_monitoring')
def handle_start_monitoring(data=None):
    user_sid = request.sid
    target_host_id = None
    
    # Check if client wants specific host logs
    if data and 'host_id' in data:
        try:
            target_host_id = int(data['host_id'])
            print(f"[WS] Client {user_sid} monitoring SPECIFIC HOST: {target_host_id}")
        except ValueError:
            pass
    else:
        print(f"[WS] Client {user_sid} monitoring ALL HOSTS")

    client_log_cursor = 0
    with app.app_context():
        max_id = db.session.query(func.max(LogEntry.id)).scalar()
        client_log_cursor = max_id if max_id else 0
        
    client_host_cache = {} 

    while True:
        try:
            with app.app_context():
                # 1. Host Status
                hosts = Host.query.all()
                now = datetime.datetime.now(datetime.timezone.utc)

                for host in hosts:
                    is_online = False
                    if host.last_heartbeat:
                        last_hb = host.last_heartbeat
                        if last_hb.tzinfo is None:
                            last_hb = last_hb.replace(tzinfo=datetime.timezone.utc)
                        delta = (now - last_hb).total_seconds()
                        is_online = delta < 60
                    
                    prev_state = client_host_cache.get(host.id)
                    if prev_state is None or prev_state != is_online:
                        # Send if global dashboard OR specific host match
                        if target_host_id is None or target_host_id == host.id:
                            socketio.emit('host_status_update', {
                                'host_id': host.id,
                                'hostname': host.hostname,
                                'is_online': is_online,
                                'last_seen': host.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if host.last_heartbeat else "Never"
                            }, room=user_sid)
                        client_host_cache[host.id] = is_online

                # 2. New Logs
                query = LogEntry.query.filter(LogEntry.id > client_log_cursor)
                if target_host_id:
                    query = query.filter_by(host_id=target_host_id)
                
                new_logs = query.order_by(LogEntry.id.asc()).all()
                
                if new_logs:
                    for log in new_logs:
                        payload = {
                            'timestamp': log.timestamp.strftime('%H:%M:%S'),
                            'hostname': log.host.hostname,
                            'program': log.program,
                            'message': log.message or "", # Handle None/Null messages safely
                            'severity': log.severity.value
                        }
                        socketio.emit('new_log', payload, room=user_sid)
                        client_log_cursor = log.id

                # CRITICAL: Force session cleanup to see new data in next iteration
                db.session.remove()

            socketio.sleep(2)

        except Exception as e:
            print(f"[WS] Error for {user_sid}: {e}")
            with app.app_context():
                db.session.remove()
            break

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
    limit = request.args.get('limit', 20, type=int)
    hosts = Host.query.all()
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(limit).all()
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
    search_query = request.args.get('q', '')
    query = LogEntry.query.filter_by(host_id=host.id)
    limit = request.args.get('limit', 20, type=int)

    now = datetime.datetime.now()
    default_start = now - timedelta(days=1)
    
    date_from_str = request.args.get('date_from', default_start.strftime('%Y-%m-%dT%H:%M'))
    date_to_str = request.args.get('date_to', now.strftime('%Y-%m-%dT%H:%M'))

    try:
        date_from = datetime.datetime.strptime(date_from_str, '%Y-%m-%dT%H:%M')
        date_to = datetime.datetime.strptime(date_to_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        date_from = default_start
        date_to = now

    chart_base64 = generate_host_chart(host.id, date_from, date_to)

    query = LogEntry.query.filter_by(host_id=host.id)
    
    query = query.filter(LogEntry.timestamp >= date_from, LogEntry.timestamp <= date_to)

    if search_query:
        query = query.filter(
            (LogEntry.message.ilike(f'%{search_query}%')) | 
            (LogEntry.program.ilike(f'%{search_query}%'))
        )

    logs = query.order_by(LogEntry.timestamp.desc()).limit(limit).all()
    
    return render_template('host_details.html', 
        host=host, 
        logs=logs, 
        search_query=search_query, 
        current_limit=limit,
        chart_data=chart_base64,
        date_from=date_from_str,
        date_to=date_to_str
    )

@app.route('/host/<int:host_id>/chart_image')
@login_required
def host_chart_image(host_id):
    now = datetime.datetime.now()
    default_start = now - timedelta(days=1)
    
    date_from_str = request.args.get('date_from', default_start.strftime('%Y-%m-%dT%H:%M'))
    date_to_str = request.args.get('date_to', now.strftime('%Y-%m-%dT%H:%M'))

    try:
        date_from = datetime.datetime.strptime(date_from_str, '%Y-%m-%dT%H:%M')
        date_to = datetime.datetime.strptime(date_to_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        date_from = default_start
        date_to = now

    img_buffer = generate_host_chart(host_id, date_from, date_to)
    
    if img_buffer:
        return send_file(img_buffer, mimetype='image/png')
    else:
        return "", 204

@app.route('/host/<int:host_id>/report')
@login_required
def download_report(host_id):
    now = datetime.datetime.now()
    default_start = now - timedelta(days=1)
    
    date_from_str = request.args.get('date_from', default_start.strftime('%Y-%m-%dT%H:%M'))
    date_to_str = request.args.get('date_to', now.strftime('%Y-%m-%dT%H:%M'))

    try:
        date_from = datetime.datetime.strptime(date_from_str, '%Y-%m-%dT%H:%M')
        date_to = datetime.datetime.strptime(date_to_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        date_from = default_start
        date_to = now

    pdf_buffer, filename = generate_pdf_report(host_id, date_from, date_to)
    
    if not pdf_buffer:
        flash("Could not generate report (Host not found or error).", "error")
        return redirect(url_for('host_details', host_id=host_id))

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

@app.route('/host/<int:host_id>/add_rule', methods=['POST'])
@login_required
def add_rule_to_host(host_id):
    host = Host.query.get_or_404(host_id)
    path = request.form.get('path')
    permissions = request.form.get('permissions')
    key = request.form.get('key_label')
    
    rule = MonitoringRule.query.filter_by(path=path, permissions=permissions, key_label=key).first()
    if not rule:
        rule = MonitoringRule(path=path, permissions=permissions, key_label=key)
        db.session.add(rule)
    
    if rule not in host.rules:
        host.rules.append(rule)
        db.session.commit()
        flash('Rule added.', 'success')
    else:
        flash('Rule already active.', 'info')
        
    return redirect(url_for('host_details', host_id=host_id))

@app.route('/host/<int:host_id>/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule_from_host(host_id, rule_id):
    host = Host.query.get_or_404(host_id)
    rule = MonitoringRule.query.get_or_404(rule_id)
    if rule in host.rules:
        host.rules.remove(rule)
        db.session.commit()
        flash('Rule removed.', 'warning')
    return redirect(url_for('host_details', host_id=host_id))

if __name__ == '__main__':
    print("Starting Web Interface on port 5002...")
    socketio.run(app, host='0.0.0.0', port=5002, debug=True, allow_unsafe_werkzeug=True)