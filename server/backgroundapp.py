import threading
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from models import db, Host, LogEntry, MonitoringRule, host_rules, Severity, User
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from time import sleep

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:secret_kso_password@localhost:5432/kso_monitor')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret_socket_key')

db.init_app(app)

socketio = SocketIO(app, cors_allowed_origins="*")

def seed_data():
    if not MonitoringRule.query.first():
        rules = [
            MonitoringRule(path='/etc/passwd', permissions='wa', key_label='identity_theft', description='Monitor changes to user list'),
            MonitoringRule(path='/etc/shadow', permissions='wa', key_label='shadow_access', description='Monitor password hash changes'),
            MonitoringRule(path='/bin/bash', permissions='x', key_label='shell_exec', description='Monitor shell execution')
        ]
        db.session.add_all(rules)

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True)
        admin.set_password(os.getenv('ADMIN_DEFAULT_PASSWORD'))
        db.session.add(admin)
        print("[Init] Seeded default admin user.")
    
    db.session.commit()

def monitor_hosts():
    with app.app_context():
        while True:
            try:
                hosts = Host.query.all()
                now = datetime.datetime.now(datetime.timezone.utc)
                
                for host in hosts:
                    if not host.last_heartbeat:
                        continue

                    last_hb = host.last_heartbeat
                    if last_hb.tzinfo is None:
                        last_hb = last_hb.replace(tzinfo=timezone.utc)

                    delta = (now - last_hb).total_seconds()

                    # set offline if host hasn't sent heartbeat in last 60 seconds
                    is_online = delta < 60
                    
                    # send status update via SocketIO to browser client
                    socketio.emit('host_status_update', {
                        'host_id': host.id,
                        'hostname': host.hostname,
                        'is_online': is_online,
                        'last_seen': host.last_heartbeat.strftime('%H:%M:%S')
                    })
            except Exception as e:
                print(f"Monitor error: {e}")
            
            sleep(5)

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    hostname = data.get('hostname')
    ip = data.get('ip')
    
    host = Host.query.filter_by(hostname=hostname).first()
    if not host:
        host = Host(hostname=hostname, ip_address=ip)
        # Auto-assign all rules to new host for MVP simplicity
        rules = MonitoringRule.query.all()
        host.rules.extend(rules)
        db.session.add(host)
    
    host.last_heartbeat = datetime.now(timezone.utc)
    host.ip_address = ip 
    host.enabled = True
    db.session.commit()
    
    return jsonify({"status": "ok", "host_id": host.id})

@app.route('/api/config/<hostname>', methods=['GET'])
def get_config(hostname):
    host = Host.query.filter_by(hostname=hostname).first()
    if not host:
        return jsonify({"error": "Host not known"}), 404
    
    rules_data = []
    for r in host.rules:
        rules_data.append({
            "path": r.path,
            "permissions": r.permissions,
            "key": r.key_label
        })
    
    return jsonify({"rules": rules_data})

@app.route('/api/logs', methods=['POST'])
def receive_logs():
    data = request.json
    hostname = data.get('hostname')
    logs = data.get('logs', [])
    
    host = Host.query.filter_by(hostname=hostname).first()
    if not host:
        return jsonify({"error": "Unknown host"}), 403

    entries = []
    for l in logs:
        severity_enum = getattr(Severity, l.get('severity', 'INFO').upper(), Severity.INFO)
        entry = LogEntry(
            host_id=host.id,
            program=l.get('program'),
            message=l.get('message'),
            severity=severity_enum,
            details=l.get('details', {})
        )
        entries.append(entry)
    
    db.session.add_all(entries)
    db.session.commit()
    
    return jsonify({"status": "received", "count": len(entries)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()


    threading.Thread(target=monitor_hosts, daemon=True).start()
    
    # W produkcji tu musi być context SSL!
    app.run(host='0.0.0.0', port=5555, debug=True)


