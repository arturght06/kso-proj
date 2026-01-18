import threading
import socket
import re
from flask import Flask, request, jsonify
from models import db, Host, LogEntry, MonitoringRule, host_rules, Severity, User, Alert
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from time import sleep
# from reporter import generate_host_chart, generate_pdf_report # Odkomentuj jeśli używasz

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:secret_kso_password@localhost:5432/kso_monitor')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret_socket_key')

db.init_app(app)

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

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    hostname = data.get('hostname')
    ip = data.get('ip')
    
    host = Host.query.filter_by(hostname=hostname).first()
    if not host:
        host = Host(hostname=hostname, ip_address=ip)
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

# --- MODUŁ: Odbiornik Syslog (TCP Server) ---
def parse_and_save_log(raw_data):
    try:
        parts = raw_data.strip().split(' ', 1)
        if len(parts) < 2:
            return
        
        hostname = parts[0]
        message = parts[1]
        
        # Filtrowanie (opcjonalne, zależne od potrzeb)
        # if 'type=SYSCALL' not in message and 'type=EXECVE' not in message:
        #      pass
        
        key_match = re.search(r'key="?(\w+)"?', message)
        key_label = key_match.group(1) if key_match else "unknown"

        exe_match = re.search(r'exe="([^"]+)"', message)
        executable = exe_match.group(1) if exe_match else None

        uid_match = re.search(r'uid=(\d+)', message)
        uid = uid_match.group(1) if uid_match else None

        with app.app_context():
            host = Host.query.filter_by(hostname=hostname).first()
            if not host:
                print(f"[Syslog] Unknown host: {hostname}")
                return

            details = {
                "raw": message,
                "key_label": key_label,
                "executable": executable,
                "uid": uid,
                "timestamp": str(datetime.now(timezone.utc))
            }

            log_entry = LogEntry(
                host_id=host.id,
                program="auditd",
                message=message,
                severity=Severity.WARNING,
                details=details,
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(log_entry)
            db.session.commit()

    except Exception as e:
        print(f"[Syslog Error] {e}")

def syslog_server():
    HOST = '127.0.0.1'
    PORT = 9999
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # ZMIANA 1: Pozwala na restart serwera bez błędu "Address already in use"
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            s.bind((HOST, PORT))
        except OSError as e:
            print(f"[Syslog] CRITICAL: Port {PORT} is busy. {e}")
            return

        s.listen()
        print(f"[Syslog Listener] Listening on {HOST}:{PORT}")
        
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    buffer = ""
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        buffer += data.decode('utf-8', errors='ignore')
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line:
                                parse_and_save_log(line)
            except Exception as e:
                print(f"[Syslog Loop Error] {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
    
    # ZMIANA 2: Uruchamiamy wątek TYLKO w procesie workera (po przeładowaniu), 
    # a nie w głównym procesie nadzorczym. To eliminuje podwójne uruchomienie.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Thread(target=syslog_server, daemon=True).start()
    
    # Jeśli uruchamiasz bez debug=True, musisz usunąć powyższy warunek if
    app.run(host='0.0.0.0', port=5555, debug=True)