import socket
import re
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

from backgroundapp import app
from models import db, Host, LogEntry, Severity

load_dotenv()

def parse_and_save_log(raw_data):
    try:
        # Rozdzielamy Hostname od reszty wiadomości
        parts = raw_data.strip().split(' ', 1)
        if len(parts) < 2:
            return
        
        hostname = parts[0]
        message = parts[1]
        
        # Filtrowanie
        if 'key=' not in message:
            return
        if 'type=SYSCALL' not in message and 'type=EXECVE' not in message:
             return
        
        key_match = re.search(r'key="?(\w+)"?', message)
        key_label = key_match.group(1) if key_match else "unknown"

        exe_match = re.search(r'exe="([^"]+)"', message)
        executable = exe_match.group(1) if exe_match else None

        uid_match = re.search(r'uid=(\d+)', message)
        uid = uid_match.group(1) if uid_match else None

        # Używamy kontekstu aplikacji Flask, aby dostać się do DB
        with app.app_context():
            host = Host.query.filter_by(hostname=hostname).first()
            if not host:
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

def run_server():
    HOST = '127.0.0.1'
    PORT = 9999
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
            s.listen()
            print(f"[Syslog Listener] Listening on {HOST}:{PORT}")
        except Exception as e:
            print(f"CRITICAL: Cannot bind port {PORT}: {e}")
            return

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
                print(f"[Connection Error] {e}")

if __name__ == '__main__':
    run_server()
