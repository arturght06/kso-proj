import requests
import time
import socket
import subprocess
import os
import re
import json
from datetime import datetime

SERVER_URL = "http://127.0.0.1:5555"
HOSTNAME = socket.gethostname()
IP_ADDRESS = socket.gethostbyname(HOSTNAME)
AUDIT_LOG_FILE = "/var/log/audit/audit.log"
BATCH_SIZE = 5
CHECK_INTERVAL = 5

class SecurityAgent:
    def __init__(self):
        self.rules = {}
        self.log_buffer = []
        self.session = requests.Session()

    def run_command(self, cmd):
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass

    def heartbeat(self):
        try:
            payload = {
                "hostname": HOSTNAME,
                "ip": IP_ADDRESS
            }
            res = self.session.post(f"{SERVER_URL}/api/heartbeat", json=payload, timeout=2)
            if res.status_code == 200:
                print(f"[+] Heartbeat OK. Host ID: {res.json().get('host_id')}")
                return True
        except Exception as e:
            print(f"[-] Heartbeat failed: {e}")
        return False

    def sync_config(self):
        try:
            res = self.session.get(f"{SERVER_URL}/api/config/{HOSTNAME}", timeout=2)
            if res.status_code == 200:
                new_rules = res.json().get('rules', [])
                self.apply_audit_rules(new_rules)
        except Exception as e:
            print(f"[-] Config sync failed: {e}")

    def apply_audit_rules(self, rules_list):
        print("[*] Applying new audit rules...")
        self.run_command("auditctl -D")
        
        active_keys = []
        for rule in rules_list:
            path = rule['path']
            perm = rule['permissions']
            key = rule['key']
            cmd = f"auditctl -w {path} -p {perm} -k {key}"
            self.run_command(cmd)
            active_keys.append(key)
            self.rules[key] = rule
        
        print(f"[+] Applied {len(active_keys)} rules: {active_keys}")

    def parse_audit_line(self, line):
        if 'key=' not in line:
            return None
        
        key_match = re.search(r'key="?(\w+)"?', line)
        if not key_match:
            return None
        
        key = key_match.group(1)
        if key not in self.rules:
            return None

        log_entry = {
            "program": "auditd",
            "message": line.strip(),
            "severity": "warning", 
            "details": {
                "raw": line.strip(),
                "key_label": key,
                "timestamp": str(datetime.now())
            }
        }

        # Proba wyciagniecia exe i uid dla lepszego kontekstu
        exe_match = re.search(r'exe="([^"]+)"', line)
        if exe_match:
            log_entry['details']['executable'] = exe_match.group(1)
            
        uid_match = re.search(r'uid=(\d+)', line)
        if uid_match:
            log_entry['details']['uid'] = uid_match.group(1)

        return log_entry

    def flush_logs(self):
        if not self.log_buffer:
            return
        
        payload = {
            "hostname": HOSTNAME,
            "logs": self.log_buffer
        }
        
        try:
            res = self.session.post(f"{SERVER_URL}/api/logs", json=payload, timeout=2)
            if res.status_code == 200:
                print(f"[+] Sent {len(self.log_buffer)} logs.")
                self.log_buffer = []
            else:
                print(f"[-] Server rejected logs: {res.status_code}")
        except Exception as e:
            print(f"[-] Failed to send logs: {e}")
            # W prawdziwym zyciu tu bysmy zachowali bufor, ale w MVP czyscimy zeby nie zapchac pamieci
            if len(self.log_buffer) > 100:
                self.log_buffer = []

    def monitor_loop(self):
        if not os.path.exists(AUDIT_LOG_FILE):
            print(f"[-] Audit log file not found at {AUDIT_LOG_FILE}")
            return

        f = open(AUDIT_LOG_FILE, 'r')
        f.seek(0, 2) # Idz na koniec pliku

        last_heartbeat = 0

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                
                # Obsluga heartbeat co 5 sekund
                if time.time() - last_heartbeat > CHECK_INTERVAL:
                    if self.heartbeat():
                        self.sync_config()
                    self.flush_logs()
                    last_heartbeat = time.time()
                continue
            
            parsed = self.parse_audit_line(line)
            if parsed:
                self.log_buffer.append(parsed)
                if len(self.log_buffer) >= BATCH_SIZE:
                    self.flush_logs()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("CRITICAL: Agent must run as root to access audit subsystem.")
        exit(1)
        
    agent = SecurityAgent()
    print(f"[*] Starting KSO Agent on {HOSTNAME}...")
    
    # Pierwsza rejestracja
    if agent.heartbeat():
        agent.sync_config()
        agent.monitor_loop()
    else:
        print("[-] Could not contact server. Exiting.")

