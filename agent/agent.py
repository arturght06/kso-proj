import requests
import time
import socket
import subprocess
import os
import json
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = os.getenv("SERVER_URL", "http://vm-serwer:5555")
HOSTNAME = socket.gethostname()
IP_ADDRESS = socket.gethostbyname(HOSTNAME)
CHECK_INTERVAL = 5

class SecurityAgent:
    def __init__(self):
        self.active_rule_signatures = set()
        self.session = requests.Session()
    
    def _get_rule_signature(self, rule):
        return f"{rule['path']}|{rule['permissions']}|{rule['key']}"

    def run_command(self, cmd):
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass
        
    def heartbeat(self):
        try:
            payload = { "hostname": HOSTNAME, "ip": IP_ADDRESS }
            res = self.session.post(f"{SERVER_URL}/api/heartbeat", json=payload, timeout=2)
            if res.status_code == 200:
                print(f"[+] Heartbeat OK.")
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
        incoming_signatures = set()
        incoming_rules_map = {}

        for rule in rules_list:
            sig = self._get_rule_signature(rule)
            incoming_signatures.add(sig)
            incoming_rules_map[sig] = rule
        
        to_add = incoming_signatures - self.active_rule_signatures

        if not to_add:
            return

        print("[*] Applying new audit rules via auditctl...")
        for sig in to_add:
            rule = incoming_rules_map[sig]
            cmd = f"auditctl -w {rule['path']} -p {rule['permissions']} -k {rule['key']}"
            self.run_command(cmd)
            self.active_rule_signatures.add(sig)
            print(f"[+] Applied rule: {rule['key']}")

    def ensure_dependencies(self):
        # Sprawdzamy czy auditd i rsyslog działają
        self.run_command("systemctl start auditd")
        self.run_command("systemctl start rsyslog")

    def run(self):
        print(f"[*] Agent started on {HOSTNAME}. Logs transport handled by Rsyslog (TLS).")
        self.ensure_dependencies()
        # Czyścimy stare reguły na starcie
        self.run_command("auditctl -D")

        while True:
            if self.heartbeat():
                self.sync_config()
            
            # Agent śpi i tylko odświeża konfig co 5s.
            # Logi lecą niezależnie przez rsyslogd.
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("CRITICAL: Agent must run as root.")
        exit(1)
        
    agent = SecurityAgent()
    agent.run()