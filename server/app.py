from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Host, LogEntry, MonitoringRule, User, Severity, MonitoringRule
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY', 'super_secret_key_for_kso_monitor')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:secret_kso_password@localhost:5432/kso_monitor')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

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
    print("Starting Web Interface on port 5000...")
    app.run(host='0.0.0.0', port=5002, debug=True)
