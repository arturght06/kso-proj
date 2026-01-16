from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import enum

db = SQLAlchemy()

host_rules = db.Table('host_rules',
    db.Column('host_id', db.Integer, db.ForeignKey('hosts.id'), primary_key=True),
    db.Column('rule_id', db.Integer, db.ForeignKey('monitoring_rules.id'), primary_key=True)
)

class Severity(enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class Host(db.Model):
    __tablename__ = 'hosts'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    last_heartbeat = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    
    rules = db.relationship('MonitoringRule', secondary=host_rules, lazy='subquery',
        backref=db.backref('hosts', lazy=True))
    logs = db.relationship('LogEntry', backref='host', lazy=True)

class MonitoringRule(db.Model):
    __tablename__ = 'monitoring_rules'
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(512), nullable=False)
    permissions = db.Column(db.String(4), default="wa")
    key_label = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class LogEntry(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    severity = db.Column(db.Enum(Severity), default=Severity.INFO)
    program = db.Column(db.String(64))
    message = db.Column(db.Text)
    details = db.Column(JSONB)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('logs.id'))
    title = db.Column(db.String(255), nullable=False)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)