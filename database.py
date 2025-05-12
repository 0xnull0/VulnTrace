import os
import logging
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime

# Setup logging
logger = logging.getLogger(__name__)

# Create database base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the base class
db = SQLAlchemy(model_class=Base)

# Database models
class ScanTarget(db.Model):
    """Target URL of a vulnerability scan"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    ip_addresses = db.Column(db.String(255))  # Stored as comma-separated
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    scans = db.relationship('Scan', backref='target', lazy=True)
    
    def __repr__(self):
        return f'<ScanTarget {self.url}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'domain': self.domain,
            'ip_addresses': self.ip_addresses.split(',') if self.ip_addresses else [],
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class Scan(db.Model):
    """Vulnerability scan record"""
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('scan_target.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # basic, full
    depth = db.Column(db.Integer, default=2)
    timeout = db.Column(db.Integer, default=10)
    started_at = db.Column(db.DateTime, default=datetime.now)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='in_progress')  # in_progress, completed, failed
    urls_scanned = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, default=0)
    error_message = db.Column(db.Text, nullable=True)
    
    # Summary stats
    vulnerability_count = db.Column(db.Integer, default=0)
    high_severity_count = db.Column(db.Integer, default=0)
    medium_severity_count = db.Column(db.Integer, default=0)
    low_severity_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    crawled_urls = db.relationship('CrawledUrl', backref='scan', lazy=True)
    errors = db.relationship('ScanError', backref='scan', lazy=True)
    
    def __repr__(self):
        return f'<Scan {self.id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target.to_dict() if self.target else None,
            'scan_type': self.scan_type,
            'depth': self.depth,
            'timeout': self.timeout,
            'started_at': self.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None,
            'status': self.status,
            'urls_scanned': self.urls_scanned,
            'scan_duration': self.scan_duration,
            'error_message': self.error_message,
            'summary': {
                'vulnerability_count': self.vulnerability_count,
                'high_severity': self.high_severity_count,
                'medium_severity': self.medium_severity_count,
                'low_severity': self.low_severity_count,
                'risk_score': self.risk_score
            }
        }

class Vulnerability(db.Model):
    """Vulnerability found during a scan"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    subtype = db.Column(db.String(100), nullable=True)
    url = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50))  # high, medium, low, info
    description = db.Column(db.Text)
    parameter = db.Column(db.String(100), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text)
    header = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<Vulnerability {self.vulnerability_type} at {self.url}>'
    
    def to_dict(self):
        result = {
            'id': self.id,
            'type': self.vulnerability_type,
            'url': self.url,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if self.subtype:
            result['subtype'] = self.subtype
        if self.parameter:
            result['parameter'] = self.parameter
        if self.payload:
            result['payload'] = self.payload
        if self.evidence:
            result['evidence'] = self.evidence
        if self.header:
            result['header'] = self.header
            
        return result

class CrawledUrl(db.Model):
    """URL discovered during crawling"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<CrawledUrl {self.url}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class ScanError(db.Model):
    """Errors encountered during a scan"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    error_type = db.Column(db.String(100), nullable=True)
    message = db.Column(db.Text)
    url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<ScanError {self.error_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'error_type': self.error_type,
            'message': self.message,
            'url': self.url,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

def init_app(app):
    """Initialize the database with the Flask app"""
    # Configure the database
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///vulntrace.db"
    
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Print debug info
    logger.debug(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Initialize the app with the extension
    db.init_app(app)
    
    # Create all tables
    with app.app_context():
        db.create_all()