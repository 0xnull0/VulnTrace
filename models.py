from app import db
from datetime import datetime
import json
from flask import current_app

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
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='in_progress')  # in_progress, completed, failed
    urls_scanned = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, default=0)
    error_message = db.Column(db.Text)
    
    # Summary stats
    vulnerability_count = db.Column(db.Integer, default=0)
    high_severity_count = db.Column(db.Integer, default=0)
    medium_severity_count = db.Column(db.Integer, default=0)
    low_severity_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    crawled_urls = db.relationship('CrawledUrl', backref='scan', lazy=True)
    
    def __repr__(self):
        return f'<Scan {self.id}>'
    
    def to_dict(self):
        target_data = None
        if self.target:
            target_data = self.target.to_dict()
        return {
            'id': self.id,
            'target': target_data,
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
    subtype = db.Column(db.String(100))
    url = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50))  # high, medium, low, info
    description = db.Column(db.Text)
    parameter = db.Column(db.String(100))
    payload = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    header = db.Column(db.String(100))
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
    status_code = db.Column(db.Integer)
    content_type = db.Column(db.String(100))
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
    error_type = db.Column(db.String(100))
    message = db.Column(db.Text)
    url = db.Column(db.String(255))
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