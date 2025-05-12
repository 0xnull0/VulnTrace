import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import scanner
import json
from datetime import datetime
import database

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "vulntrace_default_secret")

# Initialize database
database.init_app(app)

# Add template context processor for current year
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/')
def index():
    """Render the main page with scan form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Initiate a vulnerability scan based on form input"""
    target = request.form.get('target', '')
    scan_type = request.form.get('scan_type', 'basic')
    depth = int(request.form.get('depth', 2))
    timeout = int(request.form.get('timeout', 10))
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    # Store scan parameters in session
    session['scan_target'] = target
    session['scan_type'] = scan_type
    session['scan_depth'] = depth
    session['scan_timeout'] = timeout
    session['scan_started'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    session['scan_in_progress'] = True
    
    # Create a unique report ID
    report_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}"
    session['last_report_id'] = report_id
    
    # Redirect to the scanning page
    return redirect(url_for('scanning_progress'))

@app.route('/scanning')
def scanning_progress():
    """Show the scanning in progress page with animation"""
    # Make sure we have an active scan
    if not session.get('scan_in_progress'):
        return redirect(url_for('index'))
    
    target = session.get('scan_target', '')
    scan_type = session.get('scan_type', 'basic')
    depth = session.get('scan_depth', 2)
    timeout = session.get('scan_timeout', 10)
    
    # Start the actual scan in a background thread if not already started
    if not session.get('scan_thread_started'):
        session['scan_thread_started'] = True
        
        # Start the scan in a background thread
        import threading
        
        def run_scan():
            try:
                # Create the scanner
                vuln_scanner = scanner.VulnerabilityScanner(
                    target=target,
                    scan_type=scan_type,
                    depth=depth,
                    timeout=timeout
                )
                
                # Run the scan
                results = vuln_scanner.run()
                
                # Store the results in session for report view
                session['scan_results'] = results
                session['scan_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                session['scan_in_progress'] = False
                session['scan_completed'] = True
                
                # Save results to database
                try:
                    # Create or get target
                    target_info = results.get('target_info', {})
                    target_domain = target_info.get('domain', '')
                    target_ip = ','.join(target_info.get('ip_addresses', []))
                    
                    db_target = database.ScanTarget.query.filter_by(url=target).first()
                    if not db_target:
                        db_target = database.ScanTarget(
                            url=target,
                            domain=target_domain,
                            ip_addresses=target_ip
                        )
                        database.db.session.add(db_target)
                        database.db.session.flush()
                    
                    # Create scan record
                    summary = results.get('summary', {})
                    db_scan = database.Scan(
                        target_id=db_target.id,
                        scan_type=scan_type,
                        depth=depth,
                        timeout=timeout,
                        completed_at=datetime.now(),
                        status='completed',
                        urls_scanned=summary.get('urls_scanned', 0),
                        scan_duration=summary.get('scan_duration', 0),
                        vulnerability_count=summary.get('vulnerability_count', 0),
                        high_severity_count=summary.get('high_severity', 0),
                        medium_severity_count=summary.get('medium_severity', 0),
                        low_severity_count=summary.get('low_severity', 0)
                    )
                    database.db.session.add(db_scan)
                    database.db.session.flush()
                    
                    # Add vulnerabilities
                    for vuln in results.get('vulnerabilities', []):
                        db_vuln = database.Vulnerability(
                            scan_id=db_scan.id,
                            vulnerability_type=vuln.get('type', 'unknown'),
                            subtype=vuln.get('subtype', None),
                            url=vuln.get('url', ''),
                            severity=vuln.get('severity', 'low'),
                            description=vuln.get('description', ''),
                            parameter=vuln.get('parameter', None),
                            payload=vuln.get('payload', None),
                            evidence=vuln.get('evidence', None),
                            recommendation=vuln.get('recommendation', ''),
                            header=vuln.get('header', None)
                        )
                        database.db.session.add(db_vuln)
                    
                    # Add crawled URLs
                    for url in results.get('crawled_urls', []):
                        db_url = database.CrawledUrl(
                            scan_id=db_scan.id,
                            url=url
                        )
                        database.db.session.add(db_url)
                    
                    # Add errors
                    for error in results.get('errors', []):
                        db_error = database.ScanError(
                            scan_id=db_scan.id,
                            message=error
                        )
                        database.db.session.add(db_error)
                    
                    # Commit all changes
                    database.db.session.commit()
                    session['scan_id'] = db_scan.id
                    logger.info(f"Scan results saved to database with ID: {db_scan.id}")
                    
                except Exception as db_error:
                    logger.exception("Error saving scan results to database")
                    # Don't fail the request if database save fails
            except Exception as e:
                logger.exception("Error during scan")
                session['scan_error'] = str(e)
                session['scan_in_progress'] = False
                session['scan_completed'] = False
        
        # Start the scan thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    # Render the scanning template
    return render_template(
        'scanning.html',
        target=target,
        scan_type=scan_type,
        depth=depth,
        timeout=timeout
    )

@app.route('/scan_status')
def scan_status():
    """Check the status of an ongoing scan"""
    in_progress = session.get('scan_in_progress', False)
    completed = session.get('scan_completed', False)
    error = session.get('scan_error', None)
    
    status = {
        'in_progress': in_progress,
        'completed': completed,
        'error': error,
        'report_url': url_for('view_report') if completed else None
    }
    
    return jsonify(status)

@app.route('/report')
def view_report():
    """Show the vulnerability scan report"""
    results = session.get('scan_results', None)
    target = session.get('scan_target', '')
    scan_time = session.get('scan_time', '')
    
    if not results:
        return redirect(url_for('index'))
    
    return render_template(
        'report.html', 
        results=results, 
        target=target, 
        scan_time=scan_time
    )

@app.route('/download_report')
def download_report():
    """Download the scan results as JSON"""
    results = session.get('scan_results', None)
    target = session.get('scan_target', '')
    
    if not results:
        return redirect(url_for('index'))
    
    report = {
        "target": target,
        "scan_time": session.get('scan_time', ''),
        "results": results
    }
    
    return jsonify(report)

@app.route('/history')
def scan_history():
    """Show history of previous scans"""
    # Get all scans from database, ordered by most recent first
    scans = database.Scan.query.order_by(database.Scan.started_at.desc()).all()
    
    return render_template(
        'history.html',
        scans=scans
    )

@app.route('/history/<int:scan_id>')
def view_historical_report(scan_id):
    """View a historical scan report from the database"""
    # Get the scan from database
    scan = database.Scan.query.get_or_404(scan_id)
    
    # Get vulnerabilities for this scan
    vulnerabilities = database.Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    # Get crawled URLs for this scan
    crawled_urls = database.CrawledUrl.query.filter_by(scan_id=scan_id).all()
    
    # Get errors for this scan
    errors = database.ScanError.query.filter_by(scan_id=scan_id).all()
    
    # Create a results dictionary similar to the one used in view_report
    results = {
        "target_info": scan.target.to_dict() if scan.target else {},
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "crawled_urls": [u.url for u in crawled_urls],
        "errors": [e.message for e in errors],
        "summary": {
            "vulnerability_count": scan.vulnerability_count,
            "high_severity": scan.high_severity_count,
            "medium_severity": scan.medium_severity_count,
            "low_severity": scan.low_severity_count,
            "urls_scanned": scan.urls_scanned,
            "scan_duration": scan.scan_duration
        }
    }
    
    return render_template(
        'report.html',
        results=results,
        target=scan.target.url if scan.target else "",
        scan_time=scan.started_at.strftime('%Y-%m-%d %H:%M:%S'),
        from_history=True
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
