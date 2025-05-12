import logging
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

logger = logging.getLogger(__name__)

def normalize_url(url):
    """Normalize a URL to ensure consistent formatting"""
    parsed = urlparse(url)
    
    # Add http scheme if missing
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)
    
    # Convert to lowercase
    url = url.lower()
    
    # Remove trailing slash
    if url.endswith('/') and parsed.path == '/':
        url = url[:-1]
    
    # Sort query parameters
    if parsed.query:
        params = parse_qs(parsed.query)
        sorted_params = {k: sorted(v) for k, v in sorted(params.items())}
        
        # Reconstruct URL with sorted parameters
        parsed = urlparse(url)
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path
        params_str = urlencode(sorted_params, doseq=True)
        fragment = parsed.fragment
        
        url = f"{scheme}://{netloc}{path}"
        if params_str:
            url += f"?{params_str}"
        if fragment:
            url += f"#{fragment}"
    
    return url

def get_domain_from_url(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc

def is_same_domain(url, domain):
    """Check if URL belongs to the same domain"""
    parsed = urlparse(url)
    url_domain = parsed.netloc
    
    # Check if it's the same domain or a subdomain
    return url_domain == domain or url_domain.endswith('.' + domain)

def get_random_user_agent():
    """Get a random user agent string"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ]
    
    import random
    return random.choice(user_agents)

def generate_report_summary(results):
    """Generate a summary of the vulnerability scan results"""
    vulnerabilities = results.get("vulnerabilities", [])
    
    # Count vulnerabilities by severity and type
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_type_counts = {}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info")
        vuln_type = vuln.get("type", "unknown")
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
    
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "severity_counts": severity_counts,
        "vulnerability_types": vuln_type_counts,
        "urls_scanned": len(results.get("crawled_urls", [])),
        "errors": len(results.get("errors", []))
    }

def calculate_risk_score(results):
    """Calculate an overall risk score based on vulnerabilities"""
    vulnerabilities = results.get("vulnerabilities", [])
    
    # Define severity weights
    weights = {
        "high": 10,
        "medium": 5,
        "low": 2,
        "info": 0
    }
    
    # Calculate weighted score
    score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info")
        score += weights.get(severity, 0)
    
    # Normalize score to 0-100 range
    max_possible_score = 100
    normalized_score = min(score, max_possible_score)
    
    # Determine risk level
    if normalized_score >= 75:
        risk_level = "Critical"
    elif normalized_score >= 50:
        risk_level = "High"
    elif normalized_score >= 25:
        risk_level = "Medium"
    elif normalized_score > 0:
        risk_level = "Low"
    else:
        risk_level = "None"
    
    return {
        "score": normalized_score,
        "level": risk_level
    }
