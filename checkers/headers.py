import logging
import requests

logger = logging.getLogger(__name__)

class HeaderSecurityChecker:
    def __init__(self):
        self.name = "Header Security Check"
        self.description = "Checks for security-related HTTP response headers"
        
        # Define security headers and their recommended values
        self.security_headers = {
            'X-Frame-Options': {
                'recommended': ['DENY', 'SAMEORIGIN'],
                'severity': 'medium',
                'description': 'Protects against clickjacking attacks'
            },
            'X-XSS-Protection': {
                'recommended': ['1', '1; mode=block'],
                'severity': 'low',
                'description': 'Enables browser XSS protection mechanisms'
            },
            'X-Content-Type-Options': {
                'recommended': ['nosniff'],
                'severity': 'low',
                'description': 'Prevents MIME type sniffing'
            },
            'Content-Security-Policy': {
                'recommended': None,  # Any value is better than nothing
                'severity': 'medium',
                'description': 'Helps prevent XSS, clickjacking, and other code injection attacks'
            },
            'Strict-Transport-Security': {
                'recommended': None,  # Any value is better than nothing
                'severity': 'medium',
                'description': 'Enforces HTTPS connections'
            },
            'Referrer-Policy': {
                'recommended': ['no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'],
                'severity': 'low',
                'description': 'Controls what information is sent in the Referer header'
            },
            'Permissions-Policy': {
                'recommended': None,  # Any value is better than nothing
                'severity': 'low',
                'description': 'Controls which browser features can be used'
            },
            'Access-Control-Allow-Origin': {
                'recommended': None,  # Special check for this
                'severity': 'medium',
                'description': 'Restricts cross-origin resource sharing'
            },
            'Cache-Control': {
                'recommended': None,  # Multiple valid configurations
                'severity': 'low',
                'description': 'Controls how content is cached'
            }
        }
    
    def check_header_security(self, url, headers):
        """Check security headers in HTTP response"""
        findings = []
        
        for header, config in self.security_headers.items():
            header_value = headers.get(header)
            
            # Special check for Access-Control-Allow-Origin
            if header == 'Access-Control-Allow-Origin' and header_value == '*':
                findings.append({
                    "type": "insecure_header",
                    "header": header,
                    "value": header_value,
                    "expected": "Not '*'",
                    "url": url,
                    "severity": config['severity'],
                    "description": f"Insecure {header}: {config['description']}",
                    "recommendation": "Restrict CORS to specific domains instead of using wildcard '*'"
                })
            # Check if header is missing
            elif not header_value:
                findings.append({
                    "type": "missing_header",
                    "header": header,
                    "url": url,
                    "severity": config['severity'],
                    "description": f"Missing {header}: {config['description']}",
                    "recommendation": f"Add the {header} header with appropriate values"
                })
            # Check if header value is not recommended (if we have recommendations)
            elif config['recommended'] and header_value not in config['recommended']:
                findings.append({
                    "type": "insecure_header",
                    "header": header,
                    "value": header_value,
                    "expected": str(config['recommended']),
                    "url": url,
                    "severity": config['severity'],
                    "description": f"Insecure {header}: {config['description']}",
                    "recommendation": f"Set {header} to one of the recommended values: {config['recommended']}"
                })
        
        # Check for cookies without secure flag
        cookies = requests.utils.dict_from_cookiejar(requests.get(url).cookies)
        for cookie_name, cookie_value in cookies.items():
            # This is a simple check; in a real implementation, you'd need to parse the Set-Cookie header
            if 'secure' not in str(cookie_value).lower() and url.startswith('https'):
                findings.append({
                    "type": "insecure_cookie",
                    "cookie": cookie_name,
                    "url": url,
                    "severity": "medium",
                    "description": "Cookie missing Secure flag",
                    "recommendation": "Set the Secure flag on all cookies used with HTTPS"
                })
            
            if 'httponly' not in str(cookie_value).lower():
                findings.append({
                    "type": "insecure_cookie",
                    "cookie": cookie_name,
                    "url": url,
                    "severity": "medium",
                    "description": "Cookie missing HttpOnly flag",
                    "recommendation": "Set the HttpOnly flag to prevent client-side script access to cookies"
                })
        
        return findings
    
    def check(self, url, timeout=10):
        """Check for header security issues"""
        findings = []
        
        try:
            response = requests.get(url, timeout=timeout)
            header_findings = self.check_header_security(url, response.headers)
            findings.extend(header_findings)
            
        except Exception as e:
            logger.error(f"Error in header security check for {url}: {str(e)}")
        
        return findings
