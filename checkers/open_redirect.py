import logging
import requests
from urllib.parse import urlparse, parse_qsl, urlencode

logger = logging.getLogger(__name__)

class OpenRedirectChecker:
    def __init__(self):
        self.name = "Open Redirect Check"
        self.description = "Checks for potential open redirect vulnerabilities"
        
        # Common redirect parameter names
        self.redirect_params = [
            'redirect', 'redirect_to', 'url', 'return', 'return_to',
            'goto', 'next', 'target', 'destination', 'redir',
            'r', 'u', 'link', 'location', 'continue', 'returnUrl'
        ]
        
        # Test payloads
        self.payloads = [
            'https://evil.com',
            'https://attacker.com',
            '//evil.com',
            '//google.com@evil.com',
            'https://evil.com/fake-login',
            'javascript:alert(document.domain)',
            'data:text/html,<script>window.location="https://evil.com"</script>'
        ]
    
    def check_url_params(self, url, timeout):
        """Check URL parameters for open redirect vulnerabilities"""
        findings = []
        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))
        
        if not query_params:
            return findings
        
        for param_name, param_value in query_params.items():
            # Check if this parameter is a common redirect parameter
            if param_name.lower() in self.redirect_params or 'redirect' in param_name.lower() or 'url' in param_name.lower():
                for payload in self.payloads[:2]:  # Use only first two payloads to reduce requests
                    # Create a new query parameter dictionary with the payload
                    modified_params = query_params.copy()
                    modified_params[param_name] = payload
                    
                    # Reconstruct the URL with the modified parameter
                    modified_query = urlencode(modified_params)
                    test_url = url.replace(parsed_url.query, modified_query)
                    
                    try:
                        # Use allow_redirects=False to see if the server returns a redirect response
                        response = requests.get(test_url, timeout=timeout, allow_redirects=False)
                        
                        # Check if response code indicates a redirect
                        if 300 <= response.status_code < 400:
                            redirect_url = response.headers.get('Location', '')
                            
                            # Check if the redirect URL contains our payload
                            if payload in redirect_url:
                                findings.append({
                                    "type": "open_redirect",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": f"Redirects to: {redirect_url}",
                                    "severity": "medium",
                                    "description": f"Open redirect vulnerability in parameter '{param_name}'",
                                    "recommendation": "Implement a whitelist of allowed redirect URLs or use relative paths"
                                })
                                break
                    except requests.RequestException:
                        # Skip any requests that fail
                        pass
        
        return findings
    
    def check(self, url, timeout=10):
        """Check for open redirect vulnerabilities"""
        findings = []
        
        try:
            # Check URL parameters
            url_findings = self.check_url_params(url, timeout)
            findings.extend(url_findings)
            
        except Exception as e:
            logger.error(f"Error in open redirect check for {url}: {str(e)}")
        
        return findings
