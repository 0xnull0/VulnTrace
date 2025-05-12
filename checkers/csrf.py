import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class CSRFChecker:
    def __init__(self):
        self.name = "Cross-Site Request Forgery (CSRF) Check"
        self.description = "Checks for potential CSRF vulnerabilities"
        
        # Common CSRF token parameter names
        self.csrf_token_names = [
            'csrf', 'csrftoken', 'xsrftoken', '_csrf',
            'csrf_token', 'xsrf_token', '_token',
            'token', 'authenticity_token', '__RequestVerificationToken'
        ]
    
    def extract_forms(self, url, html_content):
        """Extract forms from HTML content"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Fix relative URLs in action
            if form_data['action'] and not form_data['action'].startswith(('http://', 'https://', '#')):
                form_data['action'] = urljoin(url, form_data['action'])
                
            # Extract all input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                name = input_field.get('name')
                if name:
                    form_data['inputs'].append({
                        'name': name,
                        'type': input_field.get('type', ''),
                        'value': input_field.get('value', '')
                    })
            
            forms.append(form_data)
        
        return forms
    
    def check_csrf_protection(self, form):
        """Check if a form has CSRF protection"""
        # Check if any input field has a name that suggests it's a CSRF token
        for input_field in form['inputs']:
            field_name = input_field['name'].lower()
            for token_name in self.csrf_token_names:
                if token_name in field_name:
                    return True
        
        # No CSRF token found
        return False
    
    def check(self, url, timeout=10):
        """Check for CSRF vulnerabilities"""
        findings = []
        
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code != 200:
                return findings
            
            # Extract all forms
            forms = self.extract_forms(url, response.text)
            
            # Check each form for CSRF protection
            for form in forms:
                # Only care about POST forms, as GET forms are not typically affected by CSRF
                if form['method'] != 'post':
                    continue
                
                # Verify if the form has CSRF protection
                if not self.check_csrf_protection(form):
                    # Look for forms that seem to perform sensitive actions
                    sensitive_actions = False
                    action_keywords = ['login', 'register', 'password', 'email', 'account', 'profile', 'update', 'edit', 'delete', 'remove', 'add']
                    
                    action_url = form['action'].lower()
                    for keyword in action_keywords:
                        if keyword in action_url:
                            sensitive_actions = True
                            break
                    
                    for input_field in form['inputs']:
                        field_name = input_field['name'].lower()
                        for keyword in action_keywords:
                            if keyword in field_name:
                                sensitive_actions = True
                                break
                    
                    # Determine severity based on whether the form appears to perform sensitive actions
                    severity = "high" if sensitive_actions else "medium"
                    
                    findings.append({
                        "type": "csrf",
                        "url": url,
                        "form_action": form['action'],
                        "evidence": "POST form without CSRF protection",
                        "severity": severity,
                        "description": "Form potentially vulnerable to Cross-Site Request Forgery (CSRF)",
                        "recommendation": "Implement CSRF tokens in all forms, especially those that change state"
                    })
        
        except Exception as e:
            logger.error(f"Error in CSRF check for {url}: {str(e)}")
        
        return findings
