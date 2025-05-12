import logging
import requests
from urllib.parse import urlparse, parse_qsl, urlencode
import re
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class XSSChecker:
    def __init__(self):
        self.name = "Cross-Site Scripting (XSS) Check"
        self.description = "Checks for potential XSS vulnerabilities"
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "' onmouseover='alert(1)'",
            "\" onmouseover=\"alert(1)\"",
            "' onfocus='alert(1)'",
            "\" onfocus=\"alert(1)\"",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<a href=\"javascript:alert(1)\">click me</a>"
        ]
    
    def check_url_params(self, url, timeout):
        """Check URL parameters for XSS vulnerabilities"""
        findings = []
        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))
        
        if not query_params:
            return findings
        
        for param_name, param_value in query_params.items():
            for payload in self.payloads:
                # Create a new query parameter dictionary with the payload
                modified_params = query_params.copy()
                modified_params[param_name] = payload
                
                # Reconstruct the URL with the modified parameter
                modified_query = urlencode(modified_params, safe="<>(){}[]'\"")
                test_url = url.replace(parsed_url.query, modified_query)
                
                try:
                    response = requests.get(test_url, timeout=timeout)
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        # Use BeautifulSoup to verify if the payload is in a context
                        # where it would be executed as JavaScript
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Look for script tags with our payload
                        script_tags = soup.find_all('script', string=re.compile(re.escape(payload)))
                        
                        # Look for HTML elements with event handlers containing our payload
                        elements_with_events = []
                        for tag in soup.find_all():
                            for attr in tag.attrs:
                                if (attr.startswith('on') and payload in tag[attr]) or \
                                   (attr == 'href' and 'javascript:' in tag[attr] and payload in tag[attr]) or \
                                   (attr == 'src' and 'javascript:' in tag[attr] and payload in tag[attr]):
                                    elements_with_events.append(tag)
                        
                        if script_tags or elements_with_events:
                            findings.append({
                                "type": "xss",
                                "subtype": "reflected",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": "XSS payload reflected in executable context",
                                "severity": "high",
                                "description": f"Reflected XSS vulnerability in parameter '{param_name}'",
                                "recommendation": "Implement proper input validation and output encoding"
                            })
                            break
                        else:
                            # If the payload is reflected but not in an executable context,
                            # it might still be an issue worth noting
                            findings.append({
                                "type": "xss",
                                "subtype": "potential_reflected",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": "XSS payload reflected in response",
                                "severity": "medium",
                                "description": f"Potential XSS vulnerability in parameter '{param_name}'",
                                "recommendation": "Implement proper input validation and output encoding"
                            })
                            break
                        
                except requests.RequestException:
                    # Skip any requests that fail
                    pass
        
        return findings
    
    def check_form(self, url, timeout):
        """Check forms on the page for XSS vulnerabilities"""
        findings = []
        
        try:
            response = requests.get(url, timeout=timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                # Get form action and method
                action = form.get('action', '')
                if not action:
                    action = url
                else:
                    action = urlparse(action).netloc and action or urljoin(url, action)
                
                method = form.get('method', 'get').lower()
                
                # Get form inputs
                inputs = {}
                for input_field in form.find_all(['input', 'textarea']):
                    name = input_field.get('name')
                    if name:
                        inputs[name] = input_field.get('value', '')
                
                # Skip if no inputs or only hidden inputs
                if not inputs:
                    continue
                
                # Test each input with XSS payloads
                for input_name in inputs:
                    for payload in self.payloads[:2]:  # Use a smaller subset for forms
                        form_data = inputs.copy()
                        form_data[input_name] = payload
                        
                        try:
                            if method == 'post':
                                response = requests.post(action, data=form_data, timeout=timeout)
                            else:
                                response = requests.get(action, params=form_data, timeout=timeout)
                            
                            if payload in response.text:
                                findings.append({
                                    "type": "xss",
                                    "subtype": "form_" + method,
                                    "url": url,
                                    "form_action": action,
                                    "parameter": input_name,
                                    "payload": payload,
                                    "evidence": "XSS payload reflected in response",
                                    "severity": "high",
                                    "description": f"Potential XSS vulnerability in form input '{input_name}'",
                                    "recommendation": "Implement proper input validation and output encoding"
                                })
                                break
                        except requests.RequestException:
                            # Skip any requests that fail
                            pass
        
        except Exception as e:
            logger.error(f"Error checking forms for XSS on {url}: {str(e)}")
        
        return findings
    
    def check(self, url, timeout=10):
        """Check for XSS vulnerabilities"""
        findings = []
        
        try:
            # Check URL parameters
            url_findings = self.check_url_params(url, timeout)
            findings.extend(url_findings)
            
            # Check forms
            form_findings = self.check_form(url, timeout)
            findings.extend(form_findings)
            
        except Exception as e:
            logger.error(f"Error in XSS check for {url}: {str(e)}")
        
        return findings
