import logging
import requests
import re
from urllib.parse import urlparse, parse_qsl, urlencode

logger = logging.getLogger(__name__)

class SQLInjectionChecker:
    def __init__(self):
        self.name = "SQL Injection Check"
        self.description = "Checks for potential SQL injection vulnerabilities"
        self.payloads = [
            "'",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR 1=1 --",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "1' AND '1'='1",
            "1' AND 1=1 --",
            "1' AND '1'='0",
            "1' AND 1=0 --",
            "1' UNION SELECT 1,2,3 --",
            "1' UNION SELECT null,null,null --"
        ]
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"unclosed quotation mark after the character string",
            r"SQLite3::query",
            r"ORA-[0-9]+",
            r"Microsoft SQL Server",
            r"PostgreSQL.*?ERROR",
            r"PG::SyntaxError:",
            r"Syntax error or access violation",
            r"Unclosed quotation mark",
            r"you have an error in your sql syntax"
        ]
        self.error_pattern = re.compile('|'.join(self.error_patterns), re.IGNORECASE)
    
    def check_url_params(self, url, timeout):
        """Check URL parameters for SQL injection vulnerabilities"""
        findings = []
        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))
        
        if not query_params:
            return findings
        
        original_response = None
        try:
            original_response = requests.get(url, timeout=timeout)
        except requests.RequestException:
            return findings
        
        # Test each parameter
        for param_name, param_value in query_params.items():
            for payload in self.payloads:
                # Create a new query parameter dictionary with the payload
                modified_params = query_params.copy()
                modified_params[param_name] = payload
                
                # Reconstruct the URL with the modified parameter
                modified_query = urlencode(modified_params)
                test_url = url.replace(parsed_url.query, modified_query)
                
                try:
                    response = requests.get(test_url, timeout=timeout)
                    
                    # Check for SQL error patterns in the response
                    if self.error_pattern.search(response.text):
                        findings.append({
                            "type": "sql_injection",
                            "subtype": "error_based",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": "SQL error pattern detected in response",
                            "severity": "high",
                            "description": f"Potential SQL injection vulnerability in parameter '{param_name}'",
                            "recommendation": "Implement proper input validation and parameterized queries"
                        })
                        break
                    
                    # Check for significant response differences that might indicate blind SQL injection
                    if abs(len(response.text) - len(original_response.text)) > 50:
                        findings.append({
                            "type": "sql_injection",
                            "subtype": "blind",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": "Significant response length difference",
                            "severity": "high",
                            "description": f"Potential blind SQL injection vulnerability in parameter '{param_name}'",
                            "recommendation": "Implement proper input validation and parameterized queries"
                        })
                        break
                except requests.RequestException:
                    # Connection errors might also indicate SQL injection in some cases
                    pass
        
        return findings
    
    def check_form(self, url, form_data, timeout):
        """Check form inputs for SQL injection vulnerabilities"""
        # Implementation similar to check_url_params but for form submission
        # This is a simplified version
        return []
    
    def check(self, url, timeout=10):
        """Check for SQL injection vulnerabilities"""
        findings = []
        
        try:
            # Check URL parameters
            url_findings = self.check_url_params(url, timeout)
            findings.extend(url_findings)
            
            # We could also check for forms on the page and test their inputs
            # This would require extracting forms from the page and testing each input
            # For brevity, this is not implemented in this example
            
        except Exception as e:
            logger.error(f"Error in SQL injection check for {url}: {str(e)}")
        
        return findings
