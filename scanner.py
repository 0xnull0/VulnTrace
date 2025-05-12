import logging
import socket
import concurrent.futures
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException
import time

# Import checkers
from checkers.sqli import SQLInjectionChecker
from checkers.xss import XSSChecker
from checkers.csrf import CSRFChecker
from checkers.open_redirect import OpenRedirectChecker
from checkers.headers import HeaderSecurityChecker

# Import utilities
from utils import normalize_url, get_domain_from_url
from crawlers import WebCrawler

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target, scan_type='basic', depth=2, timeout=10, threads=5):
        """
        Initialize the vulnerability scanner
        
        Args:
            target (str): Target URL or domain
            scan_type (str): Type of scan (basic, full)
            depth (int): Crawling depth
            timeout (int): Request timeout in seconds
            threads (int): Number of threads for parallel scanning
        """
        self.target = normalize_url(target)
        self.domain = get_domain_from_url(self.target)
        self.scan_type = scan_type
        self.depth = depth
        self.timeout = timeout
        self.threads = threads
        self.results = {
            "target_info": {},
            "vulnerabilities": [],
            "crawled_urls": [],
            "errors": []
        }
        
        # Initialize checkers
        self.checkers = [
            SQLInjectionChecker(),
            XSSChecker(),
            CSRFChecker(),
            OpenRedirectChecker(),
            HeaderSecurityChecker()
        ]
        
        # Initialize crawler
        self.crawler = WebCrawler(self.domain, self.depth, self.timeout)
    
    def get_target_info(self):
        """Gather basic information about the target"""
        target_info = {
            "url": self.target,
            "domain": self.domain,
            "ip_addresses": []
        }
        
        try:
            ip_list = socket.gethostbyname_ex(self.domain)[2]
            target_info["ip_addresses"] = ip_list
        except socket.gaierror:
            logger.error(f"Could not resolve domain: {self.domain}")
            self.results["errors"].append(f"Could not resolve domain: {self.domain}")
        
        # Try to get server info
        try:
            response = requests.head(self.target, timeout=self.timeout)
            target_info["status_code"] = response.status_code
            target_info["server"] = response.headers.get("Server", "Unknown")
            target_info["headers"] = dict(response.headers)
        except RequestException as e:
            logger.error(f"Error connecting to target: {str(e)}")
            self.results["errors"].append(f"Error connecting to target: {str(e)}")
        
        self.results["target_info"] = target_info
        return target_info
    
    def scan_url(self, url):
        """Scan a single URL for vulnerabilities"""
        url_results = []
        
        for checker in self.checkers:
            try:
                findings = checker.check(url, timeout=self.timeout)
                if findings:
                    url_results.extend(findings)
            except Exception as e:
                logger.error(f"Error in {checker.__class__.__name__} for {url}: {str(e)}")
                self.results["errors"].append(f"Error in {checker.__class__.__name__} for {url}: {str(e)}")
        
        return url, url_results
    
    def run(self):
        """Run the full vulnerability scan"""
        logger.info(f"Starting vulnerability scan of {self.target}")
        start_time = time.time()
        
        # Get basic target information
        self.get_target_info()
        
        # Crawl the website to find URLs
        logger.info(f"Crawling {self.target} to depth {self.depth}")
        urls = self.crawler.crawl(self.target)
        self.results["crawled_urls"] = list(urls)
        
        logger.info(f"Found {len(urls)} URLs to scan")
        
        # Scan each URL for vulnerabilities
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    _, url_results = future.result()
                    if url_results:
                        for result in url_results:
                            self.results["vulnerabilities"].append(result)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {str(e)}")
                    self.results["errors"].append(f"Error scanning {url}: {str(e)}")
        
        # Calculate stats
        vulnerability_count = len(self.results["vulnerabilities"])
        high_severity = sum(1 for v in self.results["vulnerabilities"] if v["severity"] == "high")
        medium_severity = sum(1 for v in self.results["vulnerabilities"] if v["severity"] == "medium")
        low_severity = sum(1 for v in self.results["vulnerabilities"] if v["severity"] == "low")
        
        self.results["summary"] = {
            "vulnerability_count": vulnerability_count,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
            "urls_scanned": len(self.results["crawled_urls"]),
            "scan_duration": round(time.time() - start_time, 2)
        }
        
        logger.info(f"Scan completed. Found {vulnerability_count} vulnerabilities.")
        return self.results
