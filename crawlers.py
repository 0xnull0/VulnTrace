import logging
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# Import utilities
from utils import normalize_url, is_same_domain

logger = logging.getLogger(__name__)

class WebCrawler:
    def __init__(self, domain, max_depth=2, timeout=10):
        """
        Initialize web crawler
        
        Args:
            domain (str): Domain to crawl
            max_depth (int): Maximum crawling depth
            timeout (int): Request timeout in seconds
        """
        self.domain = domain
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.session = requests.Session()
        
        # Set a reasonable user agent
        self.session.headers.update({
            'User-Agent': 'VulnScanner/1.0 (Security Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def extract_links(self, url, html_content):
        """Extract all links from HTML content"""
        links = set()
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                absolute_link = urljoin(url, link)
                
                # Skip anchors and javascript links
                if '#' in absolute_link and absolute_link.split('#')[0] in links:
                    continue
                if absolute_link.startswith('javascript:'):
                    continue
                
                # Normalize the URL
                normalized_link = normalize_url(absolute_link)
                
                # Only add links from the same domain
                if is_same_domain(normalized_link, self.domain):
                    links.add(normalized_link)
        except Exception as e:
            logger.error(f"Error extracting links from {url}: {str(e)}")
        
        return links
    
    def extract_forms(self, url, html_content):
        """Extract all forms and their inputs from HTML content"""
        forms = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_field.get('type', '')
                    input_name = input_field.get('name', '')
                    
                    if input_name and input_type != 'submit' and input_type != 'button':
                        form_data['inputs'].append({
                            'name': input_name,
                            'type': input_type
                        })
                
                forms.append(form_data)
        except Exception as e:
            logger.error(f"Error extracting forms from {url}: {str(e)}")
        
        return forms
    
    def crawl_url(self, url, depth=0):
        """Crawl a single URL and extract links"""
        if depth > self.max_depth:
            return set()
        
        if url in self.visited_urls:
            return set()
        
        logger.debug(f"Crawling: {url} (depth: {depth})")
        self.visited_urls.add(url)
        self.urls_to_scan.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if response.status_code != 200:
                return set()
            
            # Skip non-HTML content
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return set()
            
            # Extract links from the page
            links = self.extract_links(url, response.text)
            
            # Extract forms
            forms = self.extract_forms(url, response.text)
            for form in forms:
                self.urls_to_scan.add(form['action'])
            
            # Recursively crawl new links
            new_links = set()
            if depth < self.max_depth:
                for link in links:
                    if link not in self.visited_urls:
                        new_links.update(self.crawl_url(link, depth + 1))
            
            return links.union(new_links)
        
        except RequestException as e:
            logger.warning(f"Error crawling {url}: {str(e)}")
            return set()
        except Exception as e:
            logger.error(f"Unexpected error crawling {url}: {str(e)}")
            return set()
    
    def crawl(self, start_url):
        """Start crawling from the given URL"""
        self.visited_urls = set()
        self.urls_to_scan = set()
        
        self.crawl_url(start_url)
        
        logger.info(f"Crawling completed. Found {len(self.urls_to_scan)} URLs.")
        return self.urls_to_scan
