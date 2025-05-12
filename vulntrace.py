#!/usr/bin/env python
"""
VulnTrace - Web Vulnerability Scanner
Command-line interface for running vulnerability scans
Created by: https://github.com/0xnull0
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import scanner
import utils

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='VulnTrace - Web Vulnerability Scanner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('--url', '-u', type=str, required=True,
                        help='Target URL to scan (e.g., https://example.com)')
    
    parser.add_argument('--type', '-t', type=str, choices=['basic', 'full'], default='basic',
                        help='Type of scan to perform (basic or full)')
    
    parser.add_argument('--depth', '-d', type=int, default=2,
                        help='Maximum crawling depth (1-5)')
    
    parser.add_argument('--timeout', '-to', type=int, default=10,
                        help='Request timeout in seconds')
    
    parser.add_argument('--output', '-o', type=str, 
                        help='Output file to save results (JSON format)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed progress output')
    
    args = parser.parse_args()
    
    # Validate depth
    if args.depth < 1 or args.depth > 5:
        parser.error("Depth must be between 1 and 5")
    
    # Validate timeout
    if args.timeout < 1:
        parser.error("Timeout must be greater than 0")
    
    # Validate URL format
    if not args.url.startswith(('http://', 'https://')):
        parser.error("URL must start with http:// or https://")
    
    return args

def print_banner():
    """Print VulnTrace banner"""
    banner = """
 __     __     _     _____                    
 \ \   / /   _| |_  |_   _| __ __ _  ___ ___ 
  \ \ / / | | | | | | | || '__/ _` |/ __/ _ \\
   \ V /| |_| | | |_| | || | | (_| | (_|  __/
    \_/  \__,_|_|\__| |_||_|  \__,_|\___\___|
                                             
    Web Vulnerability Scanner v1.0.0
    Created by: https://github.com/0xnull0
    """
    print(banner)

def print_progress(message, verbose=False, end='\n'):
    """Print progress message"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if verbose or end != '\n':
        print(f"[{timestamp}] {message}", end=end)
        sys.stdout.flush()

def main():
    """Main function to run vulnerability scanner from command line"""
    print_banner()
    args = parse_args()
    
    print_progress(f"Starting scan of {args.url}", verbose=True)
    print_progress(f"Scan type: {args.type}", verbose=True)
    print_progress(f"Crawl depth: {args.depth}", verbose=True)
    print_progress(f"Timeout: {args.timeout}s", verbose=True)
    print()
    
    start_time = time.time()
    
    try:
        # Initialize scanner
        print_progress("Initializing scanner...", 
                      verbose=args.verbose, end='\r')
        
        vuln_scanner = scanner.VulnerabilityScanner(
            target=args.url,
            scan_type=args.type,
            depth=args.depth,
            timeout=args.timeout
        )
        
        # Gather target info
        print_progress("Gathering target information...", 
                      verbose=args.verbose, end='\r')
        
        # Run the scan
        print_progress("Starting vulnerability scan...", verbose=True)
        results = vuln_scanner.run()
        
        # Get summary
        summary = results.get('summary', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Print results
        print("\nScan Results:")
        print(f"URLs scanned: {summary.get('urls_scanned', 0)}")
        print(f"Scan duration: {summary.get('scan_duration', 0):.2f} seconds")
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\nVulnerabilities Summary:")
            high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
            medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
            low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
            
            print(f"  High severity: {high}")
            print(f"  Medium severity: {medium}")
            print(f"  Low severity: {low}")
            
            print("\nTop Vulnerabilities:")
            for i, vuln in enumerate(sorted(vulnerabilities, 
                                           key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x.get('severity', 'low'), 3))[:5]):
                print(f"{i+1}. [{vuln.get('severity', 'low').upper()}] {vuln.get('type')}: {vuln.get('url')}")
        
        # Save to file if specified
        if args.output:
            output_file = args.output
            if not output_file.endswith('.json'):
                output_file += '.json'
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\nResults saved to {output_file}")
        
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()