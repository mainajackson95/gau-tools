#!/usr/bin/env python3
"""
JavaScript File Analyzer
Extracts API endpoints, secrets, and interesting patterns from JS files
"""

import re
import requests
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class JSAnalyzer:
    def __init__(self, js_file, output_dir="js_analysis", threads=5):
        self.js_file = js_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.threads = threads
        
        # Load JS URLs
        with open(js_file, 'r') as f:
            self.js_urls = [line.strip() for line in f if line.strip()]
        
        # Regex patterns for interesting finds
        self.patterns = {
            'api_endpoints': [
                r'["\']/(api|v1|v2|v3|graphql|rest)[^"\']*["\']',
                r'["\']https?://[^"\']*/(api|v1|v2|v3)[^"\']*["\']',
                r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
                r'url\s*[:=]\s*["\']([^"\']+)["\']',
                r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            'aws_keys': [
                r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            ],
            'api_keys': [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'tokens': [
                r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'["\']?auth["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'["\']?bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',  # JWT
            ],
            'secrets': [
                r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
                r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            ],
            'google_api': [
                r'AIza[0-9A-Za-z_\-]{35}',
            ],
            'slack_tokens': [
                r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
            ],
            'private_keys': [
                r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            ],
            'urls': [
                r'https?://[^\s\'"<>]+',
            ],
            's3_buckets': [
                r'[a-z0-9.-]+\.s3\.amazonaws\.com',
                r's3://[a-z0-9.-]+',
                r's3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9.-]+',
            ],
            'firebase': [
                r'[a-z0-9.-]+\.firebaseio\.com',
                r'[a-z0-9.-]+\.firebaseapp\.com',
            ],
        }
        
        self.results = []
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║           JAVASCRIPT FILE ANALYZER v1.0                   ║
║        "Extracting secrets from the frontend"             ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def fetch_js(self, url):
        """Fetch JS file content"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            pass
        return None
    
    def analyze_js_content(self, url, content):
        """Analyze JS content for interesting patterns"""
        findings = {
            'url': url,
            'size': len(content),
            'matches': {}
        }
        
        for category, patterns in self.patterns.items():
            matches = set()
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if found:
                    matches.update([str(m) for m in found])
            
            if matches:
                findings['matches'][category] = list(matches)
        
        return findings
    
    def analyze_file(self, url):
        """Fetch and analyze a single JS file"""
        print(f"{Colors.CYAN}[*] Fetching: {url[:80]}...{Colors.END}")
        
        content = self.fetch_js(url)
        if not content:
            print(f"{Colors.RED}  └─ Failed to fetch{Colors.END}")
            return None
        
        findings = self.analyze_js_content(url, content)
        
        # Print interesting finds
        if findings['matches']:
            print(f"{Colors.GREEN}  └─ Found {len(findings['matches'])} categories of interesting data!{Colors.END}")
            for category, matches in findings['matches'].items():
                print(f"{Colors.YELLOW}     • {category}: {len(matches)} matches{Colors.END}")
        else:
            print(f"{Colors.YELLOW}  └─ No interesting patterns found{Colors.END}")
        
        return findings
    
    def analyze_all(self):
        """Analyze all JS files"""
        self.print_banner()
        
        total = len(self.js_urls)
        print(f"{Colors.YELLOW}[*] Analyzing {total} JavaScript files...{Colors.END}\n")
        
        # Analyze with threading
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.analyze_file, url): url for url in self.js_urls}
            
            for idx, future in enumerate(as_completed(futures), 1):
                print(f"\n{Colors.BOLD}[{idx}/{total}]{Colors.END}")
                result = future.result()
                if result:
                    self.results.append(result)
                time.sleep(0.1)  # Be nice to servers
        
        # Save and summarize
        self.save_results()
        self.print_summary()
    
    def save_results(self):
        """Save analysis results"""
        # 1. Complete JSON results
        json_file = self.output_dir / 'js_analysis.json'
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # 2. Categorized findings
        categories_dir = self.output_dir / 'categories'
        categories_dir.mkdir(exist_ok=True)
        
        # Group by category
        categorized = {}
        for result in self.results:
            for category, matches in result.get('matches', {}).items():
                if category not in categorized:
                    categorized[category] = []
                categorized[category].append({
                    'url': result['url'],
                    'matches': matches
                })
        
        # Save each category to separate file
        for category, items in categorized.items():
            cat_file = categories_dir / f'{category}.txt'
            with open(cat_file, 'w') as f:
                f.write(f"{'='*80}\n")
                f.write(f"CATEGORY: {category.upper()}\n")
                f.write(f"Total Occurrences: {sum(len(item['matches']) for item in items)}\n")
                f.write(f"{'='*80}\n\n")
                
                for item in items:
                    f.write(f"\nSource: {item['url']}\n")
                    f.write(f"{'-'*80}\n")
                    for match in item['matches']:
                        f.write(f"  {match}\n")
                    f.write("\n")
        
        # 3. High-priority findings (secrets, keys, tokens)
        priority_file = self.output_dir / 'HIGH_PRIORITY.txt'
        with open(priority_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("HIGH PRIORITY FINDINGS - CHECK THESE FIRST!\n")
            f.write("="*80 + "\n\n")
            
            priority_cats = ['aws_keys', 'api_keys', 'tokens', 'secrets', 'google_api', 
                           'slack_tokens', 'private_keys']
            
            for result in self.results:
                has_priority = False
                priority_matches = {}
                
                for category in priority_cats:
                    if category in result.get('matches', {}):
                        priority_matches[category] = result['matches'][category]
                        has_priority = True
                
                if has_priority:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"FILE: {result['url']}\n")
                    f.write(f"{'='*80}\n")
                    for category, matches in priority_matches.items():
                        f.write(f"\n🔴 {category.upper()}:\n")
                        for match in matches:
                            f.write(f"  {match}\n")
        
        # 4. All unique endpoints
        endpoints_file = self.output_dir / 'all_endpoints.txt'
        all_endpoints = set()
        for result in self.results:
            if 'api_endpoints' in result.get('matches', {}):
                all_endpoints.update(result['matches']['api_endpoints'])
        
        with open(endpoints_file, 'w') as f:
            for endpoint in sorted(all_endpoints):
                f.write(f"{endpoint}\n")
    
    def print_summary(self):
        """Print analysis summary"""
        total_files = len(self.results)
        files_with_findings = sum(1 for r in self.results if r.get('matches'))
        
        # Count by category
        category_counts = {}
        for result in self.results:
            for category in result.get('matches', {}).keys():
                category_counts[category] = category_counts.get(category, 0) + 1
        
        summary = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                  ANALYSIS COMPLETE                        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.GREEN}📊 Files Analyzed: {total_files}
{Colors.YELLOW}🔍 Files with Findings: {files_with_findings}

{Colors.BOLD}📋 Findings by Category:{Colors.END}
"""
        print(summary)
        
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{Colors.CYAN}   • {category:20s}: {count} files{Colors.END}")
        
        print(f"""
{Colors.BOLD}📁 Output Files:{Colors.END}
{Colors.GREEN}   ✓ {self.output_dir}/HIGH_PRIORITY.txt (Check this first!)
   ✓ {self.output_dir}/js_analysis.json
   ✓ {self.output_dir}/all_endpoints.txt
   ✓ {self.output_dir}/categories/ (Individual category files)
{Colors.END}
{Colors.RED}{Colors.BOLD}🚨 IMPORTANT: Review HIGH_PRIORITY.txt immediately for exposed secrets!{Colors.END}
""")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze JavaScript files for secrets and API endpoints',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_analyzer.py -f all_js_files.txt
  python js_analyzer.py -f all_js_files.txt -o js_secrets -t 10
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing JS URLs (one per line)')
    parser.add_argument('-o', '--output', default='js_analysis', help='Output directory (default: js_analysis)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    analyzer = JSAnalyzer(args.file, args.output, args.threads)
    analyzer.analyze_all()


if __name__ == '__main__':
    main()
