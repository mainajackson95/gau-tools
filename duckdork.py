#!/usr/bin/env python3
"""
DuckDuckGo Dorking Tool
Search for content on empty/dead subdomains using DuckDuckGo
"""

import requests
import time
import argparse
import json
from pathlib import Path
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
import re

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class DuckDorkTool:
    def __init__(self, subdomains_file, output_dir="dork_results", delay=2):
        self.subdomains_file = subdomains_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.delay = delay
        
        # Load subdomains
        with open(subdomains_file, 'r') as f:
            self.subdomains = [line.strip() for line in f if line.strip()]
        
        self.results = []
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║           DUCKDUCKGO DORKING TOOL v1.0                    ║
║      "Finding the forgotten through search engines"       ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def search_duckduckgo(self, query):
        """Perform DuckDuckGo search"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # DuckDuckGo HTML search
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return self.parse_duckduckgo_results(response.text)
            
        except Exception as e:
            print(f"{Colors.RED}  └─ Error: {str(e)}{Colors.END}")
        
        return []
    
    def parse_duckduckgo_results(self, html):
        """Parse DuckDuckGo HTML results"""
        results = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all result divs
            result_divs = soup.find_all('div', class_='result')
            
            for div in result_divs:
                result = {}
                
                # Get title and link
                title_link = div.find('a', class_='result__a')
                if title_link:
                    result['title'] = title_link.get_text(strip=True)
                    result['url'] = title_link.get('href', '')
                
                # Get snippet
                snippet = div.find('a', class_='result__snippet')
                if snippet:
                    result['snippet'] = snippet.get_text(strip=True)
                
                if result.get('url'):
                    results.append(result)
        
        except Exception as e:
            print(f"{Colors.RED}  └─ Parse error: {str(e)}{Colors.END}")
        
        return results
    
    def dork_subdomain(self, subdomain):
        """Perform various dork queries on a subdomain"""
        queries = [
            f"site:{subdomain}",
            f"site:{subdomain} inurl:admin",
            f"site:{subdomain} inurl:api",
            f"site:{subdomain} inurl:login",
            f"site:{subdomain} inurl:config",
            f"site:{subdomain} inurl:backup",
            f"site:{subdomain} filetype:pdf",
            f"site:{subdomain} filetype:xlsx",
            f"site:{subdomain} filetype:docx",
            f"site:{subdomain} intitle:index.of",
        ]
        
        all_results = []
        
        for query in queries:
            print(f"{Colors.CYAN}  └─ Query: {query}{Colors.END}")
            
            results = self.search_duckduckgo(query)
            
            if results:
                print(f"{Colors.GREEN}     • Found {len(results)} results{Colors.END}")
                all_results.extend(results)
            else:
                print(f"{Colors.YELLOW}     • No results{Colors.END}")
            
            # Be respectful with delays
            time.sleep(self.delay)
        
        return all_results
    
    def dork_all(self):
        """Dork all subdomains"""
        self.print_banner()
        
        total = len(self.subdomains)
        print(f"{Colors.YELLOW}[*] Dorking {total} subdomains...{Colors.END}")
        print(f"{Colors.YELLOW}[*] This will take a while (delay: {self.delay}s between queries)...{Colors.END}\n")
        
        for idx, subdomain in enumerate(self.subdomains, 1):
            print(f"\n{Colors.BOLD}[{idx}/{total}] Dorking: {subdomain}{Colors.END}")
            
            results = self.dork_subdomain(subdomain)
            
            if results:
                self.results.append({
                    'subdomain': subdomain,
                    'results': results,
                    'count': len(results)
                })
                print(f"{Colors.GREEN}  ✓ Total results: {len(results)}{Colors.END}")
            else:
                print(f"{Colors.RED}  ✗ No results found{Colors.END}")
        
        # Save and summarize
        self.save_results()
        self.print_summary()
    
    def save_results(self):
        """Save dorking results"""
        # 1. Complete JSON
        json_file = self.output_dir / 'dork_results.json'
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # 2. Human-readable report
        report_file = self.output_dir / 'dork_report.txt'
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("DUCKDUCKGO DORKING RESULTS\n")
            f.write("="*80 + "\n\n")
            
            for item in self.results:
                f.write(f"\n{'='*80}\n")
                f.write(f"SUBDOMAIN: {item['subdomain']}\n")
                f.write(f"Results Found: {item['count']}\n")
                f.write(f"{'='*80}\n\n")
                
                for result in item['results']:
                    f.write(f"Title: {result.get('title', 'N/A')}\n")
                    f.write(f"URL: {result.get('url', 'N/A')}\n")
                    f.write(f"Snippet: {result.get('snippet', 'N/A')}\n")
                    f.write(f"{'-'*80}\n")
        
        # 3. All URLs found
        urls_file = self.output_dir / 'found_urls.txt'
        all_urls = set()
        for item in self.results:
            for result in item['results']:
                if result.get('url'):
                    all_urls.add(result['url'])
        
        with open(urls_file, 'w') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")
        
        # 4. Interesting findings (admin, api, config, etc.)
        interesting_file = self.output_dir / 'interesting_urls.txt'
        interesting_patterns = ['admin', 'api', 'login', 'config', 'backup', 'index.of', 
                               'swagger', 'graphql', 'debug', 'test']
        
        with open(interesting_file, 'w') as f:
            f.write("INTERESTING URLS (admin, api, config, etc.)\n")
            f.write("="*80 + "\n\n")
            
            for url in sorted(all_urls):
                if any(pattern in url.lower() for pattern in interesting_patterns):
                    f.write(f"{url}\n")
    
    def print_summary(self):
        """Print summary"""
        total_subdomains = len(self.results)
        total_urls = sum(item['count'] for item in self.results)
        
        summary = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                  DORKING COMPLETE                         ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.GREEN}📊 Subdomains with Results: {total_subdomains}/{len(self.subdomains)}
{Colors.YELLOW}🔗 Total URLs Found: {total_urls}

{Colors.BOLD}📁 Output Files:{Colors.END}
{Colors.GREEN}   ✓ {self.output_dir}/dork_results.json
   ✓ {self.output_dir}/dork_report.txt
   ✓ {self.output_dir}/found_urls.txt
   ✓ {self.output_dir}/interesting_urls.txt
{Colors.END}
{Colors.YELLOW}🎯 Next Steps:
   1. Review interesting_urls.txt first
   2. Manually visit found_urls.txt
   3. For subdomains with no results, proceed to fuzzing
{Colors.END}
"""
        print(summary)


def main():
    parser = argparse.ArgumentParser(
        description='DuckDuckGo dorking tool for empty subdomains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python duckdork.py -f empty_subdomains.txt
  python duckdork.py -f empty_subdomains.txt -d 3 -o my_dorks
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing subdomains (one per line)')
    parser.add_argument('-o', '--output', default='dork_results', help='Output directory (default: dork_results)')
    parser.add_argument('-d', '--delay', type=int, default=2, help='Delay between queries in seconds (default: 2)')
    
    args = parser.parse_args()
    
    dorker = DuckDorkTool(args.file, args.output, args.delay)
    dorker.dork_all()


if __name__ == '__main__':
    main()
