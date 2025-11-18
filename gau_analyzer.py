#!/usr/bin/env python3
"""
GAU Output Analyzer
Analyzes GAU outputs, sorts by file size, and categorizes interesting findings
"""

import os
import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import argparse
from collections import defaultdict

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class GAUAnalyzer:
    def __init__(self, gau_dir, output_dir="analysis"):
        self.gau_dir = Path(gau_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Interesting patterns to look for
        self.sensitive_patterns = {
            'api_keys': [
                r'api[_-]?key["\s:=]+([a-zA-Z0-9_\-]+)',
                r'apikey["\s:=]+([a-zA-Z0-9_\-]+)',
                r'access[_-]?token["\s:=]+([a-zA-Z0-9_\-]+)',
                r'secret[_-]?key["\s:=]+([a-zA-Z0-9_\-]+)',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key',
                r'aws[_-]?secret',
            ],
            'tokens': [
                r'bearer\s+[a-zA-Z0-9\-._~+/]+',
                r'token["\s:=]+([a-zA-Z0-9_\-\.]+)',
                r'jwt["\s:=]+([a-zA-Z0-9_\-\.]+)',
            ],
            'credentials': [
                r'password["\s:=]+([^\s"]+)',
                r'passwd["\s:=]+([^\s"]+)',
                r'pwd["\s:=]+([^\s"]+)',
                r'username["\s:=]+([^\s"]+)',
            ]
        }
        
        self.interesting_paths = [
            '/admin', '/api', '/backup', '/config', '/console', '/debug',
            '/dev', '/internal', '/private', '/test', '/staging', '/swagger',
            '/graphql', '/v1', '/v2', '/v3', '/.git', '/.env', '/phpinfo',
            '/status', '/health', '/metrics', '/actuator', '/management'
        ]
        
        self.interesting_extensions = [
            '.json', '.xml', '.yml', '.yaml', '.config', '.conf', '.ini',
            '.env', '.log', '.sql', '.db', '.bak', '.backup', '.old',
            '.zip', '.tar', '.gz', '.rar', '.7z'
        ]
        
        self.interesting_parameters = [
            'id', 'user', 'account', 'key', 'token', 'api', 'callback',
            'redirect', 'url', 'next', 'file', 'path', 'dir', 'admin',
            'debug', 'test', 'lang', 'locale', 'template', 'page'
        ]
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║              GAU OUTPUT ANALYZER v1.0                     ║
║     "Mining gold from the forgotten subdomains"           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def get_file_stats(self):
        """Get all GAU output files sorted by size (smallest first)"""
        files = []
        for file_path in self.gau_dir.glob('*.txt'):
            if file_path.name != 'scan_results.json':
                size = os.path.getsize(file_path)
                files.append({
                    'path': file_path,
                    'name': file_path.stem,
                    'size': size
                })
        
        # Sort by size (smallest first - the forgotten ones!)
        return sorted(files, key=lambda x: x['size'])
    
    def analyze_urls(self, file_path):
        """Analyze URLs from a GAU output file"""
        findings = {
            'total_urls': 0,
            'unique_paths': set(),
            'parameters': defaultdict(int),
            'extensions': defaultdict(int),
            'interesting_paths': [],
            'interesting_files': [],
            'js_files': [],
            'api_endpoints': [],
            'potential_sensitive': [],
            'status_codes': defaultdict(int)
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    findings['total_urls'] += 1
                    
                    # Parse URL
                    try:
                        parsed = urlparse(line)
                        path = parsed.path
                        
                        # Collect unique paths
                        findings['unique_paths'].add(path)
                        
                        # Check for interesting paths
                        for interesting in self.interesting_paths:
                            if interesting in path.lower():
                                findings['interesting_paths'].append(line)
                                break
                        
                        # Check file extensions
                        for ext in self.interesting_extensions:
                            if path.endswith(ext):
                                findings['interesting_files'].append(line)
                                findings['extensions'][ext] += 1
                                break
                        
                        # Collect JS files
                        if path.endswith('.js'):
                            findings['js_files'].append(line)
                        
                        # Check for API endpoints
                        if '/api/' in path.lower() or path.lower().startswith('/api'):
                            findings['api_endpoints'].append(line)
                        
                        # Parse parameters
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param in params.keys():
                                findings['parameters'][param] += 1
                                
                                # Check for interesting parameters
                                if param.lower() in self.interesting_parameters:
                                    findings['interesting_paths'].append(line)
                        
                        # Check for sensitive patterns in the URL
                        for category, patterns in self.sensitive_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    findings['potential_sensitive'].append({
                                        'url': line,
                                        'category': category,
                                        'pattern': pattern
                                    })
                                    break
                    
                    except Exception as e:
                        continue
            
            # Convert sets to lists for JSON serialization
            findings['unique_paths'] = list(findings['unique_paths'])
            findings['parameters'] = dict(findings['parameters'])
            findings['extensions'] = dict(findings['extensions'])
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error analyzing {file_path}: {e}{Colors.END}")
        
        return findings
    
    def analyze_all(self):
        """Analyze all GAU output files"""
        self.print_banner()
        
        files = self.get_file_stats()
        total_files = len(files)
        
        print(f"{Colors.YELLOW}[*] Found {total_files} GAU output files{Colors.END}")
        print(f"{Colors.YELLOW}[*] Analyzing from smallest to largest (the forgotten ones first!)...{Colors.END}\n")
        
        all_results = []
        empty_files = []
        interesting_findings = []
        
        for idx, file_info in enumerate(files, 1):
            file_path = file_info['path']
            subdomain = file_info['name']
            size = file_info['size']
            
            print(f"{Colors.CYAN}[{idx}/{total_files}] Analyzing: {subdomain} ({size} bytes){Colors.END}")
            
            if size == 0:
                empty_files.append(subdomain)
                print(f"  {Colors.YELLOW}└─ Empty file (good candidate for fuzzing/dorking){Colors.END}")
                continue
            
            # Analyze the file
            findings = self.analyze_urls(file_path)
            
            result = {
                'subdomain': subdomain,
                'file_size': size,
                'findings': findings
            }
            all_results.append(result)
            
            # Print quick summary
            print(f"  {Colors.GREEN}└─ URLs: {findings['total_urls']}, " +
                  f"Unique Paths: {len(findings['unique_paths'])}, " +
                  f"JS Files: {len(findings['js_files'])}, " +
                  f"APIs: {len(findings['api_endpoints'])}{Colors.END}")
            
            # Check for interesting findings
            if findings['interesting_paths'] or findings['potential_sensitive']:
                interesting_findings.append({
                    'subdomain': subdomain,
                    'interesting_count': len(findings['interesting_paths']),
                    'sensitive_count': len(findings['potential_sensitive'])
                })
                print(f"  {Colors.RED}└─ 🔥 INTERESTING: " +
                      f"{len(findings['interesting_paths'])} interesting paths, " +
                      f"{len(findings['potential_sensitive'])} potential sensitive data{Colors.END}")
        
        # Save comprehensive results
        self.save_results(all_results, empty_files, interesting_findings)
        
        # Print summary
        self.print_summary(all_results, empty_files, interesting_findings)
    
    def save_results(self, all_results, empty_files, interesting_findings):
        """Save analysis results to various output files"""
        
        # 1. Complete analysis JSON
        with open(self.output_dir / 'complete_analysis.json', 'w') as f:
            json.dump(all_results, f, indent=2)
        
        # 2. Empty/dead subdomains for fuzzing
        with open(self.output_dir / 'empty_subdomains.txt', 'w') as f:
            f.write('\n'.join(empty_files))
        
        # 3. Interesting findings report
        with open(self.output_dir / 'interesting_findings.txt', 'w') as f:
            f.write("="*80 + "\n")
            f.write("INTERESTING FINDINGS - PRIORITIZED TARGETS\n")
            f.write("="*80 + "\n\n")
            
            for result in all_results:
                findings = result['findings']
                subdomain = result['subdomain']
                
                if findings['interesting_paths'] or findings['potential_sensitive']:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"SUBDOMAIN: {subdomain}\n")
                    f.write(f"{'='*80}\n\n")
                    
                    if findings['potential_sensitive']:
                        f.write("🔴 POTENTIAL SENSITIVE DATA:\n")
                        f.write("-" * 80 + "\n")
                        for item in findings['potential_sensitive']:
                            f.write(f"  Category: {item['category']}\n")
                            f.write(f"  URL: {item['url']}\n\n")
                    
                    if findings['interesting_paths']:
                        f.write("\n🟡 INTERESTING PATHS:\n")
                        f.write("-" * 80 + "\n")
                        for path in findings['interesting_paths'][:20]:  # Limit to first 20
                            f.write(f"  {path}\n")
                        if len(findings['interesting_paths']) > 20:
                            f.write(f"\n  ... and {len(findings['interesting_paths']) - 20} more\n")
        
        # 4. All JS files
        with open(self.output_dir / 'all_js_files.txt', 'w') as f:
            for result in all_results:
                for js_url in result['findings']['js_files']:
                    f.write(f"{js_url}\n")
        
        # 5. All API endpoints
        with open(self.output_dir / 'all_api_endpoints.txt', 'w') as f:
            for result in all_results:
                for api_url in result['findings']['api_endpoints']:
                    f.write(f"{api_url}\n")
        
        # 6. Top parameters (sorted by frequency)
        all_params = defaultdict(int)
        for result in all_results:
            for param, count in result['findings']['parameters'].items():
                all_params[param] += count
        
        with open(self.output_dir / 'top_parameters.txt', 'w') as f:
            f.write("TOP PARAMETERS (by frequency):\n")
            f.write("="*80 + "\n\n")
            for param, count in sorted(all_params.items(), key=lambda x: x[1], reverse=True)[:50]:
                f.write(f"{param:30s} : {count:5d} occurrences\n")
    
    def print_summary(self, all_results, empty_files, interesting_findings):
        """Print analysis summary"""
        total_urls = sum(r['findings']['total_urls'] for r in all_results)
        total_js = sum(len(r['findings']['js_files']) for r in all_results)
        total_apis = sum(len(r['findings']['api_endpoints']) for r in all_results)
        
        summary = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                  ANALYSIS COMPLETE                        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.GREEN}📊 Total URLs Analyzed: {total_urls}
{Colors.BLUE}📜 Total JS Files: {total_js}
{Colors.CYAN}🔌 Total API Endpoints: {total_apis}
{Colors.RED}🔥 Subdomains with Interesting Findings: {len(interesting_findings)}
{Colors.YELLOW}⚠️  Empty Subdomains (for fuzzing): {len(empty_files)}

{Colors.BOLD}📁 Output Files:{Colors.END}
{Colors.GREEN}   ✓ {self.output_dir}/complete_analysis.json
   ✓ {self.output_dir}/interesting_findings.txt
   ✓ {self.output_dir}/all_js_files.txt
   ✓ {self.output_dir}/all_api_endpoints.txt
   ✓ {self.output_dir}/empty_subdomains.txt
   ✓ {self.output_dir}/top_parameters.txt
{Colors.END}
{Colors.YELLOW}🎯 Next Steps:
   1. Review interesting_findings.txt for quick wins
   2. Feed empty_subdomains.txt to fuzzer or DuckDuckGo
   3. Extract secrets from all_js_files.txt
   4. Test API endpoints for authz issues
{Colors.END}
"""
        print(summary)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze GAU outputs and categorize findings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gau_analyzer.py -d gau_outputs
  python gau_analyzer.py -d gau_outputs -o my_analysis
        """
    )
    
    parser.add_argument('-d', '--dir', required=True, help='Directory containing GAU output files')
    parser.add_argument('-o', '--output', default='analysis', help='Output directory (default: analysis)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dir):
        print(f"{Colors.RED}[!] Error: Directory not found: {args.dir}{Colors.END}")
        exit(1)
    
    analyzer = GAUAnalyzer(args.dir, args.output)
    analyzer.analyze_all()


if __name__ == '__main__':
    main()
