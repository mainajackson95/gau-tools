#!/usr/bin/env python3
"""
GAU Reconnaissance Automation Suite
Automates GAU scanning, analysis, and categorization for bug bounty recon
"""

import subprocess
import os
import sys
import json
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
import argparse

class Colors:
    """Terminal colors for pretty output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class GAURunner:
    def __init__(self, subdomains_file, output_dir="gau_outputs", threads=10, verbose=True):
        self.subdomains_file = subdomains_file
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Load subdomains
        with open(subdomains_file, 'r') as f:
            self.subdomains = [line.strip() for line in f if line.strip()]
        
        self.total = len(self.subdomains)
        self.completed = 0
        self.errors = 0
        
    def print_banner(self):
        """Print a cool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║           GAU RECON AUTOMATION SUITE v1.0                 ║
║  "Finding the forgotten, weird, lonely subdomains"        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}[*] Total Subdomains: {self.total}
[*] Threads: {self.threads}
[*] Output Directory: {self.output_dir}
{Colors.END}
"""
        print(banner)
    
    def run_gau(self, subdomain):
        """Run GAU on a single subdomain"""
        # Sanitize subdomain for filename
        safe_name = subdomain.replace('/', '_').replace(':', '_')
        output_file = self.output_dir / f"{safe_name}.txt"
        
        try:
            # Run GAU command
            cmd = ['gau', subdomain]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout per subdomain
            )
            
            # Write output
            if result.stdout:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                # Get file size
                file_size = os.path.getsize(output_file)
                url_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                
                status = "SUCCESS"
                color = Colors.GREEN
            else:
                # Create empty file for tracking
                output_file.touch()
                file_size = 0
                url_count = 0
                status = "EMPTY"
                color = Colors.YELLOW
            
            with self.lock:
                self.completed += 1
                self.results.append({
                    'subdomain': subdomain,
                    'output_file': str(output_file),
                    'file_size': file_size,
                    'url_count': url_count,
                    'status': status
                })
                
                if self.verbose:
                    progress = f"[{self.completed}/{self.total}]"
                    print(f"{color}{progress} {subdomain:50s} | URLs: {url_count:5d} | Size: {file_size:8d} bytes{Colors.END}")
            
            return True
            
        except subprocess.TimeoutExpired:
            with self.lock:
                self.completed += 1
                self.errors += 1
                if self.verbose:
                    print(f"{Colors.RED}[{self.completed}/{self.total}] TIMEOUT: {subdomain}{Colors.END}")
            return False
            
        except Exception as e:
            with self.lock:
                self.completed += 1
                self.errors += 1
                if self.verbose:
                    print(f"{Colors.RED}[{self.completed}/{self.total}] ERROR: {subdomain} - {str(e)}{Colors.END}")
            return False
    
    def run_batch(self):
        """Run GAU on all subdomains with threading"""
        self.print_banner()
        print(f"{Colors.CYAN}[*] Starting batch GAU scan...{Colors.END}\n")
        
        start_time = time.time()
        
        # Run with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.run_gau, sub) for sub in self.subdomains]
            
            # Wait for completion
            for future in as_completed(futures):
                future.result()
        
        elapsed = time.time() - start_time
        
        # Print summary
        self.print_summary(elapsed)
        
        # Save results to JSON
        self.save_results()
        
    def print_summary(self, elapsed):
        """Print execution summary"""
        successful = sum(1 for r in self.results if r['status'] == 'SUCCESS')
        empty = sum(1 for r in self.results if r['status'] == 'EMPTY')
        
        summary = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                    SCAN COMPLETE                          ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.GREEN}[✓] Successful: {successful}
{Colors.YELLOW}[!] Empty Results: {empty}
{Colors.RED}[✗] Errors: {self.errors}
{Colors.CYAN}[⏱] Time Elapsed: {elapsed:.2f} seconds
{Colors.BLUE}[📁] Results saved to: {self.output_dir}/
{Colors.END}
"""
        print(summary)
    
    def save_results(self):
        """Save results to JSON file"""
        results_file = self.output_dir / 'scan_results.json'
        
        with open(results_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_subdomains': self.total,
                'completed': self.completed,
                'errors': self.errors,
                'results': sorted(self.results, key=lambda x: x['file_size'])
            }, f, indent=2)
        
        print(f"{Colors.GREEN}[✓] Results metadata saved to: {results_file}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='Batch GAU Runner for Bug Bounty Recon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gau_recon.py -f subdomains.txt
  python gau_recon.py -f subdomains.txt -o my_results -t 20
  python gau_recon.py -f subdomains.txt --quiet
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing subdomains (one per line)')
    parser.add_argument('-o', '--output', default='gau_outputs', help='Output directory (default: gau_outputs)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    # Check if GAU is installed
    try:
        subprocess.run(['gau', '--help'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.RED}[!] Error: GAU is not installed or not in PATH{Colors.END}")
        print(f"{Colors.YELLOW}[*] Install with: go install github.com/lc/gau/v2/cmd/gau@latest{Colors.END}")
        sys.exit(1)
    
    # Check if input file exists
    if not os.path.exists(args.file):
        print(f"{Colors.RED}[!] Error: File not found: {args.file}{Colors.END}")
        sys.exit(1)
    
    # Run the scanner
    runner = GAURunner(
        subdomains_file=args.file,
        output_dir=args.output,
        threads=args.threads,
        verbose=not args.quiet
    )
    
    runner.run_batch()


if __name__ == '__main__':
    main()
