#!/usr/bin/env python3
"""
Master Recon Orchestrator
Chains together the entire GAU-based reconnaissance workflow
"""

import subprocess
import argparse
import time
from pathlib import Path
import sys

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class ReconOrchestrator:
    def __init__(self, subdomains_file, base_dir="recon_output"):
        self.subdomains_file = subdomains_file
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        
        # Define directory structure
        self.dirs = {
            'gau': self.base_dir / '1_gau_outputs',
            'analysis': self.base_dir / '2_analysis',
            'js_analysis': self.base_dir / '3_js_analysis',
            'dork': self.base_dir / '4_dork_results',
        }
        
        # Create all directories
        for dir_path in self.dirs.values():
            dir_path.mkdir(exist_ok=True)
    
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║         MASTER RECON ORCHESTRATOR v1.0                    ║
║    "Automating the entire bug bounty recon workflow"      ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}

{Colors.YELLOW}This will run the complete recon workflow:
  1. Batch GAU scanning on all subdomains
  2. Analyze GAU outputs (sort by size, categorize)
  3. Extract secrets from JavaScript files
  4. DuckDuckGo dork empty subdomains
{Colors.END}

{Colors.RED}Warning: This can take several hours depending on subdomain count!{Colors.END}
"""
        print(banner)
    
    def run_command(self, cmd, step_name):
        """Run a command and handle errors"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}")
        print(f"STEP: {step_name}")
        print(f"{'='*80}{Colors.END}\n")
        
        try:
            result = subprocess.run(
                cmd,
                check=True,
                text=True
            )
            print(f"\n{Colors.GREEN}✓ {step_name} completed successfully!{Colors.END}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n{Colors.RED}✗ {step_name} failed with error code {e.returncode}{Colors.END}")
            return False
        except Exception as e:
            print(f"\n{Colors.RED}✗ {step_name} failed: {str(e)}{Colors.END}")
            return False
    
    def step_1_gau_scan(self, threads=10):
        """Step 1: Run GAU on all subdomains"""
        cmd = [
            'python3', 'gau_recon.py',
            '-f', self.subdomains_file,
            '-o', str(self.dirs['gau']),
            '-t', str(threads)
        ]
        return self.run_command(cmd, "1. GAU Batch Scanning")
    
    def step_2_analyze(self):
        """Step 2: Analyze GAU outputs"""
        cmd = [
            'python3', 'gau_analyzer.py',
            '-d', str(self.dirs['gau']),
            '-o', str(self.dirs['analysis'])
        ]
        return self.run_command(cmd, "2. GAU Output Analysis")
    
    def step_3_js_analysis(self, threads=5):
        """Step 3: Analyze JavaScript files"""
        js_file = self.dirs['analysis'] / 'all_js_files.txt'
        
        if not js_file.exists() or js_file.stat().st_size == 0:
            print(f"\n{Colors.YELLOW}⚠ No JavaScript files found, skipping JS analysis{Colors.END}")
            return True
        
        cmd = [
            'python3', 'js_analyzer.py',
            '-f', str(js_file),
            '-o', str(self.dirs['js_analysis']),
            '-t', str(threads)
        ]
        return self.run_command(cmd, "3. JavaScript File Analysis")
    
    def step_4_dork_empty(self, delay=2):
        """Step 4: DuckDuckGo dork empty subdomains"""
        empty_file = self.dirs['analysis'] / 'empty_subdomains.txt'
        
        if not empty_file.exists() or empty_file.stat().st_size == 0:
            print(f"\n{Colors.YELLOW}⚠ No empty subdomains found, skipping dorking{Colors.END}")
            return True
        
        cmd = [
            'python3', 'duckdork.py',
            '-f', str(empty_file),
            '-o', str(self.dirs['dork']),
            '-d', str(delay)
        ]
        return self.run_command(cmd, "4. DuckDuckGo Dorking")
    
    def print_final_summary(self):
        """Print final summary with all output locations"""
        summary = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║           RECONNAISSANCE WORKFLOW COMPLETE                ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}

{Colors.BOLD}📁 All Output Locations:{Colors.END}

{Colors.GREEN}1. GAU Outputs:{Colors.END}
   {self.dirs['gau']}/

{Colors.GREEN}2. Analysis Results:{Colors.END}
   {self.dirs['analysis']}/interesting_findings.txt   {Colors.RED}← START HERE!{Colors.END}
   {self.dirs['analysis']}/complete_analysis.json
   {self.dirs['analysis']}/all_js_files.txt
   {self.dirs['analysis']}/all_api_endpoints.txt
   {self.dirs['analysis']}/empty_subdomains.txt

{Colors.GREEN}3. JavaScript Analysis:{Colors.END}
   {self.dirs['js_analysis']}/HIGH_PRIORITY.txt   {Colors.RED}← CHECK FOR SECRETS!{Colors.END}
   {self.dirs['js_analysis']}/categories/
   {self.dirs['js_analysis']}/all_endpoints.txt

{Colors.GREEN}4. Dorking Results:{Colors.END}
   {self.dirs['dork']}/interesting_urls.txt   {Colors.RED}← HIDDEN CONTENT!{Colors.END}
   {self.dirs['dork']}/found_urls.txt
   {self.dirs['dork']}/dork_report.txt

{Colors.YELLOW}{Colors.BOLD}🎯 Recommended Testing Order:{Colors.END}
   {Colors.CYAN}1. {self.dirs['js_analysis']}/HIGH_PRIORITY.txt{Colors.END} - Check for exposed secrets
   {Colors.CYAN}2. {self.dirs['analysis']}/interesting_findings.txt{Colors.END} - Quick wins
   {Colors.CYAN}3. {self.dirs['dork']}/interesting_urls.txt{Colors.END} - Hidden admin/api panels
   {Colors.CYAN}4. Manually test the smallest GAU outputs{Colors.END} - Forgotten subdomains
   {Colors.CYAN}5. Test API endpoints for authz issues{Colors.END}
   {Colors.CYAN}6. Fuzz empty subdomains with your wordlist{Colors.END}

{Colors.GREEN}Happy Hunting! 🎯🐛{Colors.END}
"""
        print(summary)
    
    def run_full_workflow(self, gau_threads=10, js_threads=5, dork_delay=2):
        """Run the complete workflow"""
        self.print_banner()
        
        start_time = time.time()
        
        # Step 1: GAU Scanning
        if not self.step_1_gau_scan(gau_threads):
            print(f"{Colors.RED}Workflow aborted due to GAU scan failure{Colors.END}")
            return False
        
        # Step 2: Analyze GAU outputs
        if not self.step_2_analyze():
            print(f"{Colors.RED}Workflow aborted due to analysis failure{Colors.END}")
            return False
        
        # Step 3: JS Analysis
        self.step_3_js_analysis(js_threads)
        
        # Step 4: Dork empty subdomains
        self.step_4_dork_empty(dork_delay)
        
        elapsed = time.time() - start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Full workflow completed in {hours}h {minutes}m{Colors.END}")
        
        # Print final summary
        self.print_final_summary()
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Master Recon Orchestrator - Complete Bug Bounty Workflow',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full workflow with defaults
  python master_recon.py -f subdomains.txt

  # Custom settings
  python master_recon.py -f subdomains.txt -o my_recon --gau-threads 20 --js-threads 10

  # Run individual steps
  python master_recon.py -f subdomains.txt --step gau
  python master_recon.py -f subdomains.txt --step analyze
  python master_recon.py -f subdomains.txt --step js
  python master_recon.py -f subdomains.txt --step dork
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing subdomains (one per line)')
    parser.add_argument('-o', '--output', default='recon_output', help='Base output directory (default: recon_output)')
    parser.add_argument('--gau-threads', type=int, default=10, help='Threads for GAU scanning (default: 10)')
    parser.add_argument('--js-threads', type=int, default=5, help='Threads for JS analysis (default: 5)')
    parser.add_argument('--dork-delay', type=int, default=2, help='Delay between dork queries (default: 2)')
    parser.add_argument('--step', choices=['gau', 'analyze', 'js', 'dork'], help='Run only specific step')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not Path(args.file).exists():
        print(f"{Colors.RED}[!] Error: File not found: {args.file}{Colors.END}")
        sys.exit(1)
    
    orchestrator = ReconOrchestrator(args.file, args.output)
    
    # Run specific step or full workflow
    if args.step:
        if args.step == 'gau':
            orchestrator.step_1_gau_scan(args.gau_threads)
        elif args.step == 'analyze':
            orchestrator.step_2_analyze()
        elif args.step == 'js':
            orchestrator.step_3_js_analysis(args.js_threads)
        elif args.step == 'dork':
            orchestrator.step_4_dork_empty(args.dork_delay)
    else:
        orchestrator.run_full_workflow(args.gau_threads, args.js_threads, args.dork_delay)


if __name__ == '__main__':
    main()
