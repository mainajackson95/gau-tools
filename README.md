# GAU Reconnaissance Automation Suite

> **"Finding the forgotten, weird, lonely subdomains"**

A complete automation suite for bug bounty reconnaissance using GAU (GetAllUrls), following the methodology of starting with the smallest/forgotten subdomains first.

## 🎯 Philosophy

This toolkit follows the "outer rings first" methodology:
- Target the **smallest GAU outputs** first (the forgotten subdomains)
- These often have the nastiest bugs because they're unmaintained
- Automate the tedious parts, focus human effort on interesting findings

## 🚀 Features

### 1. **Batch GAU Runner** (`gau_recon.py`)
- Multi-threaded GAU scanning across all subdomains
- Automatic output file generation per subdomain
- Progress tracking and error handling
- Results sorted by file size (smallest first!)

### 2. **Smart Analyzer** (`gau_analyzer.py`)
- Analyzes GAU outputs sorted by file size
- Categorizes findings:
  - Interesting paths (`/admin`, `/api`, `/debug`, etc.)
  - Interesting file types (`.config`, `.backup`, `.env`, etc.)
  - API endpoints
  - JavaScript files
  - Potential sensitive data
- Identifies empty subdomains for fuzzing/dorking

### 3. **JavaScript Analyzer** (`js_analyzer.py`)
- Fetches and analyzes JS files for secrets
- Extracts:
  - API endpoints
  - AWS keys
  - API tokens
  - JWT tokens
  - Secret keys
  - Google API keys
  - Slack tokens
  - S3 buckets
  - Firebase URLs
- Prioritizes findings by severity

### 4. **DuckDuckGo Dorker** (`duckdork.py`)
- Automated dorking for empty/dead subdomains
- Multiple dork patterns (admin, api, config, etc.)
- Finds hidden content not discovered by GAU
- Respects rate limits

### 5. **Master Orchestrator** (`master_recon.py`)
- Chains entire workflow together
- Runs all tools in proper sequence
- Organized output structure
- Can run individual steps or full workflow

## 📋 Requirements

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Make sure GAU is in your PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

## 🔧 Installation

```bash
# Clone or download all scripts
git clone <your-repo> gau-recon-suite
cd gau-recon-suite

# Make scripts executable
chmod +x *.py

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Quick Start (Full Workflow)

```bash
# Run everything at once
python master_recon.py -f subdomains.txt

# Custom settings
python master_recon.py -f subdomains.txt \
  -o my_recon \
  --gau-threads 20 \
  --js-threads 10 \
  --dork-delay 3
```

### Individual Tools

#### 1. Run GAU on all subdomains
```bash
python gau_recon.py -f subdomains.txt -o gau_outputs -t 10
```

#### 2. Analyze GAU outputs
```bash
python gau_analyzer.py -d gau_outputs -o analysis
```

#### 3. Analyze JavaScript files
```bash
python js_analyzer.py -f analysis/all_js_files.txt -o js_secrets
```

#### 4. Dork empty subdomains
```bash
python duckdork.py -f analysis/empty_subdomains.txt -o dork_results
```

### Run Specific Steps Only

```bash
# Just run GAU scanning
python master_recon.py -f subdomains.txt --step gau

# Just run analysis
python master_recon.py -f subdomains.txt --step analyze

# Just run JS analysis
python master_recon.py -f subdomains.txt --step js

# Just run dorking
python master_recon.py -f subdomains.txt --step dork
```

## 📁 Output Structure

```
recon_output/
├── 1_gau_outputs/              # Raw GAU outputs
│   ├── subdomain1.txt
│   ├── subdomain2.txt
│   └── scan_results.json
├── 2_analysis/                 # Analyzed findings
│   ├── interesting_findings.txt   ← START HERE!
│   ├── complete_analysis.json
│   ├── all_js_files.txt
│   ├── all_api_endpoints.txt
│   ├── empty_subdomains.txt
│   └── top_parameters.txt
├── 3_js_analysis/              # JS secrets
│   ├── HIGH_PRIORITY.txt       ← CHECK FOR SECRETS!
│   ├── js_analysis.json
│   ├── all_endpoints.txt
│   └── categories/
│       ├── api_keys.txt
│       ├── aws_keys.txt
│       ├── tokens.txt
│       └── ...
└── 4_dork_results/             # Dorking results
    ├── interesting_urls.txt    ← HIDDEN CONTENT!
    ├── found_urls.txt
    ├── dork_results.json
    └── dork_report.txt
```

## 🎯 Recommended Testing Order

1. **`js_analysis/HIGH_PRIORITY.txt`** - Check for exposed secrets (P1 potential!)
2. **`analysis/interesting_findings.txt`** - Quick wins and interesting paths
3. **`dork_results/interesting_urls.txt`** - Hidden admin/API panels
4. **Manually test smallest GAU outputs** - The forgotten, lonely subdomains
5. **Test API endpoints** - Authorization bypass opportunities
6. **Fuzz empty subdomains** - Use ffuf/dirsearch on empty_subdomains.txt

## 💡 Methodology Tips

### Why smallest files first?
```
Think of 500 subdomains as concentric rings:
┌────────────────────────────────┐
│ Outer Ring (Smallest Files)   │  ← Start here!
│ ┌──────────────────────────┐   │
│ │ Middle Ring              │   │
│ │ ┌──────────────────┐     │   │
│ │ │ Inner Ring       │     │   │  (Most used/tested)
│ │ │ (Main sites)     │     │   │
│ │ └──────────────────┘     │   │
│ └──────────────────────────┘   │
└────────────────────────────────┘

Outer rings = Forgotten subdomains = Better bugs!
```

### The "Stupid Bugs" Phenomenon
- Sometimes GAU finds hardcoded URIs that still work
- Old API endpoints with no auth
- Debug pages left in production
- Free P1s just laying there

### Every URI Matters
- Different paths load different JS files
- Each JS file can leak different APIs
- More paths = more attack surface
- Don't skip the boring-looking stuff

### Authentication Opens Doors
Example: T-Mobile
- Worth spending $50/mo for a phone plan?
- YES! Opens 1000s of authenticated endpoints
- Authenticated area = much larger attack surface

## 🔍 Example Workflow

```bash
# 1. Get your subdomains (from Subfinder, Amass, etc.)
subfinder -d t-mobile.com -o subdomains.txt

# 2. Run the full recon suite
python master_recon.py -f subdomains.txt -o tmobile_recon

# 3. While it's running (will take hours), start manual testing:
#    - Browse to the target, create accounts
#    - Explore with Burp Suite
#    - Map out functionality

# 4. When complete, prioritize findings:
cat tmobile_recon/3_js_analysis/HIGH_PRIORITY.txt
cat tmobile_recon/2_analysis/interesting_findings.txt
cat tmobile_recon/4_dork_results/interesting_urls.txt

# 5. Test the smallest GAU outputs manually:
ls -S tmobile_recon/1_gau_outputs/*.txt | tail -20

# 6. Fuzz empty subdomains:
ffuf -u https://FUZZ.t-mobile.com/ \
     -w wordlist.txt \
     -w tmobile_recon/2_analysis/empty_subdomains.txt:FUZZ

# 7. Hunt for bugs! 🎯
```

## ⚙️ Configuration Options

### GAU Runner
```bash
-f, --file       Subdomains file (required)
-o, --output     Output directory (default: gau_outputs)
-t, --threads    Number of threads (default: 10)
-q, --quiet      Quiet mode
```

### Analyzer
```bash
-d, --dir        GAU outputs directory (required)
-o, --output     Output directory (default: analysis)
```

### JS Analyzer
```bash
-f, --file       JS URLs file (required)
-o, --output     Output directory (default: js_analysis)
-t, --threads    Number of threads (default: 5)
```

### DuckDork
```bash
-f, --file       Subdomains file (required)
-o, --output     Output directory (default: dork_results)
-d, --delay      Delay between queries (default: 2 seconds)
```

### Master Orchestrator
```bash
-f, --file           Subdomains file (required)
-o, --output         Base output directory (default: recon_output)
--gau-threads        Threads for GAU (default: 10)
--js-threads         Threads for JS analysis (default: 5)
--dork-delay         Delay for dorking (default: 2)
--step               Run specific step: gau|analyze|js|dork
```

## 🐛 Troubleshooting

### GAU not found
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

### SSL warnings in JS analyzer
These are expected and suppressed by default. The tool needs to fetch JS files from various hosts.

### DuckDuckGo rate limiting
Increase the `--dork-delay` parameter:
```bash
python duckdork.py -f subdomains.txt -d 5
```

### Out of memory
Reduce thread counts:
```bash
python master_recon.py -f subdomains.txt --gau-threads 5 --js-threads 3
```

## 🎓 Learning Resources

This toolkit automates the methodology described in various bug bounty resources:
- Start with reconnaissance
- Mine data systematically
- Prioritize forgotten/unmaintained areas
- Look for secrets in frontend code
- Use search engines for hidden content

## ⚠️ Responsible Disclosure

This toolkit is for **authorized bug bounty programs only**:
- Only test targets in authorized bug bounty programs
- Respect scope and rate limits
- Report findings responsibly
- Don't be a jerk

## 📝 License

Educational and bug bounty use only. Use responsibly.

## 🙏 Credits

Built following the methodology shared by bug bounty hunters who emphasize:
- Testing the forgotten outer rings
- Automating tedious reconnaissance
- Looking for "stupid bugs" in overlooked places
- Being thorough and systematic

---

**Happy Hunting! May you find many P1s in the forgotten subdomains! 🎯🐛💰**
# gau-tools
