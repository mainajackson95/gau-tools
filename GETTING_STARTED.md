# 🚀 Getting Started with GAU Recon Suite

## Installation (5 minutes)

### 1. Install GAU
```bash
# Install Go if you don't have it
# https://golang.org/doc/install

# Install GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Add to PATH (add this to your ~/.bashrc or ~/.zshrc)
export PATH=$PATH:$(go env GOPATH)/bin

# Verify installation
gau --help
```

### 2. Install Python Dependencies
```bash
# Install requirements
pip install -r requirements.txt

# Or manually:
pip install requests beautifulsoup4 urllib3
```

### 3. Make Scripts Executable
```bash
chmod +x *.py
```

## First Run (10 minutes)

### Step 1: Get Your Subdomains
```bash
# Option 1: Use Subfinder
subfinder -d target.com -o subdomains.txt

# Option 2: Use Amass
amass enum -d target.com -o subdomains.txt

# Option 3: Use any subdomain enumeration tool
# Just make sure the output is one subdomain per line
```

### Step 2: Run the Full Workflow
```bash
# Basic run
python master_recon.py -f subdomains.txt

# This will create:
# recon_output/
#   ├── 1_gau_outputs/
#   ├── 2_analysis/
#   ├── 3_js_analysis/
#   └── 4_dork_results/
```

### Step 3: Check for Quick Wins
```bash
# 1. Check for exposed secrets (PRIORITY!)
cat recon_output/3_js_analysis/HIGH_PRIORITY.txt

# 2. Check interesting findings
cat recon_output/2_analysis/interesting_findings.txt

# 3. Check dorked URLs
cat recon_output/4_dork_results/interesting_urls.txt
```

## Your First Bug Hunt

### 1. Review Automated Findings (30 minutes)
```bash
# High priority secrets
less recon_output/3_js_analysis/HIGH_PRIORITY.txt

# Look for:
# - AWS keys (instant P1 if valid)
# - API tokens (test if they work)
# - Hardcoded passwords
# - Google API keys
```

### 2. Test Interesting Paths (1 hour)
```bash
# Review interesting findings
less recon_output/2_analysis/interesting_findings.txt

# Look for:
# - /admin, /api, /debug paths
# - Backup files (.bak, .old, .zip)
# - Config files (.env, .config)
# - Directory listings
```

### 3. Manual Test Small Outputs (2 hours)
```bash
# Find the smallest GAU outputs
ls -lSh recon_output/1_gau_outputs/*.txt | tail -20

# These are the "forgotten" subdomains
# Test them manually:
# - Browse with a browser
# - Proxy through Burp
# - Look for weird behavior
# - Fuzz common paths
```

### 4. Fuzz Empty Subdomains (ongoing)
```bash
# Use ffuf
cat recon_output/2_analysis/empty_subdomains.txt | while read sub; do
    echo "Fuzzing $sub..."
    ffuf -u https://$sub/FUZZ -w wordlist.txt -mc 200,301,302,403
done
```

## Common Workflows

### Fast Initial Scan
```bash
# For quick reconnaissance
python master_recon.py -f subs.txt --gau-threads 20 --js-threads 10
```

### Deep Reconnaissance
```bash
# For thorough testing (takes longer)
python master_recon.py -f subs.txt --gau-threads 5 --dork-delay 5
```

### Re-run Specific Steps
```bash
# Just re-analyze existing GAU data
python master_recon.py -f subs.txt --step analyze

# Just re-run JS analysis
python master_recon.py -f subs.txt --step js

# Just re-run dorking
python master_recon.py -f subs.txt --step dork
```

## What to Look For

### 🔴 Critical (P1/P2)
- AWS keys in JS files → Test if valid
- API tokens → Test authorization
- Hardcoded credentials → Try to login
- S3 buckets → Check permissions
- Private keys → Immediate P1

### 🟡 High (P3/P4)
- Admin panels → Try default creds
- Debug endpoints → Check for info disclosure
- API endpoints → Test for IDOR, auth bypass
- Old backup files → Download and analyze
- Config files → Check for secrets

### 🟢 Medium/Info
- Directory listings → Map application
- Interesting paths → Potential attack surface
- Empty subdomains → Fuzz for hidden content
- Parameters → Test for injection

## Tips for Success

### 1. Patience with the "Forgotten Ones"
The smallest GAU outputs (forgotten subdomains) take time to test but often have the best bugs. Don't skip them!

### 2. Create Authenticated Accounts
If the target has user registration, create an account. The authenticated area has 10x more attack surface.

### 3. Look for Patterns
- Old versions (v1, v2 when v3 exists)
- Staging/test/dev subdomains
- Internal/admin/console subdomains
- Regional subdomains (us-east, eu-west)

### 4. Chain Tools
```bash
# Example chain
subfinder -d target.com | \
    httpx -silent | \
    tee live_subs.txt | \
    python gau_recon.py -f - | \
    python gau_analyzer.py
```

### 5. Save Everything
Always save your reconnaissance data. You'll need to refer back to it as you test.

## Troubleshooting

### "GAU not found"
```bash
# Make sure GAU is in PATH
which gau

# If not, add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

### "Permission denied" when running scripts
```bash
chmod +x *.py
```

### "No module named 'requests'"
```bash
pip install -r requirements.txt
```

### DuckDuckGo rate limiting
```bash
# Increase delay between requests
python duckdork.py -f subs.txt --delay 5
```

### Out of memory
```bash
# Reduce threads
python master_recon.py -f subs.txt --gau-threads 3 --js-threads 2
```

## Next Steps

1. **Read the full README.md** for detailed documentation
2. **Check CHEATSHEET.md** for quick command reference
3. **Start hunting!** Focus on HIGH_PRIORITY.txt first
4. **Report responsibly** through proper bug bounty channels

## Questions?

- Check README.md for detailed documentation
- Review CHEATSHEET.md for command examples
- Read the comments in the Python scripts

## Remember

> "The forgotten, weird, lonely subdomains with the smallest GAU outputs often have the nastiest bugs."

**Start with the outer rings. Test the forgotten. Find the bugs. 🎯**

---

Good luck and happy hunting! 🐛💰
