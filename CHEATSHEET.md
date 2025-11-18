# GAU Recon Suite - Quick Reference

## 🚀 Quick Start

```bash
# 1. Get subdomains
subfinder -d target.com -o subdomains.txt

# 2. Run full recon
python master_recon.py -f subdomains.txt

# 3. Check results
cat recon_output/3_js_analysis/HIGH_PRIORITY.txt
cat recon_output/2_analysis/interesting_findings.txt
```

## 📝 Common Commands

### Full Workflow (Recommended)
```bash
# Standard run
python master_recon.py -f subdomains.txt

# Fast (more threads)
python master_recon.py -f subdomains.txt --gau-threads 20 --js-threads 10

# Slow (rate limit friendly)
python master_recon.py -f subdomains.txt --gau-threads 5 --dork-delay 5
```

### Step-by-Step
```bash
# 1. GAU scanning
python gau_recon.py -f subdomains.txt -o gau_out -t 10

# 2. Analyze outputs
python gau_analyzer.py -d gau_out -o analysis

# 3. Extract JS secrets
python js_analyzer.py -f analysis/all_js_files.txt -o js_secrets

# 4. Dork empty subs
python duckdork.py -f analysis/empty_subdomains.txt -o dorks
```

### Specific Steps Only
```bash
# Just run GAU
python master_recon.py -f subs.txt --step gau

# Just analyze existing GAU outputs
python master_recon.py -f subs.txt --step analyze

# Just JS analysis
python master_recon.py -f subs.txt --step js

# Just dorking
python master_recon.py -f subs.txt --step dork
```

## 🎯 Priority Files to Check

### 1st Priority - Secrets & Keys
```bash
cat recon_output/3_js_analysis/HIGH_PRIORITY.txt
cat recon_output/3_js_analysis/categories/aws_keys.txt
cat recon_output/3_js_analysis/categories/api_keys.txt
```

### 2nd Priority - Interesting Findings
```bash
cat recon_output/2_analysis/interesting_findings.txt
cat recon_output/4_dork_results/interesting_urls.txt
```

### 3rd Priority - Manual Testing
```bash
# Find smallest GAU outputs (the forgotten ones)
ls -lSh recon_output/1_gau_outputs/*.txt | tail -20

# Empty subdomains for fuzzing
cat recon_output/2_analysis/empty_subdomains.txt
```

## 🔍 Analysis Commands

### Find specific patterns
```bash
# Search for admin panels
grep -i "admin" recon_output/2_analysis/interesting_findings.txt

# Search for API endpoints
grep -i "/api/" recon_output/2_analysis/all_api_endpoints.txt

# Find backup files
grep -E "\.(bak|backup|old|zip)$" recon_output/2_analysis/complete_analysis.json
```

### Count findings
```bash
# Total URLs found
wc -l recon_output/1_gau_outputs/*.txt

# Total JS files
wc -l recon_output/2_analysis/all_js_files.txt

# Total API endpoints
wc -l recon_output/2_analysis/all_api_endpoints.txt
```

## 🛠️ Fuzzing Empty Subdomains

### With ffuf
```bash
while read sub; do
    ffuf -u https://$sub/FUZZ \
         -w wordlist.txt \
         -mc 200,301,302,403 \
         -o ffuf_$sub.json
done < recon_output/2_analysis/empty_subdomains.txt
```

### With dirsearch
```bash
while read sub; do
    dirsearch -u https://$sub -o dirsearch_$sub.txt
done < recon_output/2_analysis/empty_subdomains.txt
```

### With gobuster
```bash
while read sub; do
    gobuster dir -u https://$sub -w wordlist.txt -o gobuster_$sub.txt
done < recon_output/2_analysis/empty_subdomains.txt
```

## 🔎 Testing Discovered URLs

### Test for secrets in JS
```bash
# Manual check
while read url; do
    curl -s "$url" | grep -E "(api[_-]key|token|secret|password)"
done < recon_output/2_analysis/all_js_files.txt
```

### Test API endpoints
```bash
# Test for auth bypass
while read endpoint; do
    curl -s -X GET "$endpoint"
    curl -s -X POST "$endpoint" -d '{}'
done < recon_output/2_analysis/all_api_endpoints.txt
```

### Test for IDOR
```bash
# Check parameters
cat recon_output/2_analysis/top_parameters.txt | grep -E "(id|user|account)"
```

## 📊 Stats & Reporting

### Generate summary
```bash
echo "=== Recon Summary ==="
echo "Total Subdomains: $(wc -l < subdomains.txt)"
echo "GAU Outputs: $(ls recon_output/1_gau_outputs/*.txt | wc -l)"
echo "Total URLs: $(cat recon_output/1_gau_outputs/*.txt | wc -l)"
echo "JS Files: $(wc -l < recon_output/2_analysis/all_js_files.txt)"
echo "API Endpoints: $(wc -l < recon_output/2_analysis/all_api_endpoints.txt)"
echo "Empty Subs: $(wc -l < recon_output/2_analysis/empty_subdomains.txt)"
```

### Check for high-value findings
```bash
# Check for secrets
[ -s recon_output/3_js_analysis/HIGH_PRIORITY.txt ] && \
    echo "⚠️  SECRETS FOUND! Check HIGH_PRIORITY.txt"

# Check for interesting paths
grep -c "interesting_paths" recon_output/2_analysis/interesting_findings.txt
```

## ⚡ Performance Tuning

### Fast (more resources)
```bash
python master_recon.py -f subs.txt --gau-threads 50 --js-threads 20
```

### Balanced (default)
```bash
python master_recon.py -f subs.txt --gau-threads 10 --js-threads 5
```

### Slow (rate limit friendly)
```bash
python master_recon.py -f subs.txt --gau-threads 3 --js-threads 2 --dork-delay 5
```

## 🐛 Troubleshooting

### GAU timeout issues
```bash
# Increase timeout in gau_recon.py line 62:
timeout=300  # 5 minutes instead of 2
```

### Memory issues
```bash
# Reduce threads
python master_recon.py -f subs.txt --gau-threads 3 --js-threads 2
```

### Rate limiting
```bash
# Increase delays
python duckdork.py -f subs.txt --delay 10
```

## 🎯 Bug Hunting Tips

1. **Start with HIGH_PRIORITY.txt** - Exposed secrets are instant P1s
2. **Test smallest GAU outputs** - Forgotten subs have forgotten bugs
3. **Check dorked URLs** - Hidden admin panels, old backups
4. **Test every API endpoint** - Look for missing authorization
5. **Check all parameters** - IDOR, SQL injection, XSS
6. **Review JS for logic flaws** - Client-side validation bypass
7. **Fuzz empty subdomains** - Hidden functionality
8. **Create authenticated account** - More attack surface

## 📚 Integration with Other Tools

### Nuclei
```bash
cat recon_output/4_dork_results/found_urls.txt | nuclei -t ~/nuclei-templates/
```

### httpx
```bash
cat subdomains.txt | httpx -o live_subdomains.txt
python gau_recon.py -f live_subdomains.txt
```

### subfinder + httpx + GAU
```bash
subfinder -d target.com | httpx | tee subs.txt
python master_recon.py -f subs.txt
```

---

**Remember: The forgotten subdomains with smallest GAU outputs often have the best bugs! 🎯**
