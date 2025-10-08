# Check Suspicious URL 🔒

A **safe CLI tool** to investigate suspicious URLs and domains.  
Designed for security enthusiasts, IT engineers, and phishing triage.

---

## Features

- Resolves domain and fetches IP
- DNS info & WHOIS lookup
- SSL certificate details
- HTTP headers and HTML preview (safe)
- Extracts all URLs and forms from the page
- VirusTotal reputation check (domain + URL)
- Geo-location & ASN lookup of host IP

---

## Requirements

- Bash 5+
- `curl`
- `jq`
- `whois`
- `dig`
- `openssl`

---

## Setup

1. Clone the repo:

```bash
git clone https://github.com/ebosnic/check_suspicious_url.git
cd check_suspicious_url```

2. Make the script executable

```chmod +x check_suspicious_url.sh```

3. Edit your VTP_API_KEY

4. Usage 

```./check_suspicious_url.sh "https://example.com/suspicious.html" ```

5. output is saved in /tmp/urlcheck_<timestamp>.log for review eg:

```less /tmp/urlcheck_20251008_123456.log```



