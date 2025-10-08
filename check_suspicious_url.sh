#!/usr/bin/env bash
# check_suspicious_url.sh
# Passive URL + domain investigation with VirusTotal
# Enhanced with IP, Geo, and ASN info
# Safe CLI usage — no JS execution or downloads

set -euo pipefail

###############################################
# 🔑 Hardcoded VirusTotal API key
VT_API_KEY="e6ecf368e418fb81d110b84b6e4117b3d1cc217af635eaae4bcbfc6b410aad2c"
###############################################

if [[ -z "$VT_API_KEY" ]]; then
  echo "❌ VirusTotal API key is empty. Please set it in the script."
  exit 1
fi

URL="${1:-}"
if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url>"
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "❌ jq required. Install: sudo dnf install -y jq"; exit 1; }

DOMAIN=$(echo "$URL" | awk -F/ '{print $3}')
REPORT="/tmp/urlcheck_$(date +%Y%m%d_%H%M%S).log"

echo "🔍 Checking: $URL" | tee "$REPORT"
echo "📁 Domain: $DOMAIN" | tee -a "$REPORT"
echo "🕓 Timestamp: $(date)" | tee -a "$REPORT"
echo "========================================" | tee -a "$REPORT"

# 1. DNS Info
echo -e "\n[1] DNS Info:" | tee -a "$REPORT"
IP=$(dig +short "$DOMAIN" | head -n 1)
echo "Resolved IP: $IP" | tee -a "$REPORT"

# 2. WHOIS
echo -e "\n[2] WHOIS Info (short):" | tee -a "$REPORT"
whois "$DOMAIN" 2>/dev/null | grep -E "Registrar|Creation Date|Expiry|Status|Org|Country" | tee -a "$REPORT" || echo "No WHOIS info" | tee -a "$REPORT"

# 3. SSL Certificate
echo -e "\n[3] SSL Certificate:" | tee -a "$REPORT"
echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":443 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates | tee -a "$REPORT" || echo "No cert info" | tee -a "$REPORT"

# 4. HTTP Headers
echo -e "\n[4] HTTP Headers:" | tee -a "$REPORT"
curl -I --max-time 10 --location --silent "$URL" | tee -a "$REPORT" || echo "No header data" | tee -a "$REPORT"

# 5. HTML content
echo -e "\n[5] HTML preview (first 50 lines):" | tee -a "$REPORT"
TMPHTML=$(mktemp)
curl --max-time 20 --location --fail --silent -o "$TMPHTML" "$URL" || true
head -n 50 "$TMPHTML" | tee -a "$REPORT"
HTMLSIZE=$(wc -l < "$TMPHTML")
echo "(Full HTML lines: $HTMLSIZE)" | tee -a "$REPORT"

# 6. Extract URLs & Forms
echo -e "\n[6] URLs found in HTML:" | tee -a "$REPORT"
grep -Eo 'https?://[A-Za-z0-9._%:/?=&-]+' "$TMPHTML" | sort -u | tee -a "$REPORT" || echo "None found" | tee -a "$REPORT"

echo -e "\n[7] Forms found:" | tee -a "$REPORT"
grep -i '<form' "$TMPHTML" | tee -a "$REPORT" || echo "No forms found" | tee -a "$REPORT"

# 7. IP / Geo / ASN
echo -e "\n[7] IP / Geo / ASN:" | tee -a "$REPORT"
if [[ -n "$IP" ]]; then
    curl -s "https://ipinfo.io/$IP/json" | jq '{ip, hostname, city, region, country, org}' | tee -a "$REPORT"
else
    echo "No IP resolved" | tee -a "$REPORT"
fi

# 8. VirusTotal Domain Reputation
echo -e "\n[8] VirusTotal Domain Reputation:" | tee -a "$REPORT"
VT_DOMAIN_URL="https://www.virustotal.com/api/v3/domains/$DOMAIN"
curl -s --request GET --url "$VT_DOMAIN_URL" --header "x-apikey: $VT_API_KEY" \
 | jq -r '.data.attributes.last_analysis_stats' 2>/dev/null | tee -a "$REPORT" || echo "No VT domain data" | tee -a "$REPORT"

# 9. VirusTotal URL Reputation
echo -e "\n[9] VirusTotal URL Reputation:" | tee -a "$REPORT"
ENCODED_URL=$(printf '%s' "$URL" | base64 | tr '+/' '-_' | tr -d '=')
VT_URL_URL="https://www.virustotal.com/api/v3/urls/$ENCODED_URL"
curl -s --request GET --url "$VT_URL_URL" --header "x-apikey: $VT_API_KEY" \
 | jq -r '.data.attributes.last_analysis_stats' 2>/dev/null | tee -a "$REPORT" || echo "No VT URL data" | tee -a "$REPORT"

echo -e "\n✅ Report saved: $REPORT"
echo "View with: less $REPORT"

