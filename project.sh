#!/bin/bash

# Check if a domain was provided

echo "                                                                                  A Bot by Aryan"



if [ -z "$1" ]; then
  echo "Usage: $0 <website_url>"
  exit 1
fi

URL="$1"
DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')  # Extract domain

echo "🔍 Checking website: $URL"
echo "🌐 Domain: $DOMAIN"
echo "------------------------------------------"

check_command() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Error: '$1' is not installed. Please install it and try again."
    exit 1
  fi
}

# Ensure required commands are installed
for cmd in whois curl dig jq openssl pup grep; do
  check_command "$cmd"
done

# 1️⃣ WHOIS Lookup
echo "📄 [1] WHOIS Info:"
whois "$DOMAIN" | grep -E "Registrar|Creation Date|Updated Date|Expiry Date"

# 2️⃣ SSL Certificate Check
echo "🔐 [2] SSL Certificate Expiry:"
echo | openssl s_client -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -dates

# 3️⃣ Get IP Address & DNS Info
echo "🌍 [3] Resolving IP Address..."
IP=$(dig +short "$DOMAIN" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)

if [[ -z "$IP" ]]; then
  echo "❌ Failed to resolve IP address."
  exit 1
fi

echo "✅ Resolved IP: $IP"

# 4️⃣ Blacklist Check (AbuseIPDB)
echo "🚨 [4] Checking Blacklists (AbuseIPDB)..."
ABUSE_CHECK=$(curl -s "https://api.abuseipdb.com/api/v2/check?ip=$IP" -H "Key:"Your API"" | jq .)

if [[ "$ABUSE_CHECK" == *'"abuseConfidenceScore":'* ]]; then
  ABUSE_SCORE=$(echo "$ABUSE_CHECK" | jq '.data.abuseConfidenceScore')
  echo "🔴 Abuse Confidence Score: $ABUSE_SCORE/100"
else
  echo "✅ No abuse report found."
fi

# 5️⃣ Google Safe Browsing Check
echo "🛡️ [5] Checking Google Safe Browsing..."
SAFE_BROWSING=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"client":{"clientId":"security-check","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"'"$URL"'"}]}}' \
  "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCfS-Hq6p4FI3ophtMxCUgt-rFcaoeYM0Y")

if [[ "$SAFE_BROWSING" == "{}" ]]; then
  echo "✅ Safe on Google Safe Browsing"
else
  echo "🚨 Warning: Potential threat found!"
fi

# 6️⃣ Extract Website Text for Perspective API
echo "📝 [6] Extracting Text from Website..."
TEXT_CONTENT=$(curl -s "$URL" | pup 'p text{}' | head -n 10 | tr '\n' ' ')

if [[ -z "$TEXT_CONTENT" ]]; then
  echo "⚠️ No text content found. Skipping Perspective API."
else
  echo "📖 Extracted Content: $TEXT_CONTENT"
  
  # 7️⃣ Analyze Content with Perspective API
  echo "🤖 [7] Analyzing Content for Toxicity..."
  PERSPECTIVE_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{
      "comment": {"text": "'"$TEXT_CONTENT"'"},
      "languages": ["en"],
      "requestedAttributes": {"TOXICITY": {}}
    }' \
    "Your API

  TOXICITY_SCORE=$(echo "$PERSPECTIVE_RESPONSE" | jq '.attributeScores.TOXICITY.summaryScore.value')

  if [[ -n "$TOXICITY_SCORE" ]]; then
    echo "🧪 Toxicity Score: $TOXICITY_SCORE (0 = Safe, 1 = Highly Toxic)"
    if (( $(echo "$TOXICITY_SCORE > 0.7" | bc -l) )); then
      echo "🚨 High toxicity detected in comments!"
    fi
  else
    echo "⚠️ Unable to fetch toxicity score."
  fi
fi

# 8️⃣ Measure Load Time using curl (No API)
echo "⏱️ [8] Measuring Load Time using curl..."
LOAD_TIME=$(curl -o /dev/null -s -w '%{time_total}\n' "$URL")

echo "✅ Load Time for $URL: $LOAD_TIME seconds"

# 9️⃣ HTTP Response Headers & Redirect Check
echo "📡 [9] Checking HTTP Headers & Redirects..."
RESPONSE_HEADERS=$(curl -I -s "$URL")
REDIRECT=$(echo "$RESPONSE_HEADERS" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')

if [[ -n "$REDIRECT" ]]; then
  echo "🔀 Redirects to: $REDIRECT"
else
  echo "✅ No unexpected redirects."
fi

echo "🔍 HTTP Headers:"
echo "$RESPONSE_HEADERS" | grep -E "Server|X-Powered-By|HTTP"

# 10️⃣ Keyword Check (Gambling-related terms)
echo "🎯 [10] Checking for Gambling-Related Keywords..."
KEYWORDS=("Gamble" "Casino" "Betting" "Poker" "Lottery" "Casino Games" "Gambling")
KEYWORD_FOUND=false

# Check if any of the keywords are in the extracted text content
for keyword in "${KEYWORDS[@]}"; do
  if echo "$TEXT_CONTENT" | grep -i -q "$keyword"; then
    echo "⚠️ Found keyword '$keyword' in the website content!"
    KEYWORD_FOUND=true
  fi
done

if [ "$KEYWORD_FOUND" = false ]; then
  echo "✅ No gambling-related keywords found."
fi

# 12️⃣ Malware & Phishing Check (VirusTotal - Optional)
echo "🦠 [11] Checking VirusTotal (Optional)..."
VIRUSTOTAL_RESPONSE=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/urls/$(echo -n "$URL" | base64 --wrap=0)" \
  --header "x-apikey: YOUR_VIRUSTOTAL_API_KEY")

VT_DETECTION_COUNT=$(echo "$VIRUSTOTAL_RESPONSE" | jq '.data.attributes.last_analysis_stats.malicious')

if [[ "$VT_DETECTION_COUNT" -gt 0 ]]; then
  echo "🚨 VirusTotal detected $VT_DETECTION_COUNT malicious reports!"
else
  echo "✅ No issues found on VirusTotal."
fi

# 12 Check if the website is behind a proxy
echo "🔍 [12] Checking if the website is behind a proxy..."

# Send a request and inspect headers for proxy-related fields
PROXY_HEADERS=$(curl -I -s "$URL")

# Check for common proxy headers
if echo "$PROXY_HEADERS" | grep -qi "X-Forwarded-For" || \
   echo "$PROXY_HEADERS" | grep -qi "Via" || \
   echo "$PROXY_HEADERS" | grep -qi "X-Real-IP"; then
  echo "⚠️ The website appears to be behind a proxy (detected proxy headers)."
else
  echo "✅ No proxy headers detected."
fi

# Optional: Perform DNS lookup to see if it's behind a known proxy provider
IP=$(dig +short "$DOMAIN" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
PROXY_IP_LIST="1.1.1.1 8.8.8.8"  # List of known proxy IP addresses (this can be expanded)

for proxy_ip in $PROXY_IP_LIST; do
  if [[ "$IP" == "$proxy_ip" ]]; then
    echo "⚠️ The website's IP matches a known proxy provider."
    break
  fi
done

# 13 Check if right-click is disabled
echo "🔍 [13] Checking if right-click is disabled on the website..."

# Fetch the website content using curl
HTML_CONTENT=$(curl -s "$URL")

# Check for common JavaScript patterns that disable right-click
RIGHT_CLICK_DISABLED=false

# Look for right-click disabling patterns like 'oncontextmenu' or event listeners
if echo "$HTML_CONTENT" | grep -qi 'oncontextmenu' || \
   echo "$HTML_CONTENT" | grep -qi 'contextmenu' && echo "$HTML_CONTENT" | grep -qi 'preventDefault'; then
  RIGHT_CLICK_DISABLED=true
fi

# Display result based on the found patterns
if [ "$RIGHT_CLICK_DISABLED" = true ]; then
  echo "⚠️ Right-click is likely disabled on this website (JavaScript detected)."
else
  echo "✅ Right-click is not disabled on this website."
fi

# 14 Check if the URL contains referral parameters
echo "🔍 [14] Checking if the URL contains referral parameters..."

# Extract the query string from the URL
QUERY_STRING=$(echo "$URL" | grep -o '\?[^#]*')

# List of common referral-related query parameters
REFERRAL_PARAMS="ref=|referral=|utm_source=|utm_campaign=|utm_medium=|utm_term=|utm_content="

# Check if any referral parameters are present in the query string
if echo "$QUERY_STRING" | grep -qiE "$REFERRAL_PARAMS"; then
  echo "⚠️ Referral parameters detected in the URL."
else
  echo "✅ No referral parameters detected in the URL."
fi

# 16️⃣ Check if the website has any typos
echo "🔍 [15] Checking if the website has any typos..."

# Fetch the website content using curl and strip HTML tags to get the text content
TEXT_CONTENT=$(curl -s "$URL" | lynx -stdin -dump)

# Check for typos using aspell
echo "$TEXT_CONTENT" | aspell list | tee typos.txt | wc -l | awk '{if($1>0) print "⚠️ Typos detected on the website."; else print "✅ No typos found on the website."}'

# 16 Check if the server software is outdated
echo "🔍 [16] Checking if the server software is outdated..."

# Fetch the HTTP headers of the website
SERVER_HEADER=$(curl -sI "$URL" | grep -i "Server:")

# Extract server name and version
SERVER_NAME=$(echo "$SERVER_HEADER" | cut -d ' ' -f2 | cut -d '/' -f1)
SERVER_VERSION=$(echo "$SERVER_HEADER" | cut -d ' ' -f2 | cut -d '/' -f2)

# List of known outdated versions 
OUTDATED_VERSIONS=("Apache/2.4.7" "Nginx/1.10.0")

# Check if the server is outdated
if [[ " ${OUTDATED_VERSIONS[@]} " =~ " ${SERVER_NAME}/${SERVER_VERSION} " ]]; then
  echo "⚠️ The web server ($SERVER_NAME $SERVER_VERSION) is outdated. Consider upgrading."
else
  echo "✅ The web server ($SERVER_NAME $SERVER_VERSION) is up-to-date."
fi

# 17 Check if the website has crypto-related keywords
echo "🔍 [17] Checking if the website contains crypto-related keywords..."

# Fetch the website content using curl and strip HTML tags to get the text content
TEXT_CONTENT=$(curl -s "$URL" | lynx -stdin -dump)

# Expanded list of crypto-related keywords
CRYPTO_KEYWORDS="Bitcoin|Ethereum|Crypto|Blockchain|Mining|Wallet|Token|NFT|Altcoin|DeFi|Staking|ICO|Cryptocurrency|Ledger|Smart Contracts|Web3|Decentralized|Crypto Trading|NFT Marketplace|Digital Asset|Cryptocurrency Exchange|Crypto Wallet|Peer-to-peer|Crypto Finance|DAO|Yield Farming|Blockchain Technology|Cryptography|Stablecoin|Solana|Litecoin|Ripple|Dogecoin|Chainlink|Cardano|Polkadot|Binance Coin|Avalanche|Bitcoin Cash|Ethereum 2.0|Crypto Mining Pool|Tokenized Asset|Blockchain Gaming|Crypto Staking|Metaverse|Decentralized Apps|ERC-20 Token|Layer 2 Solutions"

# Check if any crypto-related keywords are present in the text
if echo "$TEXT_CONTENT" | grep -qiE "$CRYPTO_KEYWORDS"; then
  echo "⚠️ Crypto-related keywords detected on the website."
else
  echo "✅ No crypto-related keywords detected on the website."
fi

# 18 Check if the website has social media handles
echo "🔍 [18] Checking if the website has any social media handles..."

# Fetch the website content using curl
HTML_CONTENT=$(curl -s "$URL")

# List of social media platforms and their URLs
SOCIAL_PLATFORMS="facebook|twitter|instagram|linkedin|youtube|tiktok|pinterest|reddit|discord"

# Search for the social media links in the HTML content
echo "$HTML_CONTENT" | grep -oE "https?://(www\.)?(facebook|twitter|instagram|linkedin|youtube|tiktok|pinterest|reddit|discord)\.com/[^\"]+" | sort | uniq > social_media_links.txt

# Check if any social media links were found
if [ -s social_media_links.txt ]; then
  echo "⚡ Social media handles found:"
  cat social_media_links.txt
else
  echo "✅ No social media handles detected on the website."
fi

# 19 Check for Privacy Policy or Terms of Service
echo "🔍 [19] Checking if the website has a Privacy Policy or Terms of Service..."
  PRIVACY_CHECK=$(curl -s "$URL" | grep -i "privacy policy\|terms of service\|terms and conditions")
  if [ -n "$PRIVACY_CHECK" ]; then
    echo "✅ Privacy Policy or Terms of Service found."
  else
    echo "⚠️ Privacy Policy or Terms of Service not found."
  fi

# 20 Check if the website has a Contact Us page
echo "🔍 [20] Checking if the website has a Contact Us page..."
CONTACT_CHECK=$(curl -s "$URL" | grep -i "contact us\|get in touch\|contact us")
if [ -n "$CONTACT_CHECK" ]; then
  echo "✅ Contact Us page found."
else
  echo "⚠️ Contact Us page not found."
fi

echo "🔍 [21] Checking if the website uses CAPTCHA..."
CAPTCHA_CHECK=$(curl -s "$URL" | grep -i "captcha\|recaptcha\|hcaptcha")
if [ -n "$CAPTCHA_CHECK" ]; then
  echo "✅ Website uses CAPTCHA to prevent bots."
else
  echo "⚠️ No CAPTCHA found (may indicate bot-like behavior)."
fi

# 22 Check Domain Age (new domains may be suspicious)
echo "🔍 [22] Checking domain age using Python script..."

DOMAIN_CREATION_DATE=$(python3 domain.py "$URL")


if [[ "$DOMAIN_CREATION_DATE" == *"Error"* || "$DOMAIN_CREATION_DATE" == "Could not retrieve domain creation date." ]]; then
  echo "⚠️ Could not retrieve domain age info or domain is hidden."
else
  echo "✅ Domain age: $DOMAIN_CREATION_DATE"
fi


echo "🔍 [23] Checking if the website triggers automatic batch (.bat) file downloads..."


wget --spider --server-response -O /dev/null "$URL" 2>&1 | grep -iE '\.bat' > batch_check.log

# Check if any .bat file reference is found
if [ -s batch_check.log ]; then
    echo "⚠️ Warning: The website might be automatically downloading a batch (.bat) file!"
else
    echo "✅ No automatic batch (.bat) file downloads detected."
fi

# Clean up the temporary file
rm -f batch_check.log



echo " 🔐 [24] Checking if the website is using any known VPN servers"
API_KEY="a56afb251b090e"
VPN_CHECK=$(curl -s "https://ipinfo.io/$WEBSITE_IP/json?token=?" | grep -i 'vpn')

if [ -n "$VPN_CHECK" ]; then
    echo "⚠️ Website is behind a VPN or proxy!"
else
    echo "🔴 No VPN detected."
fi


echo "------------------------------------------"
echo "✅ Website check completed! Review results above."


echo "This project is not uploaded on Git Hub and is solely made by Aryan Pareek"
echo "Reference is on Keypoints.txt"
echo "Requirements solely on requirements.txt"
