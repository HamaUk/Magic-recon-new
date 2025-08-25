#!/bin/bash

# MagicRecon Functions
# Contains all the recon and vulnerability functions

# Load configuration
if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/configuration.cfg" ]; then
    . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/configuration.cfg"
fi

##############################################
############### UTILITY FUNCTIONS ############
##############################################

print_banner() {
    echo -e "${BOLD}${GREEN}"
    echo "##########################################################"
    echo "####                   MagicRecon                     ####"
    echo "####           Comprehensive Reconnaissance           ####"
    echo "##########################################################"
    echo -e "${NORMAL}"
}

show_help() {
    echo -e "${BOLD}${GREEN}USAGE${NORMAL}"
    echo "$0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
    echo "           	      [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h]"
    echo ""
    echo -e "${BOLD}${GREEN}TARGET OPTIONS${NORMAL}"
    echo "   -d domain.com     Target domain"
    echo "   -w domain.com     Wildcard domain"
    echo "   -l list.txt       Target list"
    echo ""
    echo -e "${BOLD}${GREEN}MODE OPTIONS${NORMAL}"
    echo "   -a, --all         All mode - Full scan with full target recognition and vulnerability scanning"
    echo "   -p, --passive     Passive reconnaissance (Footprinting) - Performs only passive recon with multiple tools"
    echo "   -x, --active      Active reconnaissance (Fingerprinting) - Performs only active recon with multiple tools"
    echo "   -r, --recon       Reconnaissance - Perform active and passive reconnaissance"
    echo "   -v, --vulnerabilities         Vulnerabilities - Check multiple vulnerabilities in the domain/list domains"
    echo "   -m, --massive     Massive recon - Massive vulnerability analysis with repetitions every X seconds"
    echo ""
    echo -e "${BOLD}${GREEN}EXTRA OPTIONS${NORMAL}"
    echo "   -n, --notify      Notify - This option is used to receive notifications via Discord, Telegram or Slack"
    echo "   -h, --help        Help - Show this help"
    echo ""
    echo -e "${BOLD}${GREEN}EXAMPLES${NORMAL}"
    echo " ${CYAN}All:${NORMAL}"
    echo " ./magicrecon.sh -d domain.com -a"
    echo ""
    echo " ${CYAN}Passive reconnaissance to a list of domains:${NORMAL}"
    echo " ./magicrecon.sh -l domainlist.txt -p"
    echo ""
    echo " ${CYAN}Active reconnaissance to a domain:${NORMAL}"
    echo " ./magicrecon.sh -d domain.com -x"
    echo ""
    echo " ${CYAN}Full reconnaissance:${NORMAL}"
    echo " ./magicrecon.sh -d domain.com -r"
    echo ""
    echo " ${CYAN}Full reconnaissance and vulnerabilities scanning:${NORMAL}"
    echo " ./magicrecon.sh -d domain.com -r -v"
    echo ""
    echo " ${CYAN}Full reconnaissance and vulnerabilities scanning to a wildcard:${NORMAL}"
    echo " ./magicrecon.sh -w domain.com"
    echo ""
    echo " ${CYAN}Massive reconnaissance and vulnerabilities scanning:${NORMAL}"
    echo " ./magicrecon.sh -w domain.com -m"
}

check_dependencies() {
    local deps=("subfinder" "amass" "httpx" "nuclei" "aquatone" "whatweb" "dirsearch" "sqlmap" "git" "python3" "curl")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing dependencies: ${missing_deps[*]}${NORMAL}"
        echo -e "${YELLOW}[!] Please run the installation script first.${NORMAL}"
        exit 1
    fi
}

send_notification() {
    local message="$1"
    if [ "$2" = true ]; then
        # Discord notification
        if [ -n "$DISCORD_WEBHOOK" ]; then
            curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"$message\"}" "$DISCORD_WEBHOOK" >/dev/null 2>&1
        fi
        
        # Telegram notification
        if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
            curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
                -d chat_id="$TELEGRAM_CHAT_ID" \
                -d text="$message" >/dev/null 2>&1
        fi
        
        # Slack notification
        if [ -n "$SLACK_WEBHOOK" ]; then
            curl -X POST -H 'Content-type: application/json' \
                --data "{\"text\":\"$message\"}" "$SLACK_WEBHOOK" >/dev/null 2>&1
        fi
    fi
}

create_directory() {
    local dir="$1"
    if [ -d "$dir" ]; then
        rm -rf "$dir"
    fi
    mkdir -p "$dir"
}

##############################################
############### PASSIVE RECON ################
##############################################

passive_recon() {
    local domain="$1"
    local notify="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$RESULTS_DIR/passive_${domain}_${timestamp}"
    
    create_directory "$output_dir"
    cd "$output_dir"
    
    echo -e "${BOLD}${GREEN}[*] STARTING PASSIVE RECONNAISSANCE${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET:${YELLOW} $domain ${NORMAL}"
    
    local ip_address=$(dig +short "$domain" | head -n 1)
    if [ -n "$ip_address" ]; then
        echo -e "${BOLD}${GREEN}[*] TARGET IP:${YELLOW} $ip_address ${NORMAL}"
    else
        echo -e "${RED}[-] Could not resolve IP address for $domain${NORMAL}"
        return 1
    fi
    
    # Check if target is alive
    echo -e "${GREEN}[+] Checking if target is alive...${NORMAL}"
    if ping -c 1 -W 1 "$domain" &> /dev/null; then
        echo -e "${GREEN}[+] $domain is alive!${NORMAL}"
    else
        echo -e "${YELLOW}[!] $domain is not responding to ping. Continuing anyway...${NORMAL}"
    fi
    
    # Whois lookup
    echo -e "${GREEN}[+] Performing WHOIS lookup...${NORMAL}"
    whois "$domain" | grep -E 'Domain|Registry|Registrar|Updated|Creation|Registrant|Name Server|DNSSEC|Status|Whois Server|Admin|Tech' | \
    grep -v 'the Data in VeriSign Global Registry' | tee whois.txt
    
    # DNS enumeration
    echo -e "${GREEN}[+] Enumerating DNS records...${NORMAL}"
    dnsenum --noreverse "$domain" | tee dns_enum.txt
    
    # Subdomain discovery
    echo -e "${GREEN}[+] Discovering subdomains...${NORMAL}"
    subfinder -d "$domain" -silent -o subfinder_subdomains.txt
    amass enum -passive -d "$domain" -o amass_subdomains.txt
    sort -u subfinder_subdomains.txt amass_subdomains.txt -o subdomains.txt
    httpx -l subdomains.txt -silent -o alive_subdomains.txt
    
    # Screenshots with Aquatone
    echo -e "${GREEN}[+] Taking screenshots of web services...${NORMAL}"
    cat alive_subdomains.txt | aquatone -screenshot-timeout "$aquatoneTimeout" -out screenshots
    
    # TheHarvester for OSINT
    if [ "$ENABLE_OSINT" = true ]; then
        echo -e "${GREEN}[+] Gathering OSINT information...${NORMAL}"
        theHarvester -d "$domain" -b all -l 500 -f theharvester.html > theharvester.txt 2>/dev/null
    fi
    
    # Send notification if enabled
    if [ "$notify" = true ]; then
        send_notification "Passive reconnaissance completed for $domain. Found $(wc -l < subdomains.txt) subdomains, $(wc -l < alive_subdomains.txt) alive."
    fi
    
    echo -e "${GREEN}[+] Passive reconnaissance completed for $domain${NORMAL}"
    cd - >/dev/null
}

##############################################
############### ACTIVE RECON #################
##############################################

active_recon() {
    local domain="$1"
    local notify="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$RESULTS_DIR/active_${domain}_${timestamp}"
    
    create_directory "$output_dir"
    cd "$output_dir"
    
    echo -e "${BOLD}${GREEN}[*] STARTING ACTIVE RECONNAISSANCE${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET:${YELLOW} $domain ${NORMAL}"
    
    # Directory and file discovery
    echo -e "${GREEN}[+] Discovering directories and files...${NORMAL}"
    dirsearch -u "https://$domain" -e php,asp,aspx,jsp,html,txt -x 404,403 -t "$threads" -o dirsearch.txt
    
    # URL extraction from JavaScript files
    echo -e "${GREEN}[+] Extracting URLs from JavaScript files...${NORMAL}"
    gau "$domain" | grep -E '\.js$' | sort -u > js_files.txt
    for js in $(cat js_files.txt); do
        curl -s "$js" | grep -Eo '(http|https)://[^"]+' | sort -u >> js_endpoints.txt
    done
    
    # Parameter discovery
    echo -e "${GREEN}[+] Discovering URL parameters...${NORMAL}"
    arjun -u "https://$domain" -oT parameters.txt
    
    # Technology fingerprinting
    echo -e "${GREEN}[+] Fingerprinting technologies...${NORMAL}"
    whatweb "https://$domain" --color=never > whatweb.txt
    
    # Nuclei scan for vulnerabilities
    if [ "$ENABLE_NUCLEI" = true ]; then
        echo -e "${GREEN}[+] Running Nuclei vulnerability scan...${NORMAL}"
        nuclei -u "https://$domain" -t "$NUCLEI_TEMPLATES_DIR" -severity low,medium,high,critical -silent -o nuclei_scan.txt
    fi
    
    # Send notification if enabled
    if [ "$notify" = true ]; then
        send_notification "Active reconnaissance completed for $domain. Found $(wc -l < dirsearch.txt) directories, $(wc -l < nuclei_scan.txt) vulnerabilities."
    fi
    
    echo -e "${GREEN}[+] Active reconnaissance completed for $domain${NORMAL}"
    cd - >/dev/null
}

##############################################
############### VULNERABILITIES ##############
##############################################

vulnerabilities() {
    local domain="$1"
    local notify="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$RESULTS_DIR/vuln_${domain}_${timestamp}"
    
    create_directory "$output_dir"
    cd "$output_dir"
    
    echo -e "${BOLD}${GREEN}[*] STARTING VULNERABILITY SCAN${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] TARGET:${YELLOW} $domain ${NORMAL}"
    
    # Subdomain takeover check
    if [ "$ENABLE_SUBDOMAIN_TAKEOVER" = true ]; then
        echo -e "${GREEN}[+] Checking for subdomain takeovers...${NORMAL}"
        subjack -d "$domain" -ssl -v -o subdomain_takeover.txt
    fi
    
    # Secret scanning in JS files
    if [ "$ENABLE_SECRETS_SCAN" = true ]; then
        echo -e "${GREEN}[+] Scanning for secrets in JavaScript files...${NORMAL}"
        gau "$domain" | grep '\.js$' | httpx -silent -status-code -mc 200 | \
        xargs -I{} bash -c "echo 'Scanning {}'; python3 $TOOLS_DIR/SecretFinder/SecretFinder.py -i {} -o cli" | tee js_secrets.txt
    fi
    
    # CORS misconfiguration testing
    if [ "$ENABLE_CORS_TESTING" = true ]; then
        echo -e "${GREEN}[+] Testing for CORS misconfigurations...${NORMAL}"
        python3 "$TOOLS_DIR/Corsy/corsy.py" -u "https://$domain" -o cors_scan.txt
    fi
    
    # SQL injection testing
    echo -e "${GREEN}[+] Testing for SQL injection vulnerabilities...${NORMAL}"
    sqlmap -u "https://$domain" --batch --random-agent --level 1 --risk 1 -o sqlmap_scan.txt
    
    # XSS testing
    echo -e "${GREEN}[+] Testing for XSS vulnerabilities...${NORMAL}"
    gau "$domain" | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe -o xss_scan.txt
    
    # Send notification if enabled
    if [ "$notify" = true ]; then
        send_notification "Vulnerability scan completed for $domain. Check results for findings."
    fi
    
    echo -e "${GREEN}[+] Vulnerability scan completed for $domain${NORMAL}"
    cd - >/dev/null
}

##############################################
############### ALL MODES ####################
##############################################

all() {
    local domain="$1"
    local notify="$2"
    
    passive_recon "$domain" "$notify"
    active_recon "$domain" "$notify"
    vulnerabilities "$domain" "$notify"
}

all_recon() {
    local domain="$1"
    local notify="$2"
    
    passive_recon "$domain" "$notify"
    active_recon "$domain" "$notify"
}

##############################################
############### MASSIVE RECON ################
##############################################

massive_recon() {
    local wildcard="$1"
    local notify="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$RESULTS_DIR/massive_${wildcard}_${timestamp}"
    
    create_directory "$output_dir"
    cd "$output_dir"
    
    echo -e "${BOLD}${GREEN}[*] STARTING MASSIVE RECONNAISSANCE${NORMAL}"
    echo -e "${BOLD}${GREEN}[*] WILDCARD:${YELLOW} *.$wildcard ${NORMAL}"
    
    # Continuous monitoring loop
    while true; do
        local current_time=$(date +%Y%m%d_%H%M%S)
        local iteration_dir="$output_dir/scan_$current_time"
        mkdir -p "$iteration_dir"
        cd "$iteration_dir"
        
        echo -e "${GREEN}[+] Starting new scan at $(date)${NORMAL}"
        
        # Subdomain discovery
        subfinder -d "$wildcard" -silent -o subdomains.txt
        amass enum -passive -d "$wildcard" -o amass_subdomains.txt
        sort -u subdomains.txt amass_subdomains.txt -o all_subdomains.txt
        
        # Filter alive subdomains
        httpx -l all_subdomains.txt -silent -o alive_subdomains.txt
        
        # Vulnerability scanning
        nuclei -l alive_subdomains.txt -t "$NUCLEI_TEMPLATES_DIR" -severity medium,high,critical -silent -o nuclei_scan.txt
        
        # Check for new findings
        if [ -f ../nuclei_scan.txt ]; then
            diff nuclei_scan.txt ../nuclei_scan.txt | grep '^>' > new_findings.txt
            if [ -s new_findings.txt ]; then
                echo -e "${RED}[!] New vulnerabilities found!${NORMAL}"
                cat new_findings.txt
                
                if [ "$notify" = true ]; then
                    send_notification "New vulnerabilities found for $wildcard: $(cat new_findings.txt | wc -l) issues"
                fi
            fi
        fi
        
        # Copy current results for next comparison
        cp nuclei_scan.txt ../
        
        echo -e "${GREEN}[+] Scan completed. Waiting $massiveTime seconds for next scan.${NORMAL}"
        sleep "$massiveTime"
    done
    
    cd - >/dev/null
}

# Export functions for use in main script
export -f passive_recon active_recon vulnerabilities all all_recon massive_recon
