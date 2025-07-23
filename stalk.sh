#!/bin/bash

## this is a script to enumerate a target

# Initialize arrays for web pages
declare -a accessible_pages
declare -a forbidden_pages
declare -a redirect_pages
declare -a misc_pages
declare -a smb_shares
smb_vulnerable=false
ftp_anon_vulnerable=false

# Function to remove duplicates from arrays and consolidate similar URLs
deduplicate_array() {
    local -n arr=$1
    local -a unique=()
    local -A seen=()
    
    for item in "${arr[@]}"; do
        # Normalize URL by removing common file extensions
        normalized_item="$item"
        normalized_item="${normalized_item%.html}"
        normalized_item="${normalized_item%.htm}"
        normalized_item="${normalized_item%.php}"
        normalized_item="${normalized_item%.asp}"
        normalized_item="${normalized_item%.aspx}"
        normalized_item="${normalized_item%.jsp}"
        normalized_item="${normalized_item%.js}"
        normalized_item="${normalized_item%.css}"
        normalized_item="${normalized_item%.xml}"
        normalized_item="${normalized_item%.json}"
        normalized_item="${normalized_item%.txt}"
        normalized_item="${normalized_item%.pdf}"
        normalized_item="${normalized_item%.doc}"
        normalized_item="${normalized_item%.docx}"
        normalized_item="${normalized_item%.xls}"
        normalized_item="${normalized_item%.xlsx}"
        normalized_item="${normalized_item%.ppt}"
        normalized_item="${normalized_item%.pptx}"
        normalized_item="${normalized_item%.zip}"
        normalized_item="${normalized_item%.tar}"
        normalized_item="${normalized_item%.gz}"
        normalized_item="${normalized_item%.rar}"
        
        if [[ ! -v seen["$normalized_item"] ]]; then
            seen["$normalized_item"]=1
            unique+=("$item")
        fi
    done
    
    arr=("${unique[@]}")
}

update_status() {
    local status=$1
    local message=$2
    echo "{\"status\":\"$status\",\"message\":\"$message\",\"target\":\"$rhost\"}" > output/status.json
}

# RHOST environment variable setup
if [ -n "$RHOST" ]; then
    echo "[+] RHOST is currently set to $RHOST."
    read -p "[?] Do you want to change it? (y/N): " change_rhost
    if [[ "$change_rhost" =~ ^[Yy]$ ]]; then
        read -p "[?] Enter new RHOST value: " new_rhost
        export RHOST="$new_rhost"
        echo "[+] RHOST updated to $RHOST."
    else
        echo "[+] Continuing with RHOST=$RHOST."
    fi
else
    read -p "[?] RHOST is not set. Enter RHOST value: " RHOST
    export RHOST
    echo "[+] RHOST set to $RHOST."
fi

# Set rhost variable for use in script
rhost="$RHOST"

# Set initial status
update_status "scanning" "Initializing enumeration script..."

# Ensure output directory exists
mkdir -p output

# Reset HTML page to default state
cat > output/enumeration_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Enigma-3NMA cheat codes - $rhost</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #1a1a1a; color: #e0e0e0; }
        .container { max-width: 1200px; margin: 0 auto; background: #2d2d2d; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        h1 { color: #ffffff; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #007acc; margin-top: 30px; }
        h3 { color: #cccccc; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; background-color: #3a3a3a; }
        .port { display: inline-block; margin: 5px; padding: 5px 10px; background-color: #1e3a5f; border-radius: 4px; color: #ffffff; }
        .vuln { color: #ff6b6b; font-weight: bold; }
        .web-page { margin: 5px 0; padding: 5px; background-color: #2d4a2d; border-radius: 4px; }
        .web-page a { color: #4caf50; text-decoration: none; }
        .web-page a:hover { color: #66bb6a; text-decoration: underline; }
        .forbidden { background-color: #4a3a2d; }
        .forbidden a { color: #ff9800; }
        .forbidden a:hover { color: #ffb74d; }
        .misc { background-color: #3a2d4a; }
        .misc a { color: #9c27b0; }
        .misc a:hover { color: #ba68c8; }
        .timestamp { color: #888888; font-size: 0.9em; margin-bottom: 20px; }
        .status { background-color: #2d4a2d; border: 1px solid #4caf50; border-radius: 4px; padding: 10px; margin-bottom: 20px; color: #e0e0e0; }
        .status.running { background-color: #4a3a2d; border-color: #ff9800; }
        .status.scanning { background-color: #2d4a2d; border-color: #007acc; }
        .status.complete { background-color: #2d4a2d; border-color: #4caf50; }
        .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid #555555; border-top: 3px solid #007acc; border-radius: 50%; animation: spin 1s linear infinite; }
        p { color: #cccccc; }
        .redirect { background-color: #2d4a4a; }
        .redirect a { color: #00bcd4; }>&
        .redirect a:hover { color: #26c6da; }
        .smb-share { margin: 5px 0; padding: 5px; background-color: #2d4a2d; border-radius: 4px; }
        .smb-share span { color: #4caf50; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enumeration Report</h1>
        <div class="timestamp">Generated on: $(date)</div>
        <div id="target-display" class="timestamp">Target: $rhost</div>
        
        <div class="section">
            <h2>Open Ports</h2>
            <div>
                <p>Scanning in progress...</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Web Directories Found</h2>
            <h3>Accessible Pages</h3>
            $(if [[ ${#accessible_pages[@]} -gt 0 ]]; then
                for page in "${accessible_pages[@]}"; do
                    echo "<div class=\"web-page\"><a href=\"$page\" target=\"_blank\">$page</a></div>"
                done
            else
                echo "<p>No accessible pages found</p>"
            fi)
            <h3>Redirect Pages</h3>
            $(if [[ ${#redirect_pages[@]} -gt 0 ]]; then
                for page in "${redirect_pages[@]}"; do
                    echo "<div class=\"web-page redirect\"><a href=\"$page\" target=\"_blank\">$page</a></div>"
                done
            else
                echo "<p>No redirect pages found</p>"
            fi)
            <h3>Forbidden Pages (Potential Interest)</h3>
            $(if [[ ${#forbidden_pages[@]} -gt 0 ]]; then
                for page in "${forbidden_pages[@]}"; do
                    echo "<div class=\"web-page forbidden\"><a href=\"$page\" target=\"_blank\">$page</a></div>"
                done
            else
                echo "<p>No forbidden pages found</p>"
            fi)
        </div>
        
        <div class="section">
            <h2>SMB Shares</h2>
            $(if [[ ${#smb_shares[@]} -gt 0 ]]; then
                for share in "${smb_shares[@]}"; do
                    echo "<div class=\"smb-share\"><span>$share</span></div>"
                done
            else
                echo "<p>No SMB shares found</p>"
            fi)
        </div>
        
        <div class="section">
            <h2>Potential Vulnerabilities</h2>
            <div>
                $(if [[ "$smb_vulnerable" == "true" ]]; then
                    if grep -q "Message signing enabled but not required" output/smb_check.txt 2>/dev/null; then
                        echo "<p class=\"vuln\">• SMB Message Signing not required (AS-REP Roasting/Kerberoasting potential)</p>"
                    fi
                    if grep -q "Anonymous access granted\|NULL sessions are allowed\|Anonymous login successful\|Guest login successful" output/smb_check.txt 2>/dev/null; then
                        echo "<p class=\"vuln\">• SMB Null Sessions allowed (information disclosure vulnerability)</p>"
                    fi
                fi)
                $(if [[ "$ftp_anon_vulnerable" == "true" ]]; then
                    echo "<p class=\"vuln\">• Anonymous FTP login allowed (potential security risk)</p>"
                fi)
                $(if [[ "$smb_vulnerable" == "false" && "$ftp_anon_vulnerable" == "false" ]]; then
                    echo "<p>No obvious vulnerabilities detected</p>"
                fi)
            </div>
        </div>
    </div>
</body>
</html>
EOF

loading_animation() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

dir_fuzz() {
    local port=$1
    echo "Running directory fuzzing on port $port"
    update_status "running" "Fuzzing directories on port $port..."
    ffuf -s -u "http://$resolved_ip:$port/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt  -mc 200,204,301,302,307,401,403 -o output/ffuf_$port.json &
    ffuf_pid=$!
    
    echo -n "Fuzzing directories on port $port... "
    loading_animation $ffuf_pid
    echo "Done!"
    
    # Parse ffuf results and add to lists
    if [[ -f "output/ffuf_$port.json" ]]; then
        echo "Parsing ffuf results for port $port..."
        
        # Use a more robust parsing approach
        while IFS= read -r result; do
            # Parse the result line: path,status,url
            path=$(echo "$result" | cut -d',' -f1)
            status=$(echo "$result" | cut -d',' -f2)
            full_url=$(echo "$result" | cut -d',' -f3)
            
            if [[ -n "$path" && -n "$status" && "$status" =~ ^[0-9]+$ ]]; then
                # Create the final URL with domain
                final_url="http://$rhost:$port/$path"
                
                # Categorize based on status code
                if [[ "$status" =~ ^(200|204)$ ]]; then
                    # Check if already in other arrays and remove
                    for i in "${!forbidden_pages[@]}"; do
                        if [[ "${forbidden_pages[$i]}" == "$final_url" ]]; then
                            unset "forbidden_pages[$i]"
                        fi
                    done
                    for i in "${!redirect_pages[@]}"; do
                        if [[ "${redirect_pages[$i]}" == "$final_url" ]]; then
                            unset "redirect_pages[$i]"
                        fi
                    done
                    # Add to accessible
                    accessible_pages+=("$final_url")
                elif [[ "$status" =~ ^(301|302|307)$ ]]; then
                    # Check if already in other arrays and remove
                    for i in "${!accessible_pages[@]}"; do
                        if [[ "${accessible_pages[$i]}" == "$final_url" ]]; then
                            unset "accessible_pages[$i]"
                        fi
                    done
                    for i in "${!forbidden_pages[@]}"; do
                        if [[ "${forbidden_pages[$i]}" == "$final_url" ]]; then
                            unset "forbidden_pages[$i]"
                        fi
                    done
                    # Add to redirects
                    redirect_pages+=("$final_url")
                elif [[ "$status" =~ ^(401|403)$ ]]; then
                    # Check if already in other arrays and remove
                    for i in "${!accessible_pages[@]}"; do
                        if [[ "${accessible_pages[$i]}" == "$final_url" ]]; then
                            unset "accessible_pages[$i]"
                        fi
                    done
                    for i in "${!redirect_pages[@]}"; do
                        if [[ "${redirect_pages[$i]}" == "$final_url" ]]; then
                            unset "redirect_pages[$i]"
                        fi
                    done
                    # Add to forbidden
                    forbidden_pages+=("$final_url")
                fi
            fi
        done < <(jq -r '.results[] | "\(.input.FUZZ),\(.status),\(.url)"' "output/ffuf_$port.json" 2>/dev/null)
        
        # Rebuild arrays to remove gaps
        accessible_pages=("${accessible_pages[@]}")
        forbidden_pages=("${forbidden_pages[@]}")
        redirect_pages=("${redirect_pages[@]}")
        
        # Remove duplicates
        deduplicate_array accessible_pages
        deduplicate_array forbidden_pages
        deduplicate_array redirect_pages
        
        echo "Final results for port $port:"
        echo "  Accessible: ${#accessible_pages[@]} pages"
        echo "  Forbidden: ${#forbidden_pages[@]} pages"
        echo "  Redirects: ${#redirect_pages[@]} pages"
    fi
}

update_status "running" "Checking target configuration..."

# Check if rhost is a domain name and resolve it
if [[ "$rhost" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Target is an IP address: $rhost"
    resolved_ip="$rhost"
    is_ipv6=false
else
    echo "Target is a domain name: $rhost"
    update_status "running" "Resolving domain name..."
    echo "Resolving domain to IP address..."
    
    # Try to get IPv4 first (preferred)
    resolved_ip=$(nslookup -type=A "$rhost" 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}')
    
    if [[ -n "$resolved_ip" ]] && [[ "$resolved_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Resolved to IPv4: $resolved_ip"
        is_ipv6=false
    else
        # If no IPv4, try IPv6
        echo "No IPv4 address found, trying IPv6..."
        resolved_ip=$(nslookup -type=AAAA "$rhost" 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}')
        if [[ -n "$resolved_ip" ]] && [[ "$resolved_ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            echo "Resolved to IPv6: $resolved_ip"
            is_ipv6=true
        else
            echo "ERROR: Could not resolve domain name $rhost to either IPv4 or IPv6"
            exit 1
        fi
    fi
fi

# Test connectivity to the target
echo "Testing connectivity to $resolved_ip..."
update_status "running" "Testing connectivity to target..."
if [[ "$is_ipv6" == "true" ]]; then
    ping6 -c 1 -W 3 "$resolved_ip" >/dev/null 2>&1
else
    ping -c 1 -W 3 "$resolved_ip" >/dev/null 2>&1
fi

if [[ $? -ne 0 ]]; then
    echo "WARNING: Target $resolved_ip appears to be unreachable"
    echo "Continuing with scan anyway (target might be blocking ICMP)..."
fi

update_status "running" "Starting port enumeration..."

if [[ "$is_ipv6" == "true" ]]; then
    nmap -6 -sV -sC -A "$resolved_ip" >> output/port_scan.txt &
else
    nmap -sV -sC -A "$resolved_ip" >> output/port_scan.txt &
fi
nmap_pid=$!

echo "beginning port scanning"
echo -n "Running initial nmap scan... "
update_status "running" "Running initial nmap scan..."
loading_animation $nmap_pid
echo "Done!"

if [[ -n $(grep "Note: Host seems down." output/port_scan.txt) ]]; then
  echo "host is either down or blocking probes. switching to UDP and ICMP scans"
  update_status "running" "Running UDP and ICMP scans..."
  if [[ "$is_ipv6" == "true" ]]; then
    nmap -6 -sV -sU "$resolved_ip" >> output/port_scan.txt &
    udp_pid=$!
    nmap -6 -sV -Pn "$resolved_ip" >> output/port_scan.txt &
    icmp_pid=$!
  else
    nmap -sV -sU "$resolved_ip" >> output/port_scan.txt &
    udp_pid=$!
    nmap -sV -Pn "$resolved_ip" >> output/port_scan.txt &
    icmp_pid=$!
  fi
  
  echo -n "Running UDP scan... "
  loading_animation $udp_pid
  echo "Done!"
  
  echo -n "Running ICMP scan... "
  loading_animation $icmp_pid
  echo "Done!"
  
  wait
else
  echo "Host is up, continuing with results..."
fi

update_status "running" "Processing scan results..."

declare -a open_ports

while IFS= read -r port; do
    open_ports+=("$port")
done < <(awk '$2 == "open" {print $1}' "output/port_scan.txt" | cut -d'/' -f1)

echo "$open_ports" >> output/open.txt
echo $open_ports

printf "%s\n" "${open_ports[@]}"

echo "These are the open ports:"

update_status "running" "Analyzing open ports and services..."

# Check for SMB vulnerabilities from initial scan
if grep -q "Message signing enabled but not required" output/port_scan.txt; then
    echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
    # Create smb_check.txt for HTML report
    echo "SMB Message signing enabled but not required" > output/smb_check.txt
    smb_vulnerable=true
fi

for port in "${open_ports[@]}"; do
  if [[ "$port" == "21" ]]; then
    echo "Port 21 (FTP)"
    echo "Checking for anonymous FTP access..."
    if [[ "$is_ipv6" == "true" ]]; then
        nmap -6 --script ftp-anon -p 21 "$resolved_ip" > output/ftp_check.txt
    else
        nmap --script ftp-anon -p 21 "$resolved_ip" > output/ftp_check.txt
    fi
    if grep -q "Anonymous FTP login allowed" output/ftp_check.txt; then
      echo "WARNING: Anonymous FTP login allowed - potential security risk"
      ftp_anon_vulnerable=true
    fi
  elif [[ "$port" == "22" ]]; then
    echo "Port 22 (SSH)"
  elif [[ "$port" == "53" ]]; then
    echo "Port 53 (DNS)"
  elif [[ "$port" == "23" ]]; then
    echo "Port 23 (Telnet)"
  elif [[ "$port" == "80" ]]; then
    echo "Port 80 (HTTP)"
    dir_fuzz 80
  elif [[ "$port" == "443" ]]; then
    echo "Port 443 (HTTPS)"
    dir_fuzz 443
  elif [[ "$port" == "88" ]]; then
    echo "Port 88 (Kerberos)"
  elif [[ "$port" == "445" ]]; then
    echo "Port 445 (SMB)"
    echo "Checking SMB message signing, enumerating shares, and testing null sessions..."
    if [[ "$is_ipv6" == "true" ]]; then
        nmap -6 --script smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups -p 445 "$resolved_ip" > output/smb_check.txt
    else
        nmap --script smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups -p 445 "$resolved_ip" > output/smb_check.txt
    fi
    if grep -q "Message signing enabled but not required" output/smb_check.txt; then
      echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
      smb_vulnerable=true
    fi
    if grep -q "Anonymous access granted\|NULL sessions are allowed\|Anonymous login successful\|Guest login successful" output/smb_check.txt; then
      echo "WARNING: SMB null sessions allowed - potential information disclosure vulnerability"
      smb_vulnerable=true
    fi
    
    # Extract SMB share names
    echo "Extracting SMB share names..."
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*Share[[:space:]]+name:[[:space:]]+(.+)$ ]]; then
            share_name="${BASH_REMATCH[1]}"
            smb_shares+=("$share_name")
            echo "Found SMB share: $share_name"
        fi
    done < output/smb_check.txt
  elif [[ "$port" == "139" ]]; then
    echo "Port 139 (SMB)"
    echo "Checking SMB message signing, enumerating shares, and testing null sessions..."
    if [[ "$is_ipv6" == "true" ]]; then
        nmap -6 --script smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups -p 139 "$resolved_ip" > output/smb_check.txt
    else
        nmap --script smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups -p 139 "$resolved_ip" > output/smb_check.txt
    fi
    if grep -q "Message signing enabled but not required" output/smb_check.txt; then
      echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
      smb_vulnerable=true
    fi
    if grep -q "Anonymous access granted\|NULL sessions are allowed\|Anonymous login successful\|Guest login successful" output/smb_check.txt; then
      echo "WARNING: SMB null sessions allowed - potential information disclosure vulnerability"
      smb_vulnerable=true
    fi
    
    # Extract SMB share names
    echo "Extracting SMB share names..."
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*Share[[:space:]]+name:[[:space:]]+(.+)$ ]]; then
            share_name="${BASH_REMATCH[1]}"
            smb_shares+=("$share_name")
            echo "Found SMB share: $share_name"
        fi
    done < output/smb_check.txt
  elif [[ "$port" == "389" ]]; then
    echo "Port 389 (LDAP)"
  elif [[ "$port" == "636" ]]; then
    echo "Port 636 (LDAPS)"
  elif [[ "$port" == "25" ]]; then
    echo "Port 25 (SMTP)"
  elif [[ "$port" == "110" ]]; then
    echo "Port 110 (POP3)"
  elif [[ "$port" == "143" ]]; then
    echo "Port 143 (IMAP)"
  elif [[ "$port" == "3306" ]]; then
    echo "Port 3306 (MySQL)"
  elif [[ "$port" == "3389" ]]; then
    echo "Port 3389 (RDP)"
  elif [[ "$port" == "3390" ]]; then
    echo "Port 3390 (RDP)"
  elif [[ "$port" == "3388" ]]; then
    echo "Port 3388 (RDP)"
  elif [[ "$port" == "3391" ]]; then
    echo "Port 3391 (RDP)"
  elif [[ "$port" == "8080" ]]; then
    echo "Port 8080 (HTTP-Alt)"
    dir_fuzz 8080
  elif [[ "$port" == "8000" ]]; then
    echo "Port 8000 (HTTP-Alt/Web)"
    dir_fuzz 8000
  elif [[ "$port" == "135" ]]; then
    echo "Port 135 (MS-RPC)"
  fi
done

echo "Accessible pages:"
for page in "${accessible_pages[@]}"; do
    echo "$page"
done

echo "Redirect pages:"
for page in "${redirect_pages[@]}"; do
    echo "$page"
done

echo "Forbidden pages:"
for page in "${forbidden_pages[@]}"; do
    echo "$page"
done

# Final deduplication before summary
deduplicate_array accessible_pages
deduplicate_array redirect_pages
deduplicate_array forbidden_pages
deduplicate_array smb_shares

echo ""
echo "=========================================="
echo "           ENUMERATION SUMMARY"
echo "=========================================="
echo ""

echo "OPEN PORTS:"
for port in "${open_ports[@]}"; do
    # Get common port name
    case $port in
        21) port_name="FTP" ;;
        22) port_name="SSH" ;;
        23) port_name="Telnet" ;;
        25) port_name="SMTP" ;;
        53) port_name="DNS" ;;
        80) port_name="HTTP" ;;
        88) port_name="Kerberos" ;;
        110) port_name="POP3" ;;
        135) port_name="MS-RPC" ;;
        139) port_name="SMB" ;;
        143) port_name="IMAP" ;;
        389) port_name="LDAP" ;;
        443) port_name="HTTPS" ;;
        445) port_name="SMB" ;;
        636) port_name="LDAPS" ;;
        3306) port_name="MySQL" ;;
        3388) port_name="RDP" ;;
        3389) port_name="RDP" ;;
        3390) port_name="RDP" ;;
        3391) port_name="RDP" ;;
        5357) port_name="HTTP-API" ;;
        5985) port_name="HTTP-API" ;;
        8000) port_name="HTTP-Alt" ;;
        8080) port_name="HTTP-Alt" ;;
        *) port_name="Unknown" ;;
    esac
    echo "  $port ($port_name)"
done
echo ""

echo "WEB DIRECTORIES FOUND:"
if [[ ${#accessible_pages[@]} -gt 0 ]]; then
    echo "Accessible pages:"
    for page in "${accessible_pages[@]}"; do
        echo "  - $page"
    done
else
    echo "No accessible pages found"
fi

if [[ ${#redirect_pages[@]} -gt 0 ]]; then
    echo "Redirect pages:"
    for page in "${redirect_pages[@]}"; do
        echo "  - $page"
    done
else
    echo "No redirect pages found"
fi

if [[ ${#forbidden_pages[@]} -gt 0 ]]; then
    echo "Forbidden pages (potential interest):"
    for page in "${forbidden_pages[@]}"; do
        echo "  - $page"
    done
else
    echo "No forbidden pages found"
fi

if [[ ${#smb_shares[@]} -gt 0 ]]; then
    echo "SMB Shares Found:"
    for share in "${smb_shares[@]}"; do
        echo "  - $share"
    done
else
    echo "No SMB shares found"
fi

echo "POTENTIAL VULNERABILITIES:"
if [[ "$smb_vulnerable" == "true" ]]; then
    if grep -q "Message signing enabled but not required" output/smb_check.txt 2>/dev/null; then
        echo "  - SMB Message Signing not required (AS-REP Roasting/Kerberoasting potential)"
    fi
    if grep -q "Anonymous access granted\|NULL sessions are allowed\|Anonymous login successful\|Guest login successful" output/smb_check.txt 2>/dev/null; then
        echo "  - SMB Null Sessions allowed (information disclosure vulnerability)"
    fi
fi
if [[ "$ftp_anon_vulnerable" == "true" ]]; then
    echo "  - Anonymous FTP login allowed (potential security risk)"
fi

echo ""
echo "=========================================="

# Generate HTML report
echo "Generating HTML report..."
cat > output/enumeration_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Enigma-3NMA cheat codes - $rhost</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #1a1a1a; color: #e0e0e0; }
        .container { max-width: 1200px; margin: 0 auto; background: #2d2d2d; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        h1 { color: #ffffff; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #007acc; margin-top: 30px; }
        h3 { color: #cccccc; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; background-color: #3a3a3a; }
        .port { display: inline-block; margin: 5px; padding: 5px 10px; background-color: #1e3a5f; border-radius: 4px; color: #ffffff; }
        .vuln { color: #ff6b6b; font-weight: bold; }
        .web-page { margin: 5px 0; padding: 5px; background-color: #2d4a2d; border-radius: 4px; }
        .web-page a { color: #4caf50; text-decoration: none; }
        .web-page a:hover { color: #66bb6a; text-decoration: underline; }
        .forbidden { background-color: #4a3a2d; }
        .forbidden a { color: #ff9800; }
        .forbidden a:hover { color: #ffb74d; }
        .misc { background-color: #3a2d4a; }
        .misc a { color: #9c27b0; }
        .misc a:hover { color: #ba68c8; }
        .timestamp { color: #888888; font-size: 0.9em; margin-bottom: 20px; }
        .status { background-color: #2d4a2d; border: 1px solid #4caf50; border-radius: 4px; padding: 10px; margin-bottom: 20px; color: #e0e0e0; }
        .status.running { background-color: #4a3a2d; border-color: #ff9800; }
        .status.scanning { background-color: #2d4a2d; border-color: #007acc; }
        .status.complete { background-color: #2d4a2d; border-color: #4caf50; }
        .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid #555555; border-top: 3px solid #007acc; border-radius: 50%; animation: spin 1s linear infinite; }
        p { color: #cccccc; }
        .redirect { background-color: #2d4a4a; }
        .redirect a { color: #00bcd4; }
        .redirect a:hover { color: #26c6da; }
        .smb-share { margin: 5px 0; padding: 5px; background-color: #2d4a2d; border-radius: 4px; }
        .smb-share span { color: #4caf50; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enumeration Report</h1>
        <div class="timestamp">Generated on: $(date)</div>
        <div id="target-display" class="timestamp">Target: $rhost</div>
        
        <div class="section">
            <h2>Open Ports</h2>
            <div>
EOF

for port in "${open_ports[@]}"; do
    # Get common port name
    case $port in
        21) port_name="FTP" ;;
        22) port_name="SSH" ;;
        23) port_name="Telnet" ;;
        25) port_name="SMTP" ;;
        53) port_name="DNS" ;;
        80) port_name="HTTP" ;;
        88) port_name="Kerberos" ;;
        110) port_name="POP3" ;;
        135) port_name="MS-RPC" ;;
        139) port_name="SMB" ;;
        143) port_name="IMAP" ;;
        389) port_name="LDAP" ;;
        443) port_name="HTTPS" ;;
        445) port_name="SMB" ;;
        636) port_name="LDAPS" ;;
        3306) port_name="MySQL" ;;
        3388) port_name="RDP" ;;
        3389) port_name="RDP" ;;
        3390) port_name="RDP" ;;
        3391) port_name="RDP" ;;
        5357) port_name="HTTP-API" ;;
        5985) port_name="HTTP-API" ;;
        8000) port_name="HTTP-Alt" ;;
        8080) port_name="HTTP-Alt" ;;
        *) port_name="Unknown" ;;
    esac
    echo "                <span class=\"port\">$port ($port_name)</span>" >> output/enumeration_report.html
done

cat >> output/enumeration_report.html << EOF
            </div>
        </div>
        
        <div class="section">
            <h2>Web Directories Found</h2>
            <h3>Accessible Pages</h3>
EOF

if [[ ${#accessible_pages[@]} -gt 0 ]]; then
    for page in "${accessible_pages[@]}"; do
        echo "            <div class=\"web-page\"><a href=\"$page\" target=\"_blank\">$page</a></div>" >> output/enumeration_report.html
    done
else
    echo "            <p>No accessible pages found</p>" >> output/enumeration_report.html
fi

cat >> output/enumeration_report.html << EOF
            <h3>Redirect Pages</h3>
EOF

if [[ ${#redirect_pages[@]} -gt 0 ]]; then
    for page in "${redirect_pages[@]}"; do
        echo "            <div class=\"web-page redirect\"><a href=\"$page\" target=\"_blank\">$page</a></div>" >> output/enumeration_report.html
    done
else
    echo "            <p>No redirect pages found</p>" >> output/enumeration_report.html
fi

cat >> output/enumeration_report.html << EOF
            <h3>Forbidden Pages (Potential Interest)</h3>
EOF

if [[ ${#forbidden_pages[@]} -gt 0 ]]; then
    for page in "${forbidden_pages[@]}"; do
        echo "            <div class=\"web-page forbidden\"><a href=\"$page\" target=\"_blank\">$page</a></div>" >> output/enumeration_report.html
    done
else
    echo "            <p>No forbidden pages found</p>" >> output/enumeration_report.html
fi

cat >> output/enumeration_report.html << EOF
        </div>
        
        <div class="section">
            <h2>SMB Shares</h2>
            $(if [[ ${#smb_shares[@]} -gt 0 ]]; then
                for share in "${smb_shares[@]}"; do
                    echo "<div class=\"smb-share\"><span>$share</span></div>"
                done
            else
                echo "<p>No SMB shares found</p>"
            fi)
        </div>
        
        <div class="section">
            <h2>Potential Vulnerabilities</h2>
            <div>
EOF

if [[ "$smb_vulnerable" == "true" ]]; then
    echo "                <div class=\"vuln\">• SMB Message Signing not required (AS-REP Roasting/Kerberoasting potential)</div>" >> output/enumeration_report.html
fi

cat >> output/enumeration_report.html << EOF
            </div>
        </div>
    </div>
</body>
</html>
EOF

echo "HTML report generated: output/enumeration_report.html"

update_status "complete" "Enumeration completed successfully!"

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -f output/port_scan.txt output/open.txt output/smb_check.txt
rm -f output/ffuf_*.json

echo "Cleanup complete. Main findings saved to HTML report."

# Remove status file last
rm -f output/status.json

# At the end of the script, print export command for user
echo "\n[!] To use RHOST in your shell, run:"
echo "export RHOST=$RHOST"


