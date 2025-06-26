#!/bin/bash

## this is a script to enumerate a target

declare -a accessible_pages
declare -a forbidden_pages
smb_vulnerable=false

update_status() {
    local status=$1
    local message=$2
    echo "{\"status\":\"$status\",\"message\":\"$message\",\"target\":\"$rhost\"}" > output/status.json
}

# Set initial status
update_status "running" "Initializing enumeration script..."

# Ensure output directory exists
mkdir -p output

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
        # Extract accessible pages (200,204,301,302,307)
        while IFS= read -r line; do
            if [[ $line =~ \"status\":(200|204|301|302|307) ]]; then
                # Extract just the path from the full URL
                full_url=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
                path=$(echo "$full_url" | sed 's|http://[^/]*||')
                if [[ -n "$path" ]]; then
                    accessible_pages+=("http://$rhost:$port$path")
                fi
            fi
        done < <(jq -r '.results[] | "{\"status\":\(.status),\"url\":\"\(.url)\"}"' "output/ffuf_$port.json" 2>/dev/null)
        
        # Extract forbidden pages (401,403) - make sure they don't overlap with accessible
        while IFS= read -r line; do
            if [[ $line =~ \"status\":(401|403) ]]; then
                # Extract just the path from the full URL
                full_url=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
                path=$(echo "$full_url" | sed 's|http://[^/]*||')
                if [[ -n "$path" ]]; then
                    # Check if this path is already in accessible_pages and remove it if so
                    for i in "${!accessible_pages[@]}"; do
                        if [[ "${accessible_pages[$i]}" == "http://$rhost:$port$path" ]]; then
                            unset "accessible_pages[$i]"
                        fi
                    done
                    # Rebuild array to remove gaps
                    accessible_pages=("${accessible_pages[@]}")
                    # Add to forbidden pages
                    forbidden_pages+=("http://$rhost:$port$path")
                fi
            fi
        done < <(jq -r '.results[] | "{\"status\":\(.status),\"url\":\"\(.url)\"}"' "output/ffuf_$port.json" 2>/dev/null)
    fi
}

if [[ -z "$rhost" ]]; then
  echo "Please run ./start.sh to and set a RHOST"
  exit 1
fi  

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
  if [[ "$port" == "22" ]]; then
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
    echo "Checking SMB message signing..."
    if [[ "$is_ipv6" == "true" ]]; then
        nmap -6 --script smb-security-mode -p 445 "$resolved_ip" > output/smb_check.txt
    else
        nmap --script smb-security-mode -p 445 "$resolved_ip" > output/smb_check.txt
    fi
    if grep -q "Message signing enabled but not required" output/smb_check.txt; then
      echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
      smb_vulnerable=true
    fi
  elif [[ "$port" == "139" ]]; then
    echo "Port 139 (SMB)"
    echo "Checking SMB message signing..."
    if [[ "$is_ipv6" == "true" ]]; then
        nmap -6 --script smb-security-mode -p 139 "$resolved_ip" > output/smb_check.txt
    else
        nmap --script smb-security-mode -p 139 "$resolved_ip" > output/smb_check.txt
    fi
    if grep -q "Message signing enabled but not required" output/smb_check.txt; then
      echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
      smb_vulnerable=true
    fi
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

echo "Forbidden pages:"
for page in "${forbidden_pages[@]}"; do
    echo "$page"
done

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

if [[ ${#forbidden_pages[@]} -gt 0 ]]; then
    echo "Forbidden pages (potential interest):"
    for page in "${forbidden_pages[@]}"; do
        echo "  - $page"
    done
else
    echo "No forbidden pages found"
fi
echo ""

echo "POTENTIAL VULNERABILITIES:"
if [[ "$smb_vulnerable" == "true" ]]; then
    echo "  - SMB Message Signing not required (AS-REP Roasting/Kerberoasting potential)"
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
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #007acc; margin-top: 30px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; background-color: #f9f9f9; }
        .port { display: inline-block; margin: 5px; padding: 5px 10px; background-color: #e3f2fd; border-radius: 4px; }
        .vuln { color: #d32f2f; font-weight: bold; }
        .web-page { margin: 5px 0; padding: 5px; background-color: #f1f8e9; border-radius: 4px; }
        .forbidden { background-color: #fff3e0; }
        .timestamp { color: #666; font-size: 0.9em; margin-bottom: 20px; }
        .status { background-color: #e8f5e8; border: 1px solid #4caf50; border-radius: 4px; padding: 10px; margin-bottom: 20px; }
        .status.running { background-color: #fff3e0; border-color: #ff9800; }
        .status.complete { background-color: #e8f5e8; border-color: #4caf50; }
        .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid #f3f3f3; border-top: 3px solid #007acc; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
    <script>
        function updateStatus(status, message, target) {
            const statusDiv = document.getElementById('script-status');
            const targetDiv = document.getElementById('target-display');
            statusDiv.className = 'status ' + status;
            
            if (status === 'complete') {
                statusDiv.innerHTML = '<strong>Status:</strong> ' + message;
            } else {
                statusDiv.innerHTML = '<strong>Status:</strong> <span class="spinner"></span> ' + message;
            }
            
            if (target) {
                targetDiv.innerHTML = 'Target: ' + target;
            }
        }
        
        function checkProgress() {
            // This would be updated by the script
            fetch('status.json')
                .then(response => response.json())
                .then(data => {
                    updateStatus(data.status, data.message, data.target);
                    if (data.status !== 'complete') {
                        setTimeout(checkProgress, 1000);
                    }
                    // Stop checking when complete - don't schedule another check
                })
                .catch(() => {
                    // If status file doesn't exist, assume script is done
                    updateStatus('complete', 'Enumeration completed');
                    // Don't schedule another check - script is finished
                });
        }
        
        // Start checking progress when page loads
        window.onload = function() {
            checkProgress();
        };
    </script>
</head>
<body>
    <div class="container">
        <h1>Enumeration Report</h1>
        <div class="timestamp">Generated on: $(date)</div>
        <div id="target-display" class="timestamp">Target: $rhost</div>
        
        <div id="script-status" class="status running">
            <strong>Status:</strong> <span class="spinner"></span> Script is running...
        </div>
        
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
            <h3>Forbidden Pages (Potential Interest)</h3>
EOF

if [[ ${#forbidden_pages[@]} -gt 0 ]]; then
    for page in "${forbidden_pages[@]}"; do
        echo "            <div class=\"web-page forbidden\">$page</div>" >> output/enumeration_report.html
    done
else
    echo "            <p>No forbidden pages found</p>" >> output/enumeration_report.html
fi

cat >> output/enumeration_report.html << EOF
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


