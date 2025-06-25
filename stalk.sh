#!/bin/bash

## this is a script to enumerate a target

declare -a accessible_pages
declare -a forbidden_pages
smb_vulnerable=false

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
    ffuf -u "http://$rhost:$port/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -o output/ffuf_$port.json &
    ffuf_pid=$!
    
    echo -n "Fuzzing directories on port $port... "
    loading_animation $ffuf_pid
    echo "Done!"
    
    # Parse ffuf results and add to lists
    if [[ -f "output/ffuf_$port.json" ]]; then
        # Extract accessible pages (200,204,301,302,307)
        while IFS= read -r line; do
            if [[ $line =~ \"status\":(200|204|301|302|307) ]]; then
                path=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
                if [[ -n "$path" ]]; then
                    accessible_pages+=("http://$rhost:$port$path")
                fi
            fi
        done < <(jq -r '.results[] | "{\"status\":\(.status),\"url\":\"\(.url)\"}"' "output/ffuf_$port.json" 2>/dev/null)
        
        # Extract forbidden pages (401,403)
        while IFS= read -r line; do
            if [[ $line =~ \"status\":(401|403) ]]; then
                path=$(echo "$line" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
                if [[ -n "$path" ]]; then
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

nmap -sV -sC -A "$rhost" >> output/port_scan.txt &
nmap_pid=$!

echo "beginning port scanning"
echo -n "Running initial nmap scan... "
loading_animation $nmap_pid
echo "Done!"

if [[ -n $(grep "Note: Host seems down." output/port_scan.txt) ]]; then
  echo "host is either down or blocking probes. switching to UDP and ICMP scans"
  nmap -sV -sU "$rhost" >> output/port_scan.txt &
  udp_pid=$!
  nmap -sV -Pn "$rhost" >> output/port_scan.txt &
  icmp_pid=$!
  
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

declare -a open_ports

while IFS= read -r port; do
    open_ports+=("$port")
done < <(awk '$2 == "open" {print $1}' "output/port_scan.txt" | cut -d'/' -f1)

echo "$open_ports" >> output/open.txt
echo $open_ports

printf "%s\n" "${open_ports[@]}"

echo "These are the open ports:"

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
    nmap --script smb-security-mode -p 445 "$rhost" > output/smb_check.txt
    if grep -q "Message signing enabled but not required" output/smb_check.txt; then
      echo "WARNING: SMB message signing not required - potential target for AS-REP Roasting and Kerberoasting"
      smb_vulnerable=true
    fi
  elif [[ "$port" == "139" ]]; then
    echo "Port 139 (SMB)"
    echo "Checking SMB message signing..."
    nmap --script smb-security-mode -p 139 "$rhost" > output/smb_check.txt
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
printf "%s\n" "${open_ports[@]}"
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
    <title>Enumeration Report - $rhost</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #007acc; margin-top: 30px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; background-color: #f9f9f9; }
        .port { display: inline-block; margin: 5px; padding: 5px 10px; background-color: #e3f2fd; border-radius: 4px; }
        .vuln { color: #d32f2f; font-weight: bold; }
        .web-page { margin: 5px 0; padding: 5px; background-color: #f1f8e9; border-radius: 4px; }
        .forbidden { background-color: #fff3e0; }
        .timestamp { color: #666; font-size: 0.9em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enumeration Report</h1>
        <div class="timestamp">Generated on: $(date)</div>
        <div class="timestamp">Target: $rhost</div>
        
        <div class="section">
            <h2>Open Ports</h2>
            <div>
EOF

for port in "${open_ports[@]}"; do
    echo "                <span class=\"port\">$port</span>" >> output/enumeration_report.html
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
        echo "            <div class=\"web-page\">$page</div>" >> output/enumeration_report.html
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

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -f output/port_scan.txt output/open.txt output/smb_check.txt
rm -f output/ffuf_*.json

echo "Cleanup complete. Main findings saved to HTML report."


