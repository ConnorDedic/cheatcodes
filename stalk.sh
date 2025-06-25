#!/bin/bash

## this is a script to enumerate a target
if [[ -z "$rhost" ]]; then
  echo "Please run ./start.sh to and set a RHOST"
  exit 1
fi  

nmap -sV -sC -A "$rhost" >> output/port_scan.txt &

echo "beginning port scanning"

if [[ -z $(grep "Note: Host seems down." port_scan.txt) ]]; then
  echo "starting nmap"
  exit 1

else
  echo "host is either down or blocking probes. switching to UDP and ICMP scans"
  sudo nmap -sV -sU "$rhost" >> output/port_scan.txt &
  sudo nmap -sV -Pn "$rhost" >> output/port_scan.txt &
fi

declare -a open_ports

while IFS= read -r port; do
    open_ports+=("$port")
done < <(awk '$2 == "open" {print $1}' "port_scan.txt" | cut -d'/' -f1)

echo "$open_ports" >> output/open.txt
echo $open_ports

printf "%s\n" "${open_ports[@]}"

echo "These 
for port in "${open_ports[@]}"; do
  if [[ "$port" == "22" ]]; then
    echo "Port 22 (SSH)"
  elif [[ "$port" == "53" ]]; then
    echo "Port 53 (DNS)"
  elif [[ "$port" == "23" ]]; then
    echo "Port 23 (Telnet)"
  elif [[ "$port" == "80" ]]; then
    echo "Port 80 (HTTP)"
  elif [[ "$port" == "443" ]]; then
    echo "Port 443 (HTTPS)"
  elif [[ "$port" == "88" ]]; then
    echo "Port 88 (Kerberos)"
  elif [[ "$port" == "445" ]]; then
    echo "Port 445 (SMB)"
  elif [[ "$port" == "139" ]]; then
    echo "Port 139 (SMB)"
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
  elif [[ "$port" == "8000" ]]; then
    echo "Port 8000 (HTTP-Alt/Web)"
  fi
done


