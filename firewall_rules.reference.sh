#!/bin/bash
# Production Stateful & DPI Firewall Script for Ubuntu Gateway
set -e

echo "[*] Resetting filter table rules (preserving existing NAT configuration)..."
iptables -t filter -F
iptables -t filter -X

# Default Policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Gateway Host Protection (INPUT Chain)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 10.10.1.0/24 -j ACCEPT

# DPI Inspection for Shellshock (MUST precede generic ESTABLISHED accept)
iptables -A FORWARD -p tcp --dport 80 -m string --string "() { :;};" --algo bm \
    -j LOG --log-prefix "[IPT-SHELLSHOCK-DROP]: " --log-level 4
iptables -A FORWARD -p tcp --dport 80 -m string --string "() { :;};" --algo bm \
    -j DROP

# Block Outbound Reverse Shells (Port 4444)
iptables -A FORWARD -p tcp --dport 4444 -j LOG --log-prefix "[IPT-REVSHELL-DROP]: " --log-level 4
iptables -A FORWARD -p tcp --dport 4444 -j DROP
iptables -A FORWARD -p tcp --sport 4444 -j DROP

# Stateful Connection Tracking for Established Sessions
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow New Valid Web Traffic to Target
iptables -A FORWARD -i ens37 -o ens33 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow ICMP with Rate Limiting (Anti-DoS)
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 2/s -j ACCEPT

# Internet Outbound Masquerading on ens38 only (idempotent check)
iptables -t nat -C POSTROUTING -o ens38 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ens38 -j MASQUERADE

echo "[+] Firewall rules successfully applied."
