#!/usr/bin/env bash
# Gateway lab: prepare a separate target-to-Kali TCP/4444 blocking test.
set -Eeuo pipefail

if (( EUID != 0 )); then
    printf 'Run this script with sudo bash.\n' >&2
    exit 1
fi

backup=$(mktemp /var/tmp/lab-callback-before.XXXXXX)
iptables-save -c > "$backup"
printf 'Original rules and counters saved to: %s\n' "$backup"

rollback() {
    trap - ERR
    printf 'A command failed; restoring the saved ruleset.\n' >&2
    iptables-restore -c < "$backup"
    exit 1
}
trap rollback ERR

remove_rule() {
    while iptables -C FORWARD "$@" 2>/dev/null; do
        iptables -D FORWARD "$@"
    done
}

# Remove only the two known test exceptions, including any duplicate copies.
remove_rule -s 10.10.1.10 -d 172.16.1.10 -p tcp --sport 4444 \
    -m comment --comment LAB-CALLBACK-TEST -j ACCEPT
remove_rule -s 172.16.1.10 -d 10.10.1.10 -p tcp --dport 4444 \
    -m comment --comment LAB-CALLBACK-TEST -j ACCEPT

# Reposition the exact test rules so repeated runs do not add duplicates.
remove_rule -s 172.16.1.10 -d 10.10.1.10 -p tcp --dport 4444 \
    -j LOG --log-prefix 'LAB-CALLBACK-DROP: '
remove_rule -s 172.16.1.10 -d 10.10.1.10 -p tcp --dport 4444 -j DROP

iptables -I FORWARD 1 -s 172.16.1.10 -d 10.10.1.10 \
    -p tcp --dport 4444 -j DROP
iptables -I FORWARD 1 -s 172.16.1.10 -d 10.10.1.10 \
    -p tcp --dport 4444 -j LOG --log-prefix 'LAB-CALLBACK-DROP: '

# Self-check: both expected rules must exist or the error trap restores backup.
iptables -C FORWARD -s 172.16.1.10 -d 10.10.1.10 \
    -p tcp --dport 4444 -j LOG --log-prefix 'LAB-CALLBACK-DROP: '
iptables -C FORWARD -s 172.16.1.10 -d 10.10.1.10 \
    -p tcp --dport 4444 -j DROP

printf '\nReady: LOG then DROP for target -> Kali TCP/4444.\n'
printf 'HTTP rules, NAT and chain policies were retained.\n'
printf 'Repeated runs recreate these two rules and reset their counters.\n\n'
iptables -L FORWARD -n -v -x --line-numbers
