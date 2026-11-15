#!/usr/bin/env bash
# Run on Kali. Fixed scope: the Metasploitable lab target only.
set -uo pipefail
export LC_ALL=C
TARGET=172.16.1.10
EXTENDED=0
SHELLSHOCK=0
for arg in "$@"; do
    case "$arg" in
        --extended) EXTENDED=1 ;;
        --shellshock) SHELLSHOCK=1 ;;
        -h|--help)
            echo 'Usage: bash recon_evidence.sh [--extended] [--shellshock]'
            echo 'Run as your normal Kali user; sudo is requested for Nmap.'
            exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done
for cmd in nmap ip ping timeout sudo tee sha256sum mktemp; do
    command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }
done
sudo -v || exit 1
OUT=$(mktemp -d "$HOME/recon-evidence-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || exit 1
printf 'step\texit_code\n' > "$OUT/status.tsv"
FAILURES=0

run() {
    local label=$1 result
    shift
    {
        printf '\n=== %s ===\n' "$label"
        date -u '+Started: %Y-%m-%dT%H:%M:%SZ'
        printf 'Command: '; printf '%q ' "$@"; printf '\n'
        "$@"
        result=$?
        date -u '+Finished: %Y-%m-%dT%H:%M:%SZ'
        printf 'Exit code: %s\n' "$result"
        exit "$result"
    } 2>&1 | tee "$OUT/$label.console.txt"
    result=${PIPESTATUS[0]}
    printf '%s\t%s\n' "$label" "$result" >> "$OUT/status.tsv"
    if (( result != 0 )); then FAILURES=$((FAILURES + 1)); fi
}

{
    date -u '+Run UTC: %Y-%m-%dT%H:%M:%SZ'
    printf 'Target: %s\nExtended: %s\nShellshock NSE: %s\n' "$TARGET" "$EXTENDED" "$SHELLSHOCK"
    hostname
    uname -a
    nmap --version
    printf '\nThis is a new run. Do not merge its counters or timestamps with older evidence.\n'
} > "$OUT/00-metadata.txt"
echo "Evidence directory: $OUT"

run 01-addresses ip -br address
run 02-route ip route get "$TARGET"
run 03-ping ping -n -c 3 -W 2 "$TARGET"
run 04-neighbors ip neigh show
if command -v traceroute >/dev/null; then
    run 05-path timeout 30 traceroute -n -m 5 -w 1 -q 1 "$TARGET"
else
    printf 'traceroute is not installed; no path trace was collected.\n' > "$OUT/05-path-skipped.txt"
fi

run 06-discovery sudo nmap -n -sn -PE -PS80,443 -PA80 --reason \
    --host-timeout 45s -oA "$OUT/06-discovery" "$TARGET"
PORTS=21,22,80,139,445,3306,4444
run 07-tcp sudo nmap -n -Pn -sS -p "$PORTS" --reason \
    --host-timeout 90s -oA "$OUT/07-tcp" "$TARGET"
run 08-service-os sudo nmap -n -Pn -sS -sV -O --osscan-limit \
    -p "$PORTS" --reason --host-timeout 180s -oA "$OUT/08-service-os" "$TARGET"

if (( EXTENDED )); then
    run 10-icmp-timestamp sudo nmap -n -sn -PP --reason --host-timeout 45s -oA "$OUT/10-icmp-timestamp" "$TARGET"
    run 11-connect timeout 100 nmap -n -Pn -sT -p 21,22,80 --reason --host-timeout 90s -oA "$OUT/11-connect" "$TARGET"
    run 12-ack sudo nmap -n -Pn -sA -p 21,22,80,443 --reason --host-timeout 90s -oA "$OUT/12-ack" "$TARGET"
    run 13-fin sudo nmap -n -Pn -sF -p 21,22,80 --reason --host-timeout 90s -oA "$OUT/13-fin" "$TARGET"
    run 14-xmas sudo nmap -n -Pn -sX -p 21,22,80 --reason --host-timeout 90s -oA "$OUT/14-xmas" "$TARGET"
    run 15-udp sudo nmap -n -Pn -sU -sV --top-ports 10 --reason --host-timeout 180s -oA "$OUT/15-udp" "$TARGET"
fi
if (( SHELLSHOCK )); then
    run 20-shellshock sudo nmap -n -Pn -sV -p 80 --script http-shellshock \
        --script-args http-shellshock.uri=/cgi-bin/test.cgi --script-timeout 30s \
        --host-timeout 90s -oA "$OUT/20-shellshock" "$TARGET"
fi

printf '\nSteps with nonzero exit codes: %s\n' "$FAILURES"
printf 'A zero exit code does not establish reachability, an open port or a vulnerability.\n'
printf 'Review scan output and status.tsv, including timeout and OS reliability warnings.\n'
(
    cd "$OUT" || exit 1
    shopt -s nullglob
    files=(*.txt *.tsv *.nmap *.xml *.gnmap)
    sha256sum -- "${files[@]}" > SHA256SUMS.txt
) || exit 1
printf 'Evidence saved to: %s\n' "$OUT"
printf 'Integrity check: cd %q && sha256sum -c SHA256SUMS.txt\n' "$OUT"
if (( FAILURES > 0 )); then exit 1; fi
