#!/bin/bash
# Monitor VPN connection and kill qBittorrent if VPN drops
# This prevents IP leaks if VPN disconnects

while true; do
	sleep 30

	# Check if VPN tunnel interface exists
	if ! ip addr show | grep -q "${VPN_DEVICE_TYPE}"; then
		echo "[crit] VPN tunnel down detected!" | ts '%Y-%m-%d %H:%M:%.S'
		echo "[crit] Killing qBittorrent to prevent IP leak" | ts '%Y-%m-%d %H:%M:%.S'
		killall qbittorrent-nox

		# Exit container - Docker restart policy will restart it
		echo "[info] Container exiting - will restart if restart policy set" | ts '%Y-%m-%d %H:%M:%.S'
		exit 1
	fi

	# Verify internet connectivity through VPN (use DNS lookup — some providers block ICMP)
	if ! nslookup google.com >/dev/null 2>&1; then
		echo "[warn] VPN tunnel exists but internet not reachable" | ts '%Y-%m-%d %H:%M:%.S'
	fi
done
