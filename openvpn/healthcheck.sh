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

	# Optional: Verify internet connectivity through VPN
	if ! ping -c 1 -W 5 -I "${VPN_DEVICE_TYPE}" 1.1.1.1 >/dev/null 2>&1; then
		echo "[warn] VPN tunnel exists but internet not reachable" | ts '%Y-%m-%d %H:%M:%.S'
	fi
done
