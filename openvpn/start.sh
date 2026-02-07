#!/bin/bash
# Forked from binhex's OpenVPN dockers
set -e

# check for presence of network interface docker0
check_network=$(ip link show docker0 2>/dev/null || true)

# if network interface docker0 is present then we are running in host mode and thus must exit
if [[ ! -z "${check_network}" ]]; then
	echo "[crit] Network type detected as 'Host', this will cause major issues, please stop the container and switch back to 'Bridge' mode" | ts '%Y-%m-%d %H:%M:%.S' && exit 1
fi

export VPN_ENABLED=$(echo "${VPN_ENABLED}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
if [[ ! -z "${VPN_ENABLED}" ]]; then
	echo "[info] VPN_ENABLED defined as '${VPN_ENABLED}'" | ts '%Y-%m-%d %H:%M:%.S'
else
	echo "[warn] VPN_ENABLED not defined,(via -e VPN_ENABLED), defaulting to 'yes'" | ts '%Y-%m-%d %H:%M:%.S'
	export VPN_ENABLED="yes"
fi

if [[ $VPN_ENABLED == "yes" ]]; then
	# create directory to store openvpn config files
	mkdir -p /config/openvpn
	# set perms and owner for files in /config/openvpn directory
	set +e
	chown -R "${PUID}":"${PGID}" "/config/openvpn" &> /dev/null
	exit_code_chown=$?
	chmod -R 775 "/config/openvpn" &> /dev/null
	exit_code_chmod=$?
	set -e
	if (( ${exit_code_chown} != 0 || ${exit_code_chmod} != 0 )); then
		echo "[warn] Unable to chown/chmod /config/openvpn/, assuming SMB mountpoint" | ts '%Y-%m-%d %H:%M:%.S'
	fi
	
	# wildcard search for openvpn config files (match on first result)
	export VPN_CONFIG=$(find /config/openvpn -maxdepth 1 -name "*.ovpn" -print -quit)
	
	# if ovpn file not found in /config/openvpn then exit
	if [[ -z "${VPN_CONFIG}" ]]; then
		echo "[crit] No OpenVPN config file located in /config/openvpn/ (ovpn extension), please download from your VPN provider and then restart this container, exiting..." | ts '%Y-%m-%d %H:%M:%.S' && exit 1
	fi
	
	echo "[info] OpenVPN config file (ovpn extension) is located at ${VPN_CONFIG}" | ts '%Y-%m-%d %H:%M:%.S'
	
	# Read username and password env vars and put them in credentials.conf, then add ovpn config for credentials file
	if [[ ! -z "${VPN_USERNAME}" ]] && [[ ! -z "${VPN_PASSWORD}" ]]; then
		if [[ ! -e /config/openvpn/credentials.conf ]]; then
			touch /config/openvpn/credentials.conf
			chmod 600 /config/openvpn/credentials.conf
		fi

		printf '%s\n' "${VPN_USERNAME}" > /config/openvpn/credentials.conf
		printf '%s\n' "${VPN_PASSWORD}" >> /config/openvpn/credentials.conf
		chmod 600 /config/openvpn/credentials.conf

		# Replace line with one that points to credentials.conf
		auth_cred_exist=$(cat "${VPN_CONFIG}" | grep -m 1 'auth-user-pass')
		if [[ ! -z "${auth_cred_exist}" ]]; then
			# Get line number of auth-user-pass
			LINE_NUM=$(grep -Fn -m 1 'auth-user-pass' "${VPN_CONFIG}" | cut -d: -f 1)
			sed -i "${LINE_NUM}s/.*/auth-user-pass credentials.conf\n/" "${VPN_CONFIG}"
		else
			sed -i "1s/.*/auth-user-pass credentials.conf\n/" "${VPN_CONFIG}"
		fi
	fi
	
	# convert CRLF (windows) to LF (unix) for ovpn
	/usr/bin/dos2unix "${VPN_CONFIG}" 1> /dev/null
	
	# parse values from ovpn file
	export vpn_remote_line=$(cat "${VPN_CONFIG}" | grep -P -o -m 1 '(?<=^remote\s)[^\n\r]+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${vpn_remote_line}" ]]; then
		echo "[info] VPN remote line defined as '${vpn_remote_line}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[crit] VPN configuration file ${VPN_CONFIG} does not contain 'remote' line, showing contents of file before exit..." | ts '%Y-%m-%d %H:%M:%.S'
		cat "${VPN_CONFIG}" && exit 1
	fi
	export VPN_REMOTE=$(echo "${vpn_remote_line}" | grep -P -o -m 1 '^[^\s\r\n]+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${VPN_REMOTE}" ]]; then
		echo "[info] VPN_REMOTE defined as '${VPN_REMOTE}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[crit] VPN_REMOTE not found in ${VPN_CONFIG}, exiting..." | ts '%Y-%m-%d %H:%M:%.S' && exit 1
	fi
	export VPN_PORT=$(echo "${vpn_remote_line}" | grep -P -o -m 1 '(?<=\s)\d{2,5}(?=\s)?+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${VPN_PORT}" ]]; then
		echo "[info] VPN_PORT defined as '${VPN_PORT}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[crit] VPN_PORT not found in ${VPN_CONFIG}, exiting..." | ts '%Y-%m-%d %H:%M:%.S' && exit 1
	fi
	export VPN_PROTOCOL=$(cat "${VPN_CONFIG}" | grep -P -o -m 1 '(?<=^proto\s)[^\r\n]+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${VPN_PROTOCOL}" ]]; then
		echo "[info] VPN_PROTOCOL defined as '${VPN_PROTOCOL}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		export VPN_PROTOCOL=$(echo "${vpn_remote_line}" | grep -P -o -m 1 'udp|tcp-client|tcp$' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
		if [[ ! -z "${VPN_PROTOCOL}" ]]; then
			echo "[info] VPN_PROTOCOL defined as '${VPN_PROTOCOL}'" | ts '%Y-%m-%d %H:%M:%.S'
		else
			echo "[warn] VPN_PROTOCOL not found in ${VPN_CONFIG}, assuming udp" | ts '%Y-%m-%d %H:%M:%.S'
			export VPN_PROTOCOL="udp"
		fi
	fi
	
	# required for use in iptables
	if [[ "${VPN_PROTOCOL}" == "tcp-client" ]]; then
		export VPN_PROTOCOL="tcp"
	fi
	
	VPN_DEVICE_TYPE=$(cat "${VPN_CONFIG}" | grep -P -o -m 1 '(?<=^dev\s)[^\r\n\d]+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${VPN_DEVICE_TYPE}" ]]; then
		export VPN_DEVICE_TYPE="${VPN_DEVICE_TYPE}0"
		echo "[info] VPN_DEVICE_TYPE defined as '${VPN_DEVICE_TYPE}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[crit] VPN_DEVICE_TYPE not found in ${VPN_CONFIG}, exiting..." | ts '%Y-%m-%d %H:%M:%.S' && exit 1
	fi
	# get values from env vars as defined by user
	export LAN_NETWORK=$(echo "${LAN_NETWORK}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${LAN_NETWORK}" ]]; then
		echo "[info] LAN_NETWORK defined as '${LAN_NETWORK}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[crit] LAN_NETWORK not defined (via -e LAN_NETWORK), exiting..." | ts '%Y-%m-%d %H:%M:%.S' && exit 1
	fi
	export NAME_SERVERS=$(echo "${NAME_SERVERS}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${NAME_SERVERS}" ]]; then
		echo "[info] NAME_SERVERS defined as '${NAME_SERVERS}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[warn] NAME_SERVERS not defined (via -e NAME_SERVERS), defaulting to Cloudflare and Quad9 name servers" | ts '%Y-%m-%d %H:%M:%.S'
		export NAME_SERVERS="1.1.1.1,9.9.9.9,1.0.0.1,149.112.112.112"
	fi
	export VPN_OPTIONS=$(echo "${VPN_OPTIONS}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
	if [[ ! -z "${VPN_OPTIONS}" ]]; then
		echo "[info] VPN_OPTIONS defined as '${VPN_OPTIONS}'" | ts '%Y-%m-%d %H:%M:%.S'
	else
		echo "[info] VPN_OPTIONS not defined (via -e VPN_OPTIONS)" | ts '%Y-%m-%d %H:%M:%.S'
		export VPN_OPTIONS=""
	fi
elif [[ $VPN_ENABLED == "no" ]]; then
	echo "[warn] !!IMPORTANT!! You have set the VPN to disabled, you will NOT be secure!" | ts '%Y-%m-%d %H:%M:%.S'
fi

# split comma seperated string into list from NAME_SERVERS env variable
IFS=',' read -ra name_server_list <<< "${NAME_SERVERS}"

# process name servers in the list
for name_server_item in "${name_server_list[@]}"; do

	# strip whitespace from start and end of lan_network_item
	name_server_item=$(echo "${name_server_item}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')

	echo "[info] Adding ${name_server_item} to resolv.conf" | ts '%Y-%m-%d %H:%M:%.S'
	echo "nameserver ${name_server_item}" >> /etc/resolv.conf

done

# Lock resolv.conf to prevent OpenVPN or other processes from changing it
# This prevents DNS leaks by ensuring our configured DNS servers are always used
chattr +i /etc/resolv.conf
echo "[info] resolv.conf locked to prevent DNS leaks" | ts '%Y-%m-%d %H:%M:%.S'

if [[ -z "${PUID}" ]]; then
	echo "[info] PUID not defined. Defaulting to root user" | ts '%Y-%m-%d %H:%M:%.S'
	export PUID="root"
fi

if [[ -z "${PGID}" ]]; then
	echo "[info] PGID not defined. Defaulting to root group" | ts '%Y-%m-%d %H:%M:%.S'
	export PGID="root"
fi

if [[ $VPN_ENABLED == "yes" ]]; then
	echo "[info] Starting OpenVPN..." | ts '%Y-%m-%d %H:%M:%.S'
	cd /config/openvpn
	exec openvpn --config "${VPN_CONFIG}" &
	sleep 10  # Increased from 5 to 10 seconds

	# Verify VPN is actually connected
	max_attempts=30
	attempt=0
	echo "[info] Waiting for VPN tunnel to establish..." | ts '%Y-%m-%d %H:%M:%.S'

	while [ $attempt -lt $max_attempts ]; do
		# Check if tunnel interface exists and is routing
		if ip addr show | grep -q "${VPN_DEVICE_TYPE}" && ip route | grep -q "${VPN_DEVICE_TYPE}"; then
			echo "[info] VPN tunnel is up and routing" | ts '%Y-%m-%d %H:%M:%.S'

			# Extra verification: check we can reach internet through VPN
			if ping -c 1 -W 2 -I "${VPN_DEVICE_TYPE}" 1.1.1.1 >/dev/null 2>&1; then
				echo "[info] VPN connection verified - internet accessible through tunnel" | ts '%Y-%m-%d %H:%M:%.S'
				break
			fi
		fi
		sleep 2
		attempt=$((attempt + 1))
	done

	if [ $attempt -eq $max_attempts ]; then
		echo "[crit] VPN failed to establish connection after 60 seconds" | ts '%Y-%m-%d %H:%M:%.S'
		echo "[crit] Container will exit to prevent IP leak" | ts '%Y-%m-%d %H:%M:%.S'
		exit 1
	fi

	# Start VPN health monitoring in background
	echo "[info] Starting VPN health monitor..." | ts '%Y-%m-%d %H:%M:%.S'
	/bin/bash /etc/openvpn/healthcheck.sh &

	exec /bin/bash /etc/qbittorrent/iptables.sh
else
	exec /bin/bash /etc/qbittorrent/start.sh
fi
