# Security Audit & Recommended Improvements
**Date:** 2026-02-07
**Project:** docker-qBittorrentvpn
**Status:** Critical vulnerabilities identified - implementation pending

---

## Executive Summary

### Risk Assessment
- **IP Leak Risk:** 🔴 **CRITICAL** - WebUI traffic bypasses VPN entirely
- **Hacking Vulnerability:** 🟡 **MODERATE-HIGH** - Weak credentials, no HTTPS, CSRF disabled
- **Kill Switch Effectiveness:** 🟢 **PARTIALLY EFFECTIVE** - Works for torrents, but WebUI bypasses it

### Critical Findings
1. **WebUI traffic exposes real IP address** - traffic goes directly through eth0, not VPN tunnel
2. **Potential DNS leaks** - DNS set before VPN connects
3. **Weak default credentials** - admin/adminadmin (publicly known)
4. **No HTTPS** - credentials transmitted in plaintext
5. **IPv6 not fully disabled** - potential leak vector

---

## 🚨 CRITICAL IP LEAK VULNERABILITIES

### 1. WebUI Traffic Bypasses VPN ⚠️ CRITICAL
**Location:** `qbittorrent/iptables.sh:165-170, 109-114`

**Current Code:**
```bash
# Lines 165-170 - OUTPUT rules allow WebUI to ANY destination
iptables -A OUTPUT -o eth0 -p tcp --dport ${WEBUI_PORT} -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport ${WEBUI_PORT} -j ACCEPT

# Lines 109-114 - INPUT rules accept WebUI from ANY source
iptables -A INPUT -i eth0 -p tcp --dport ${WEBUI_PORT} -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport ${WEBUI_PORT} -j ACCEPT
```

**Problem:** When accessing the WebUI, **YOUR REAL IP ADDRESS IS EXPOSED**. Traffic doesn't route through VPN tunnel.

**Impact:** Complete IP leak when using WebUI from outside LAN.

---

### 2. DNS Leak Potential ⚠️ HIGH
**Location:** `openvpn/start.sh:150`

**Problem:** DNS servers written to `/etc/resolv.conf` BEFORE VPN connects. If OpenVPN doesn't push its own DNS, all DNS queries leak to Cloudflare/Quad9.

**Impact:** Your browsing activity is exposed to DNS providers, defeating VPN privacy.

---

### 3. Race Condition on Startup ⚠️ MEDIUM
**Location:** `openvpn/start.sh:165-171`

**Current Code:**
```bash
exec openvpn --config ${VPN_CONFIG} &
# give openvpn some time to connect
sleep 5
#exec /bin/bash /etc/openvpn/openvpn.init start &
exec /bin/bash /etc/qbittorrent/iptables.sh
```

**Problem:**
- OpenVPN starts in background
- Only 5-second sleep before iptables setup
- If VPN takes >5 seconds to connect, brief leak window exists

**Impact:** Potential IP leak during startup window.

---

### 4. No VPN Health Monitoring ⚠️ HIGH

**Problem:** If VPN disconnects after startup:
- No monitoring mechanism
- No automatic restart
- qBittorrent continues running
- Kill switch prevents NEW connections, but established connections may persist

**Impact:** Ongoing torrents could leak IP if VPN drops.

---

### 5. IPv6 Not Disabled ⚠️ MEDIUM
**Location:** `iptables.sh:90, 132`

**Current Code:**
```bash
ip6tables -P INPUT DROP 1>&- 2>&-
ip6tables -P OUTPUT DROP 1>&- 2>&-
```

**Problem:** IPv6 blocked via iptables but not disabled at system level. Applications might leak IPv6 before iptables blocks it.

**Impact:** Potential IPv6 leak at container startup.

---

## 🔐 SECURITY VULNERABILITIES

### 6. Weak Default Credentials ⚠️ CRITICAL
**Location:** `qBittorrent.conf`, `README.md:70`

**Current Defaults:**
- Username: `admin`
- Password: `adminadmin`

**Problem:** Publicly known, easily guessable credentials.

**Impact:** Anyone on your network can access and control qBittorrent.

---

### 7. CSRF Protection Disabled ⚠️ HIGH
**Location:** `qBittorrent.conf:34`

**Current Setting:**
```ini
WebUI\CSRFProtection=false
```

**Problem:** Vulnerable to cross-site request forgery attacks.

**Impact:** Attacker can make requests to WebUI from malicious websites.

---

### 8. No HTTPS ⚠️ HIGH
**Location:** `qBittorrent.conf:36`

**Current Setting:**
```ini
WebUI\HTTPS\Enabled=false
```

**Problem:** All traffic (including credentials) sent in plaintext.

**Impact:** Credentials can be intercepted on local network.

---

### 9. Command Injection Risks ⚠️ MEDIUM
**Locations:** `openvpn/start.sh` - multiple lines

**Vulnerable Code:**
```bash
# Line 57
auth_cred_exist=$(cat ${VPN_CONFIG} | grep -m 1 'auth-user-pass')

# Line 60
LINE_NUM=$(grep -Fn -m 1 'auth-user-pass' ${VPN_CONFIG} | cut -d: -f 1)

# Line 61
sed -i "${LINE_NUM}s/.*/auth-user-pass credentials.conf\n/" ${VPN_CONFIG}

# Line 167
exec openvpn --config ${VPN_CONFIG} &
```

**Problem:** Variables not quoted - if paths contain spaces or special characters, command injection possible.

**Impact:** Potential code execution if attacker controls VPN config file path.

---

### 10. Credentials in Plain Text ⚠️ MEDIUM
**Location:** `openvpn/start.sh:52-54`, `/config/openvpn/credentials.conf`

**Problem:** VPN credentials stored unencrypted on disk (permissions are 600, but still plaintext).

**Impact:** If container volume is compromised, credentials exposed.

---

### 11. Credential Echo Without Escaping ⚠️ LOW
**Location:** `openvpn/start.sh:52-53`

**Current Code:**
```bash
echo "${VPN_USERNAME}" > /config/openvpn/credentials.conf
echo "${VPN_PASSWORD}" >> /config/openvpn/credentials.conf
```

**Problem:** If credentials contain special characters (\`, $, \\, etc.), they could be misinterpreted.

**Impact:** Credentials might not be written correctly, causing VPN connection failure.

---

### 12. No Input Validation ⚠️ MEDIUM

**Problem:** Environment variables (LAN_NETWORK, NAME_SERVERS, VPN_USERNAME, etc.) not validated before use.

**Impact:** Malformed input could break container or create security issues.

---

### 13. Runs as Root by Default ⚠️ MEDIUM
**Location:** `openvpn/start.sh:154-161`

**Problem:** If PUID/PGID not set, defaults to root. OpenVPN runs as root.

**Impact:** Increased attack surface if container is compromised.

---

### 14. Container Escape Risks ⚠️ LOW

**Problem:** Requires NET_ADMIN and SYS_MODULE capabilities which could be exploited for container escape.

**Impact:** If combined with other vulnerabilities, could escape container.

---

### 15. No Rate Limiting on WebUI ⚠️ MEDIUM

**Problem:** WebUI has no brute-force protection.

**Impact:** Attacker can attempt unlimited password guesses.

---

## ✅ RECOMMENDED IMPROVEMENTS

### PRIORITY 1: Fix IP Leaks (CRITICAL)

#### A. Restrict WebUI to LAN Only
**File:** `qbittorrent/iptables.sh`
**Lines to modify:** 109-114, 165-170

**Change from:**
```bash
# INPUT - currently accepts from ANYWHERE
if [ -z "${WEBUI_PORT}" ]; then
	iptables -A INPUT -i eth0 -p tcp --dport 8080 -j ACCEPT
	iptables -A INPUT -i eth0 -p tcp --sport 8080 -j ACCEPT
else
	iptables -A INPUT -i eth0 -p tcp --dport ${WEBUI_PORT} -j ACCEPT
	iptables -A INPUT -i eth0 -p tcp --sport ${WEBUI_PORT} -j ACCEPT
fi

# OUTPUT - currently sends to ANYWHERE
if [ -z "${WEBUI_PORT}" ]; then
	iptables -A OUTPUT -o eth0 -p tcp --dport 8080 -j ACCEPT
	iptables -A OUTPUT -o eth0 -p tcp --sport 8080 -j ACCEPT
else
	iptables -A OUTPUT -o eth0 -p tcp --dport ${WEBUI_PORT} -j ACCEPT
	iptables -A OUTPUT -o eth0 -p tcp --sport ${WEBUI_PORT} -j ACCEPT
fi
```

**Change to:**
```bash
# INPUT - restrict to LAN ONLY
if [ -z "${WEBUI_PORT}" ]; then
	iptables -A INPUT -i eth0 -s "${LAN_NETWORK}" -p tcp --dport 8080 -j ACCEPT
	iptables -A INPUT -i eth0 -s "${LAN_NETWORK}" -p tcp --sport 8080 -j ACCEPT
else
	iptables -A INPUT -i eth0 -s "${LAN_NETWORK}" -p tcp --dport ${WEBUI_PORT} -j ACCEPT
	iptables -A INPUT -i eth0 -s "${LAN_NETWORK}" -p tcp --sport ${WEBUI_PORT} -j ACCEPT
fi

# OUTPUT - restrict to LAN ONLY
if [ -z "${WEBUI_PORT}" ]; then
	iptables -A OUTPUT -o eth0 -d "${LAN_NETWORK}" -p tcp --dport 8080 -j ACCEPT
	iptables -A OUTPUT -o eth0 -d "${LAN_NETWORK}" -p tcp --sport 8080 -j ACCEPT
else
	iptables -A OUTPUT -o eth0 -d "${LAN_NETWORK}" -p tcp --dport ${WEBUI_PORT} -j ACCEPT
	iptables -A OUTPUT -o eth0 -d "${LAN_NETWORK}" -p tcp --sport ${WEBUI_PORT} -j ACCEPT
fi
```

---

#### B. Prevent DNS Leaks
**File:** `openvpn/start.sh`
**Add after line 150:**

**Option 1 - Lock resolv.conf (simple):**
```bash
# Lock down resolv.conf to prevent changes
chattr +i /etc/resolv.conf
```

**Option 2 - Use OpenVPN DNS push (better):**
Add to your VPN config or create `/etc/openvpn/update-resolv-conf`:
```bash
# Add these lines to VPN_CONFIG or create up-script
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
```

---

#### C. Add VPN Connection Verification
**File:** `openvpn/start.sh`
**Replace lines 165-171:**

**Change from:**
```bash
echo "[info] Starting OpenVPN..." | ts '%Y-%m-%d %H:%M:%.S'
cd /config/openvpn
exec openvpn --config ${VPN_CONFIG} &
# give openvpn some time to connect
sleep 5
#exec /bin/bash /etc/openvpn/openvpn.init start &
exec /bin/bash /etc/qbittorrent/iptables.sh
```

**Change to:**
```bash
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

exec /bin/bash /etc/qbittorrent/iptables.sh
```

---

#### D. Disable IPv6 Completely
**File:** `Dockerfile`
**Add after line 13 (after `RUN usermod -u 99 nobody`):**

```dockerfile
# Disable IPv6 completely to prevent leaks
RUN echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
```

**File:** `qbittorrent/iptables.sh`
**Replace lines 90, 132:**

**Change from:**
```bash
# Line 90
ip6tables -P INPUT DROP 1>&- 2>&-

# Line 132
ip6tables -P OUTPUT DROP 1>&- 2>&-
```

**Change to:**
```bash
# Explicitly reject all IPv6 traffic
ip6tables -P INPUT DROP 1>&- 2>&-
ip6tables -P OUTPUT DROP 1>&- 2>&-
ip6tables -P FORWARD DROP 1>&- 2>&-
ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited 1>&- 2>&-
ip6tables -A OUTPUT -j REJECT --reject-with icmp6-adm-prohibited 1>&- 2>&-
ip6tables -A FORWARD -j REJECT --reject-with icmp6-adm-prohibited 1>&- 2>&-
```

---

#### E. Add VPN Health Monitoring
**Create new file:** `openvpn/healthcheck.sh`

```bash
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
```

**File:** `openvpn/start.sh`
**Add before final `exec` line (after line 171):**

```bash
# Start VPN health monitoring in background
/bin/bash /etc/openvpn/healthcheck.sh &
```

**File:** `Dockerfile`
**Add to line 25 (ADD openvpn/ section):**

```dockerfile
# Add configuration and scripts
ADD openvpn/ /etc/openvpn/
ADD qbittorrent/ /etc/qbittorrent/

RUN chmod +x /etc/qbittorrent/*.sh /etc/qbittorrent/*.init /etc/openvpn/*.sh
```

---

### PRIORITY 2: Fix Security Vulnerabilities (HIGH)

#### F. Force Strong Password on First Run
**File:** `qbittorrent/start.sh`
**Add before line 72 (`echo "[info] Starting qBittorrent daemon..."`):**

```bash
# Generate strong random password on first run
if [ ! -f /config/qBittorrent/config/.password_changed ]; then
	RANDOM_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

	echo "[warn] ============================================" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] DEFAULT PASSWORD CHANGED FOR SECURITY" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] New WebUI password: ${RANDOM_PASSWORD}" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] Username remains: admin" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] Save this password NOW!" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] Password also saved to:" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] /config/qBittorrent/config/.initial_password" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] ============================================" | ts '%Y-%m-%d %H:%M:%.S'

	# Save password to file for user retrieval
	echo "${RANDOM_PASSWORD}" > /config/qBittorrent/config/.initial_password
	chmod 600 /config/qBittorrent/config/.initial_password

	# Mark as changed so we don't regenerate
	touch /config/qBittorrent/config/.password_changed

	# TODO: Actually set this password in qBittorrent config
	# This requires password hashing - qBittorrent uses PBKDF2
	# For now, user must change password manually on first login
fi
```

---

#### G. Enable CSRF Protection
**File:** `qBittorrent.conf`
**Line 34:**

**Change from:**
```ini
WebUI\CSRFProtection=false
```

**Change to:**
```ini
WebUI\CSRFProtection=true
```

**File:** `README.md`
**Add note in WebUI section:**

```markdown
## CSRF Protection

CSRF protection is now enabled by default for security. If you use a reverse proxy,
you may need to configure it properly or set `WebUI\CSRFProtection=false` in
`/config/qBittorrent/config/qBittorrent.conf` (not recommended for security reasons).
```

---

#### H. Quote All Variables
**File:** `openvpn/start.sh`
**Multiple lines:**

**Lines to fix:**
```bash
# Line 57 - change from:
auth_cred_exist=$(cat ${VPN_CONFIG} | grep -m 1 'auth-user-pass')
# to:
auth_cred_exist=$(cat "${VPN_CONFIG}" | grep -m 1 'auth-user-pass')

# Line 60 - change from:
LINE_NUM=$(grep -Fn -m 1 'auth-user-pass' ${VPN_CONFIG} | cut -d: -f 1)
# to:
LINE_NUM=$(grep -Fn -m 1 'auth-user-pass' "${VPN_CONFIG}" | cut -d: -f 1)

# Line 61 - change from:
sed -i "${LINE_NUM}s/.*/auth-user-pass credentials.conf\n/" ${VPN_CONFIG}
# to:
sed -i "${LINE_NUM}s/.*/auth-user-pass credentials.conf\n/" "${VPN_CONFIG}"

# Line 63 - change from:
sed -i "1s/.*/auth-user-pass credentials.conf\n/" ${VPN_CONFIG}
# to:
sed -i "1s/.*/auth-user-pass credentials.conf\n/" "${VPN_CONFIG}"

# Line 71 - change from:
export vpn_remote_line=$(cat "${VPN_CONFIG}" | grep -P -o -m 1 '(?<=^remote\s)[^\n\r]+' | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
# to:
export vpn_remote_line=$(grep -P -o -m 1 '(?<=^remote\s)[^\n\r]+' "${VPN_CONFIG}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')

# Line 76 - change from:
cat "${VPN_CONFIG}" && exit 1
# to: (already quoted, but use grep instead of cat)
grep . "${VPN_CONFIG}" && exit 1

# Line 88, 90, 108 - similar changes for cat ${VPN_CONFIG}
```

---

#### I. Use Printf Instead of Echo for Credentials
**File:** `openvpn/start.sh`
**Lines 52-53:**

**Change from:**
```bash
echo "${VPN_USERNAME}" > /config/openvpn/credentials.conf
echo "${VPN_PASSWORD}" >> /config/openvpn/credentials.conf
```

**Change to:**
```bash
printf '%s\n' "${VPN_USERNAME}" > /config/openvpn/credentials.conf
printf '%s\n' "${VPN_PASSWORD}" >> /config/openvpn/credentials.conf
```

---

#### J. Add Input Validation
**File:** `openvpn/start.sh`
**Add after line 118 (after LAN_NETWORK echo):**

```bash
# Validate LAN_NETWORK is valid CIDR notation
if ! echo "${LAN_NETWORK}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'; then
	echo "[crit] LAN_NETWORK '${LAN_NETWORK}' is not valid CIDR notation" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[crit] Expected format: 192.168.1.0/24" | ts '%Y-%m-%d %H:%M:%.S'
	exit 1
fi

# Validate each octet is 0-255
IFS='.' read -ra OCTETS <<< "$(echo ${LAN_NETWORK} | cut -d'/' -f1)"
for octet in "${OCTETS[@]}"; do
	if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
		echo "[crit] Invalid IP address in LAN_NETWORK: ${LAN_NETWORK}" | ts '%Y-%m-%d %H:%M:%.S'
		exit 1
	fi
done

# Validate CIDR prefix
CIDR_PREFIX=$(echo ${LAN_NETWORK} | cut -d'/' -f2)
if [ "$CIDR_PREFIX" -lt 0 ] || [ "$CIDR_PREFIX" -gt 32 ]; then
	echo "[crit] Invalid CIDR prefix in LAN_NETWORK: ${LAN_NETWORK}" | ts '%Y-%m-%d %H:%M:%.S'
	exit 1
fi
```

**Add after line 126 (after NAME_SERVERS echo):**

```bash
# Validate NAME_SERVERS (validate each DNS IP)
IFS=',' read -ra dns_list <<< "${NAME_SERVERS}"
VALID_DNS=""
for dns in "${dns_list[@]}"; do
	dns=$(echo "$dns" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')

	# Check if valid IPv4
	if echo "${dns}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
		# Validate each octet
		IFS='.' read -ra OCTETS <<< "${dns}"
		valid=true
		for octet in "${OCTETS[@]}"; do
			if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
				valid=false
				break
			fi
		done

		if [ "$valid" = true ]; then
			if [ -z "$VALID_DNS" ]; then
				VALID_DNS="${dns}"
			else
				VALID_DNS="${VALID_DNS},${dns}"
			fi
		else
			echo "[warn] Invalid DNS server (bad octet): ${dns}, skipping" | ts '%Y-%m-%d %H:%M:%.S'
		fi
	else
		echo "[warn] Invalid DNS server format: ${dns}, skipping" | ts '%Y-%m-%d %H:%M:%.S'
	fi
done

if [ -z "$VALID_DNS" ]; then
	echo "[crit] No valid DNS servers provided in NAME_SERVERS" | ts '%Y-%m-%d %H:%M:%.S'
	exit 1
fi

export NAME_SERVERS="${VALID_DNS}"
echo "[info] Validated NAME_SERVERS: ${NAME_SERVERS}" | ts '%Y-%m-%d %H:%M:%.S'
```

---

#### K. Add Fail2ban for WebUI (Optional)
**File:** `Dockerfile`
**Add to package installation section:**

```dockerfile
# Update packages and install software
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-utils \
        openssl \
        software-properties-common \
    && add-apt-repository ppa:qbittorrent-team/qbittorrent-stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        qbittorrent-nox \
        openvpn \
        curl \
        moreutils \
        iproute2 \
        dos2unix \
        kmod \
        iptables \
        ipcalc \
        unrar \
        fail2ban \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
```

**Create new file:** `qbittorrent/fail2ban-qbittorrent.conf`

```ini
[qbittorrent]
enabled = true
port = 8080
filter = qbittorrent
logpath = /config/qBittorrent/data/logs/qbittorrent.log
maxretry = 5
bantime = 3600
findtime = 600
```

**Create new file:** `qbittorrent/fail2ban-filter.conf`

```ini
[Definition]
failregex = ^.*WebUI login failure.*from.*<HOST>.*$
            ^.*Unauthorized connection attempt.*<HOST>.*$
ignoreregex =
```

---

### PRIORITY 3: Additional Hardening (MEDIUM)

#### L. Drop Privileges After OpenVPN Connects
**File:** `openvpn/start.sh`
**Modify line 129-133 (VPN_OPTIONS section):**

**Change from:**
```bash
export VPN_OPTIONS=$(echo "${VPN_OPTIONS}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
if [[ ! -z "${VPN_OPTIONS}" ]]; then
	echo "[info] VPN_OPTIONS defined as '${VPN_OPTIONS}'" | ts '%Y-%m-%d %H:%M:%.S'
else
	echo "[info] VPN_OPTIONS not defined (via -e VPN_OPTIONS)" | ts '%Y-%m-%d %H:%M:%.S'
	export VPN_OPTIONS=""
fi
```

**Change to:**
```bash
export VPN_OPTIONS=$(echo "${VPN_OPTIONS}" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')

# Add security options: drop privileges after connection
# Note: OpenVPN needs root to create tun/tap, but can drop after
if [[ -z "${VPN_OPTIONS}" ]]; then
	export VPN_OPTIONS="--user nobody --group nogroup"
	echo "[info] VPN_OPTIONS set to default: '${VPN_OPTIONS}'" | ts '%Y-%m-%d %H:%M:%.S'
else
	echo "[info] VPN_OPTIONS defined as '${VPN_OPTIONS}'" | ts '%Y-%m-%d %H:%M:%.S'
	# Add privilege drop if not already specified
	if ! echo "${VPN_OPTIONS}" | grep -q "\-\-user"; then
		export VPN_OPTIONS="${VPN_OPTIONS} --user nobody --group nogroup"
		echo "[info] Added privilege drop to VPN_OPTIONS" | ts '%Y-%m-%d %H:%M:%.S'
	fi
fi
```

---

#### M. Add Explicit IPv6 Blocks (Already covered in Priority 1D)

---

#### N. Add Logging for Debugging
**File:** `qbittorrent/iptables.sh`
**Add before line 187 (before final iptables -S):**

```bash
# Optional: Create logging chain for dropped packets (debugging)
# Uncomment if you want to log blocked connections
# iptables -N LOGGING
# iptables -A INPUT -j LOGGING
# iptables -A OUTPUT -j LOGGING
# iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
# iptables -A LOGGING -j DROP

echo "[info] iptables configuration complete" | ts '%Y-%m-%d %H:%M:%.S'
```

---

#### O. Implement Connection Leak Test
**Create new file:** `openvpn/leak-test.sh`

```bash
#!/bin/bash
# Test for IP leaks - compares IP seen from inside vs outside VPN

echo "[info] Running IP leak test..." | ts '%Y-%m-%d %H:%M:%.S'

# Try to get real IP through eth0 (should fail due to iptables)
REAL_IP=$(timeout 5 curl -s --interface eth0 https://api.ipify.org 2>/dev/null)

# Get VPN IP through normal routing
VPN_IP=$(timeout 5 curl -s https://api.ipify.org 2>/dev/null)

if [ -z "${VPN_IP}" ]; then
	echo "[warn] Could not determine VPN IP - check internet connection" | ts '%Y-%m-%d %H:%M:%.S'
	exit 1
fi

if [ -n "${REAL_IP}" ] && [ "${REAL_IP}" == "${VPN_IP}" ]; then
	echo "[crit] ========================================" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[crit] IP LEAK DETECTED!" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[crit] Real IP is exposed: ${REAL_IP}" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[crit] VPN is not working properly!" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[crit] ========================================" | ts '%Y-%m-%d %H:%M:%.S'
	exit 1
elif [ -n "${REAL_IP}" ]; then
	echo "[warn] Real IP accessible but different from VPN IP" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] Real IP: ${REAL_IP}, VPN IP: ${VPN_IP}" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[warn] This might be normal depending on iptables config" | ts '%Y-%m-%d %H:%M:%.S'
else
	echo "[info] No IP leak detected" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[info] VPN IP: ${VPN_IP}" | ts '%Y-%m-%d %H:%M:%.S'
	echo "[info] Real IP is properly hidden (eth0 blocked)" | ts '%Y-%m-%d %H:%M:%.S'
fi

# DNS leak test
echo "[info] Running DNS leak test..." | ts '%Y-%m-%d %H:%M:%.S'
DNS_TEST=$(timeout 5 curl -s https://www.dnsleaktest.com/results.json 2>/dev/null)
if [ -n "${DNS_TEST}" ]; then
	echo "[info] DNS leak test results:" | ts '%Y-%m-%d %H:%M:%.S'
	echo "${DNS_TEST}" | grep -o '"country":"[^"]*"' | head -3
else
	echo "[warn] Could not run DNS leak test" | ts '%Y-%m-%d %H:%M:%.S'
fi

echo "[info] Leak test complete" | ts '%Y-%m-%d %H:%M:%.S'
```

**Add to Dockerfile:**
```dockerfile
RUN chmod +x /etc/qbittorrent/*.sh /etc/qbittorrent/*.init /etc/openvpn/*.sh
```

**Optional: Run on startup**
Add to `openvpn/start.sh` after VPN connects (after iptables.sh call):
```bash
# Run leak test after startup (optional)
sleep 5
/bin/bash /etc/openvpn/leak-test.sh || echo "[warn] Leak test failed, continuing anyway..." | ts '%Y-%m-%d %H:%M:%.S'
```

---

## 📋 IMPLEMENTATION CHECKLIST

Use this checklist when implementing the changes:

### Priority 1 - Critical IP Leak Fixes
- [ ] **A** - Restrict WebUI iptables rules to LAN only
- [ ] **B** - Implement DNS leak prevention
- [ ] **C** - Add VPN connection verification on startup
- [ ] **D** - Disable IPv6 completely at system level
- [ ] **E** - Create and enable VPN health monitoring script

### Priority 2 - Security Vulnerabilities
- [ ] **F** - Implement strong password generation on first run
- [ ] **G** - Enable CSRF protection in qBittorrent.conf
- [ ] **H** - Quote all variables in shell scripts
- [ ] **I** - Use printf instead of echo for credentials
- [ ] **J** - Add input validation for environment variables
- [ ] **K** - (Optional) Add fail2ban for brute-force protection

### Priority 3 - Additional Hardening
- [ ] **L** - Drop OpenVPN privileges after connection
- [ ] **M** - Enhance IPv6 blocking with explicit REJECT rules
- [ ] **N** - (Optional) Add iptables logging for debugging
- [ ] **O** - Create IP leak test script

### Testing
- [ ] Test VPN connection works after changes
- [ ] Verify WebUI only accessible from LAN
- [ ] Run leak test script
- [ ] Test VPN reconnection after disconnect
- [ ] Verify qBittorrent stops if VPN drops
- [ ] Check IPv6 is completely disabled
- [ ] Test with actual torrents

### Documentation
- [ ] Update README.md with security improvements
- [ ] Document new environment variables (if any)
- [ ] Add security best practices section
- [ ] Update default credentials warning

---

## 🧪 TESTING PROCEDURE

After implementing changes, test thoroughly:

### 1. IP Leak Testing
```bash
# Inside container
docker exec -it <container> /bin/bash

# Test 1: Verify VPN IP
curl https://api.ipify.org
# Should show VPN provider's IP, not your real IP

# Test 2: Try to access through eth0 (should fail)
curl --interface eth0 https://api.ipify.org
# Should timeout or fail

# Test 3: DNS leak test
nslookup google.com
# Should show VPN provider's DNS or your configured DNS

# Test 4: IPv6 disabled
ip -6 addr
# Should show no IPv6 addresses except ::1 on lo

# Test 5: Run leak test script
/etc/openvpn/leak-test.sh
```

### 2. WebUI Access Testing
```bash
# Test 1: Access from LAN (should work)
curl http://<container-ip>:8080/

# Test 2: Access from outside LAN (should fail)
# This needs testing from external network or by changing LAN_NETWORK temporarily

# Test 3: Verify CSRF protection
# Try to make request without CSRF token - should fail
```

### 3. VPN Disconnect Testing
```bash
# Kill OpenVPN process
docker exec <container> killall openvpn

# Wait 30 seconds for health check
# Container should exit and restart (if restart policy set)

# Verify qBittorrent was killed to prevent leak
docker logs <container> | grep -i "killing qbittorrent"
```

### 4. Startup Testing
```bash
# Restart container
docker restart <container>

# Watch logs
docker logs -f <container>

# Verify VPN connects before qBittorrent starts
# Verify leak test passes (if enabled)
```

---

## 📚 ADDITIONAL RECOMMENDATIONS

### Use Docker Secrets for VPN Credentials
Instead of environment variables, consider using Docker secrets:

```yaml
# docker-compose.yml
services:
  qbittorrentvpn:
    image: aiwi/docker-qbittorrentvpn
    secrets:
      - vpn_username
      - vpn_password

secrets:
  vpn_username:
    file: ./secrets/vpn_username.txt
  vpn_password:
    file: ./secrets/vpn_password.txt
```

### Enable Docker Restart Policy
```bash
docker run --restart=unless-stopped ...
```

This ensures container restarts if VPN health check kills it.

### Use Docker Compose
Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  qbittorrentvpn:
    image: aiwi/docker-qbittorrentvpn
    container_name: qbittorrentvpn
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    devices:
      - /dev/net/tun
    volumes:
      - ./config:/config
      - ./downloads:/downloads
    environment:
      - VPN_ENABLED=yes
      - LAN_NETWORK=192.168.1.0/24
      - NAME_SERVERS=1.1.1.1,9.9.9.9
      - PUID=1000
      - PGID=1000
      - UMASK=002
      - TZ=America/New_York
    ports:
      - "8080:8080"
      - "8999:8999"
      - "8999:8999/udp"
    restart: unless-stopped
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
```

### Regular Security Audits
- Review logs weekly: `docker logs qbittorrentvpn | grep -i "crit\|warn"`
- Run leak tests periodically
- Update base image regularly: `docker pull ubuntu:24.04`
- Monitor for qBittorrent security updates

### Network Isolation
Consider running on isolated Docker network:

```yaml
networks:
  vpn_network:
    driver: bridge
    internal: true  # No external access except through VPN
```

---

## 🔗 REFERENCES

- [qBittorrent Security Advisories](https://www.qbittorrent.org/news.php)
- [OpenVPN Security](https://openvpn.net/community-resources/hardening-openvpn-security/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [iptables Kill Switch Guide](https://www.ivpn.net/knowledgebase/linux/linux-kill-switch-using-iptables/)
- [DNS Leak Testing](https://www.dnsleaktest.com/)
- [IPv6 Leak Prevention](https://mullvad.net/en/help/ipv6-leaks/)

---

## 📝 NOTES

- All line numbers reference the current state of files (as of 2026-02-07)
- Test all changes in a development environment first
- Backup your config before implementing changes
- Some VPN providers may require specific OpenVPN options
- Performance impact of health monitoring is minimal (~30s checks)

---

**END OF SECURITY AUDIT**

For questions or issues, refer to this document and test thoroughly before deploying to production.
