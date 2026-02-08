# qBittorrent with OpenVPN and Kill Switch

Docker container running the latest headless qBittorrent client with WebUI, connected through OpenVPN with an iptables kill switch to prevent IP leaks if the VPN tunnel drops.

## Features

- Ubuntu 24.04 LTS base, always builds latest qBittorrent
- OpenVPN support (can be disabled)
- iptables kill switch — all traffic blocked if VPN goes down
- IPv6 fully disabled to prevent leaks
- DNS leak prevention (defaults to Cloudflare `1.1.1.1` and Quad9 `9.9.9.9`)
- Configurable UID/GID/UMASK for file permissions
- Docker health check on WebUI availability

---

## Quick Start with Docker Compose (Recommended)

This is the easiest way to run the container, especially on a Raspberry Pi.

### 1. Create your directory structure

```bash
mkdir -p ~/qbittorrent/config/openvpn
mkdir -p ~/qbittorrent/downloads
```

### 2. Add your VPN config

Copy your `.ovpn` file from your VPN provider into the `config/openvpn/` directory:

```bash
cp /path/to/your-vpn.ovpn ~/qbittorrent/config/openvpn/
```

### 3. Create `docker-compose.yml`

```yaml
services:
  qbittorrent:
    image: aiwi/docker-qbittorrentvpn
    container_name: qbittorrent
    restart: unless-stopped
    privileged: true
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
    ports:
      - 8080:8080
      - 8999:8999
      - 8999:8999/udp
```

> **Tip:** Change `LAN_NETWORK` to match your local network. On Raspbian, run `ip route | grep default` to find it (e.g. `192.168.1.0/24`).

### 4. Start the container

```bash
docker compose up -d
```

### 5. Open the WebUI

Go to `http://<YOUR-PI-IP>:8080` in a browser on the same network.

Default login: **admin** / **adminadmin**

---

## Raspberry Pi / Raspbian Notes

- **Architecture:** This image must be built for ARM if you're running on a Raspberry Pi. If the pre-built image doesn't support ARM, see [Building the Container Yourself](#building-the-container-yourself) below.
- **Find your LAN network:** Run `ip route | grep default` — if the output shows `192.168.1.1`, your `LAN_NETWORK` is `192.168.1.0/24`.
- **Find your PUID/PGID:** Run `id` — use the `uid` and `gid` values shown (typically `1000` for the default `pi` user).
- **TUN device:** If `/dev/net/tun` doesn't exist, load the module: `sudo modprobe tun`. To make it persist across reboots, add `tun` to `/etc/modules`.
- **Performance:** qBittorrent + OpenVPN can be demanding on older Pi models. A Raspberry Pi 4 or newer is recommended.

---

## Docker Run (Alternative)

```bash
docker run -d \
  --privileged \
  --device=/dev/net/tun \
  -v /your/config/path:/config \
  -v /your/downloads/path:/downloads \
  -e "VPN_ENABLED=yes" \
  -e "LAN_NETWORK=192.168.1.0/24" \
  -e "NAME_SERVERS=1.1.1.1,9.9.9.9" \
  -p 8080:8080 \
  -p 8999:8999 \
  -p 8999:8999/udp \
  aiwi/docker-qbittorrentvpn
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `VPN_ENABLED` | No | `yes` | Enable VPN (`yes` or `no`) |
| `OPENVPN_USERNAME` | No | — | VPN username (auto-configures `.ovpn` auth) |
| `OPENVPN_PASSWORD` | No | — | VPN password (auto-configures `.ovpn` auth) |
| `LAN_NETWORK` | Yes (if VPN on) | — | Local network in CIDR notation, e.g. `192.168.1.0/24` |
| `NAME_SERVERS` | No | `1.1.1.1,9.9.9.9` | Comma-separated DNS servers |
| `PUID` | No | `0` (root) | User ID for file ownership |
| `PGID` | No | `0` (root) | Group ID for file ownership |
| `UMASK` | No | `002` | File permission mask for new files |
| `WEBUI_PORT_ENV` | No | `8080` | WebUI port (must also change exposed port to match) |
| `INCOMING_PORT_ENV` | No | `8999` | Torrent listening port (must also change exposed port to match) |

## Volumes

| Path | Required | Description |
|---|---|---|
| `/config` | Yes | qBittorrent config, OpenVPN config, and logs |
| `/downloads` | No | Default download directory |

## Ports

| Port | Protocol | Description |
|---|---|---|
| `8080` | TCP | qBittorrent WebUI |
| `8999` | TCP + UDP | qBittorrent incoming connections |

---

## VPN Setup

The container **will not start** if `VPN_ENABLED=yes` and no `.ovpn` file is found in `/config/openvpn/`.

1. Place a single `.ovpn` file from your VPN provider in `/config/openvpn/`.
2. If your provider requires username/password auth, either:
   - Set `OPENVPN_USERNAME` and `OPENVPN_PASSWORD` environment variables, **or**
   - Add `auth-user-pass credentials.conf` to your `.ovpn` file and create `/config/openvpn/credentials.conf`:
     ```
     your-username
     your-password
     ```

> **Note:** Only the first `.ovpn` file found is used. Multiple files won't create multiple connections.

---

## Troubleshooting

### "Origin header & Target origin mismatch"

Set `WebUI\CSRFProtection=false` in `/config/qBittorrent/config/qBittorrent.conf` if using a reverse proxy.

### "WebUI: Invalid Host header, port mismatch"

This happens when using port forwarding with bridge networking. Don't remap ports externally — instead change `WEBUI_PORT_ENV` and/or `INCOMING_PORT_ENV` and update the exposed ports to match.

### Container won't start on Raspberry Pi

- Make sure `/dev/net/tun` exists: `ls -la /dev/net/tun`
- If missing, run: `sudo modprobe tun`
- Check logs: `docker compose logs -f qbittorrent`

### VPN connection fails

- Verify your `.ovpn` file works outside Docker first
- Check container logs for OpenVPN errors: `docker compose logs qbittorrent | grep -i openvpn`
- Make sure `LAN_NETWORK` is set correctly

---

## Building the Container Yourself

Clone the repo and build:

```bash
git clone https://github.com/your-username/docker-qBittorrentvpn.git
cd docker-qBittorrentvpn
docker build -t qbittorrentvpn .
```

Then update `docker-compose.yml` to use `image: qbittorrentvpn` instead of `image: aiwi/docker-qbittorrentvpn`, or run directly:

```bash
docker run -d \
  --privileged \
  --device=/dev/net/tun \
  -v /your/config/path:/config \
  -v /your/downloads/path:/downloads \
  -e "VPN_ENABLED=yes" \
  -e "LAN_NETWORK=192.168.1.0/24" \
  -e "NAME_SERVERS=1.1.1.1,9.9.9.9" \
  -p 8080:8080 \
  -p 8999:8999 \
  -p 8999:8999/udp \
  qbittorrentvpn
```

---

## Issues

If you run into problems, [open an issue on GitHub](https://github.com/MarkusMcNugen/docker-qBittorrentvpn/issues) with:

- Container logs (`docker compose logs qbittorrent`)
- Docker version (`docker --version`)
- Host OS and architecture (`uname -a`)
