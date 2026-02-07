# qBittorrent and OpenVPN
#
# Version 2.0

FROM ubuntu:24.04
LABEL maintainer="MarkusMcNugen"

VOLUME /downloads
VOLUME /config

ENV DEBIAN_FRONTEND noninteractive

RUN usermod -u 99 nobody

# Disable IPv6 completely to prevent leaks
RUN echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

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
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add configuration and scripts
ADD openvpn/ /etc/openvpn/
ADD qbittorrent/ /etc/qbittorrent/

RUN chmod +x /etc/qbittorrent/*.sh /etc/qbittorrent/*.init /etc/openvpn/*.sh

# Expose ports and run
EXPOSE 8080
EXPOSE 8999
EXPOSE 8999/udp

# Health check to verify qBittorrent WebUI is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${WEBUI_PORT:-8080}/ || exit 1

CMD ["/bin/bash", "/etc/openvpn/start.sh"]
