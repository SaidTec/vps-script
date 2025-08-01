#!/usr/bin/env bash
# config.sh
# Global configuration for saidtech-vpn-installer

# === Branding ===
BRAND_NAME="SAID_TÉCH PREMIUM INTERNET"
BRAND_POWERED="Powered by joshuasaid.tech"

# === Database Settings ===
DB_TYPE="sqlite" # or mysql
DB_PATH="./saidtech.db"

# === Default Protocol Ports ===
V2RAY_PORT=443
SSH_WS_PORT=80
STUNNEL_PORT=443
SLOWDNS_PORT=5300
SHADOWSOCKS_PORT=8388
TROJAN_GO_PORT=4433
OPENVPN_TCP_PORT=1194
OPENVPN_UDP_PORT=1194
PSIPHON3_PORT=8080

# === Cloudflare DNS ===
CF_DNS="aria.ns.cloudflare.com"

# === Misc ===
LOG_FILE="./saidtech.log"