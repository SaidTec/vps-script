#!/bin/bash

# SAID_TÉCH PREMIUM INTERNET VPN Installer
# Version: 1.0.0
# Author: Joshua Said
# Website: joshuasaid.tech

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Directories
CONFIG_DIR="/etc/saidtech"
LOG_DIR="/var/log/saidtech"
BACKUP_DIR="/var/backups/saidtech"
DATABASE="$CONFIG_DIR/users.db"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Load configuration files
source <(curl -s https://raw.githubusercontent.com/joshuasaid/saidtech-vpn/main/config.sh)
source <(curl -s https://raw.githubusercontent.com/joshuasaid/saidtech-vpn/main/functions.sh)

# Main menu
function main_menu() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo -e " ███████╗ █████╗ ██╗██████╗ ████████╗███████╗ ██████╗██╗  ██╗"
        echo -e " ██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║  ██║"
        echo -e " ███████╗███████║██║██║  ██║   ██║   █████╗  ██║     ███████║"
        echo -e " ╚════██║██╔══██║██║██║  ██║   ██║   ██╔══╝  ██║     ██╔══██║"
        echo -e " ███████║██║  ██║██║██████╔╝   ██║   ███████╗╚██████╗██║  ██║"
        echo -e " ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝"
        echo -e "${NC}"
        echo -e "${BLUE}SAID_TÉCH PREMIUM INTERNET VPN INSTALLER${NC}"
        echo -e "${BLUE}Powered by joshuasaid.tech${NC}"
        echo -e ""
        echo -e "${YELLOW}1. Install Full VPN Suite${NC}"
        echo -e "${YELLOW}2. Add User${NC}"
        echo -e "${YELLOW}3. Delete User${NC}"
        echo -e "${YELLOW}4. List Users${NC}"
        echo -e "${YELLOW}5. View Connected Clients${NC}"
        echo -e "${YELLOW}6. Bandwidth Management${NC}"
        echo -e "${YELLOW}7. Protocol Configuration${NC}"
        echo -e "${YELLOW}8. Free Internet Optimizations${NC}"
        echo -e "${YELLOW}9. Update Script${NC}"
        echo -e "${YELLOW}10. Backup/Restore${NC}"
        echo -e "${YELLOW}11. Uninstall${NC}"
        echo -e "${RED}0. Exit${NC}"
        echo -e ""
        read -p "Enter your choice: " choice

        case $choice in
            1) install_full_vpn ;;
            2) add_user ;;
            3) delete_user ;;
            4) list_users ;;
            5) view_connected_clients ;;
            6) bandwidth_management ;;
            7) protocol_configuration ;;
            8) free_internet_optimizations ;;
            9) update_script ;;
            10) backup_restore ;;
            11) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# Install full VPN suite
function install_full_vpn() {
    echo -e "${GREEN}[*] Installing SAID_TÉCH PREMIUM INTERNET VPN Suite${NC}"
    
    # Create directories
    mkdir -p $CONFIG_DIR $LOG_DIR $BACKUP_DIR
    
    # Update system
    apt-get update
    apt-get upgrade -y
    
    # Install dependencies
    apt-get install -y curl wget git nano unzip jq bc build-essential \
    libssl-dev libffi-dev python3-dev python3-pip python3-setuptools \
    fail2ban iptables-persistent netfilter-persistent
    
    # Install protocols
    install_v2ray
    install_ssh_websocket
    install_stunnel
    install_slowdns
    install_shadowsocks
    install_trojan_go
    install_openvpn
    install_psiphon
    
    # Setup security
    setup_firewall
    setup_fail2ban
    setup_ssl
    
    # Setup database
    setup_database
    
    # Setup branding
    setup_branding
    
    echo -e "${GREEN}[*] Installation completed successfully!${NC}"
    sleep 3
}

# V2Ray installation
function install_v2ray() {
    echo -e "${GREEN}[*] Installing V2Ray${NC}"
    bash <(curl -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Configure V2Ray
    cat > /usr/local/etc/v2ray/config.json <<EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$(uuidgen)",
                        "alterId": 64
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/saidtech"
                }
            }
        },
        {
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$(uuidgen)",
                        "flow": "xtls-rprx-direct"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
    
    systemctl enable v2ray
    systemctl restart v2ray
    echo -e "${GREEN}[*] V2Ray installed and configured${NC}"
}

# SSH WebSocket installation
function install_ssh_websocket() {
    echo -e "${GREEN}[*] Installing SSH WebSocket${NC}"
    
    # Install required packages
    apt-get install -y nginx
    
    # Configure SSH over WebSocket
    cat > /etc/nginx/conf.d/ssh_websocket.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /ssh {
        proxy_pass http://127.0.0.1:2222;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    
    # Restart Nginx
    systemctl restart nginx
    
    echo -e "${GREEN}[*] SSH WebSocket installed and configured${NC}"
}

# SlowDNS installation
function install_slowdns() {
    echo -e "${GREEN}[*] Installing SlowDNS${NC}"
    
    # Clone SlowDNS
    git clone https://github.com/ghostline/slowdns.git /tmp/slowdns
    cd /tmp/slowdns
    make
    cp slowdns /usr/local/bin/
    
    # Configure SlowDNS
    cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/slowdns -udp :5300 -privkey-file /etc/saidtech/slowdns.key $DOMAIN 127.0.0.1:53
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable slowdns
    systemctl start slowdns
    
    echo -e "${GREEN}[*] SlowDNS installed and configured${NC}"
}

# Other protocol installation functions would follow similar patterns...

# Setup SSL
function setup_ssl() {
    echo -e "${GREEN}[*] Setting up SSL${NC}"
    
    # Install Certbot
    apt-get install -y certbot
    
    # Obtain certificate
    if certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN; then
        echo -e "${GREEN}[*] SSL certificate obtained successfully${NC}"
    else
        echo -e "${YELLOW}[!] Failed to obtain Let's Encrypt certificate, generating self-signed${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/selfsigned.key \
            -out /etc/ssl/certs/selfsigned.crt \
            -subj "/CN=$DOMAIN"
    fi
    
    # Setup auto-renewal
    echo "0 0 * * * root certbot renew --quiet --post-hook \"systemctl reload nginx\"" > /etc/cron.d/certbot
}

# User management functions
function add_user() {
    echo -e "${GREEN}[*] Adding User${NC}"
    read -p "Enter username: " username
    read -p "Enter password: " password
    read -p "Enter expiry date (YYYY-MM-DD): " expiry
    read -p "Enter bandwidth limit (MB, 0 for unlimited): " bandwidth
    
    # Add to database
    sqlite3 $DATABASE "INSERT INTO users (username, password, expiry, bandwidth_limit, used_bandwidth) VALUES ('$username', '$password', '$expiry', $bandwidth, 0);"
    
    echo -e "${GREEN}[*] User $username added successfully${NC}"
    sleep 2
}

function delete_user() {
    echo -e "${GREEN}[*] Deleting User${NC}"
    read -p "Enter username to delete: " username
    
    # Remove from database
    sqlite3 $DATABASE "DELETE FROM users WHERE username='$username';"
    
    echo -e "${GREEN}[*] User $username deleted successfully${NC}"
    sleep 2
}

function list_users() {
    echo -e "${GREEN}[*] Listing Users${NC}"
    sqlite3 -column -header $DATABASE "SELECT username, expiry, bandwidth_limit, used_bandwidth FROM users;"
    read -p "Press Enter to continue..."
}

# Free internet optimizations
function free_internet_optimizations() {
    echo -e "${GREEN}[*] Configuring Free Internet Optimizations${NC}"
    
    # SNI injection
    echo -e "${BLUE}Configuring SNI injection...${NC}"
    cat > /etc/saidtech/sni_injector.sh <<EOF
#!/bin/bash
# SNI Injector for bypassing ISP restrictions
while true; do
    for domain in \$(cat /etc/saidtech/sni_domains.txt); do
        iptables -t mangle -A OUTPUT -p tcp --dport 443 -j TEE --gateway $domain
        sleep 60
    done
done
EOF
    
    # Add common zero-rated domains
    cat > /etc/saidtech/sni_domains.txt <<EOF
safaricom.com
airtel.com
facebook.com
whatsapp.com
twitter.com
instagram.com
EOF
    
    # Make executable and run in background
    chmod +x /etc/saidtech/sni_injector.sh
    nohup /etc/saidtech/sni_injector.sh > /dev/null 2>&1 &
    
    # Domain fronting setup
    echo -e "${BLUE}Configuring domain fronting...${NC}"
    cat > /etc/nginx/conf.d/domain_fronting.conf <<EOF
server {
    listen 443 ssl;
    server_name $DOMAIN *.cloudflare.com;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
    
    systemctl restart nginx
    
    echo -e "${GREEN}[*] Free internet optimizations configured${NC}"
    sleep 2
}

# Branding setup
function setup_branding() {
    echo -e "${GREEN}[*] Setting up branding${NC}"
    
    # SSH banner
    cat > /etc/issue.net <<EOF
╔════════════════════════════════════════════════════════════╗
║                   SAID_TÉCH PREMIUM INTERNET               ║
║                  Powered by joshuasaid.tech                ║
║                                                            ║
║   * Premium high-speed VPN service                         ║
║   * Multiple protocol support                              ║
║   * Optimized for free internet access                     ║
║                                                            ║
║   Your connection is secured and encrypted                 ║
╚════════════════════════════════════════════════════════════╝
EOF
    
    # MOTD
    cat > /etc/motd <<EOF
╔════════════════════════════════════════════════════════════╗
║                  SAID_TÉCH VPN CONNECTION                  ║
║                  Powered by joshuasaid.tech                ║
║                                                            ║
║   Account: %username%                                      ║
║   Expiry:  %expiry_date%                                   ║
║   Bandwidth: %used_bandwidth%/%bandwidth_limit% MB used    ║
║                                                            ║
║   For support: admin@joshuasaid.tech                       ║
╚════════════════════════════════════════════════════════════╝
EOF
    
    # Enable banner in SSH
    sed -i 's/#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    systemctl restart sshd
    
    echo -e "${GREEN}[*] Branding setup complete${NC}"
}

# Initialize
check_os
check_dependencies
main_menu
