#!/bin/bash

#################################################################################
#                         SAID_TÉCH VPN Installer Functions                    #
#                           Core utilities and helpers                         #
#################################################################################

# Logging functions
setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
    fi
    
    LOG_FILE="$LOG_DIR/installer.log"
    ERROR_LOG="$LOG_DIR/error.log"
    
    # Create log rotation
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
    fi
}

log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] [$level] $message" >> "$ERROR_LOG"
    fi
    
    # Also output to console for important messages
    case $level in
        "ERROR")
            echo -e "${RED}[$level] $message${NC}"
            ;;
        "WARN")
            echo -e "${YELLOW}[$level] $message${NC}"
            ;;
        "INFO")
            echo -e "${GREEN}[$level] $message${NC}"
            ;;
    esac
}

# Network utilities
get_server_ip() {
    local ip
    ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || curl -s -4 ipinfo.io/ip 2>/dev/null)
    if [[ -z "$ip" ]]; then
        ip=$(ip route get 8.8.8.8 | head -1 | awk '{print $7}')
    fi
    echo "$ip"
}

get_server_ipv6() {
    local ipv6
    ipv6=$(curl -s -6 ifconfig.me 2>/dev/null || curl -s -6 icanhazip.com 2>/dev/null)
    echo "$ipv6"
}

check_port() {
    local port=$1
    if netstat -tlnp | grep -q ":$port "; then
        return 0
    else
        return 1
    fi
}

generate_random_port() {
    local min=${1:-1024}
    local max=${2:-65535}
    local port
    
    while true; do
        port=$((RANDOM % (max - min + 1) + min))
        if ! check_port "$port"; then
            echo "$port"
            break
        fi
    done
}

# SSL/TLS functions
setup_ssl_certificates() {
    echo -e "${YELLOW}Setting up SSL certificates...${NC}"
    
    local domain
    domain=$(whiptail --inputbox "Enter your domain name (optional, press Enter to use self-signed):" 10 60 3>&1 1>&2 2>&3)
    
    if [[ -n "$domain" ]]; then
        # Try Let's Encrypt
        if command -v certbot >/dev/null 2>&1; then
            log_message "INFO" "Attempting Let's Encrypt SSL for domain: $domain"
            
            # Stop nginx temporarily
            systemctl stop nginx 2>/dev/null || true
            
            if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email "admin@$domain" --no-eff-email; then
                log_message "INFO" "Let's Encrypt SSL certificate obtained successfully"
                SSL_CERT="/etc/letsencrypt/live/$domain/fullchain.pem"
                SSL_KEY="/etc/letsencrypt/live/$domain/privkey.pem"
                
                # Setup auto-renewal
                setup_ssl_autorenewal "$domain"
            else
                log_message "WARN" "Let's Encrypt failed, falling back to self-signed certificate"
                create_self_signed_cert "$domain"
            fi
            
            systemctl start nginx
        else
            create_self_signed_cert "$domain"
        fi
    else
        create_self_signed_cert "$(get_server_ip)"
    fi
    
    echo "$domain" > "$CONFIG_DIR/.domain"
}

create_self_signed_cert() {
    local domain=$1
    local cert_dir="$CONFIG_DIR/ssl"
    
    mkdir -p "$cert_dir"
    
    log_message "INFO" "Creating self-signed SSL certificate for: $domain"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$cert_dir/server.key" \
        -out "$cert_dir/server.crt" \
        -subj "/C=US/ST=State/L=City/O=SAID_TECH/OU=IT/CN=$domain"
    
    SSL_CERT="$cert_dir/server.crt"
    SSL_KEY="$cert_dir/server.key"
    
    chmod 600 "$cert_dir/server.key"
    chmod 644 "$cert_dir/server.crt"
}

setup_ssl_autorenewal() {
    local domain=$1
    
    # Create renewal script
    cat > "$INSTALL_DIR/ssl_renewal.sh" << 'EOF'
#!/bin/bash
certbot renew --quiet --post-hook "systemctl reload nginx"
EOF
    
    chmod +x "$INSTALL_DIR/ssl_renewal.sh"
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 12 * * * $INSTALL_DIR/ssl_renewal.sh") | crontab -
    
    log_message "INFO" "SSL auto-renewal configured"
}

# Node.js installation
install_nodejs() {
    if ! command -v node >/dev/null 2>&1; then
        log_message "INFO" "Installing Node.js..."
        
        case $PACKAGE_MANAGER in
            apt)
                curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
                apt-get install -y nodejs
                ;;
            pkg)
                pkg install -y nodejs npm
                ;;
        esac
    fi
}

# Database functions
setup_database() {
    local db_type=${1:-sqlite}
    
    case $db_type in
        sqlite)
            DB_FILE="$CONFIG_DIR/users.db"
            create_sqlite_schema
            ;;
        mysql)
            setup_mysql_database
            ;;
    esac
}

create_sqlite_schema() {
    log_message "INFO" "Creating SQLite database schema"
    
    sqlite3 "$DB_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    protocol TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    max_connections INTEGER DEFAULT 1,
    bandwidth_limit INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1,
    last_login DATETIME,
    data_used INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address TEXT,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    disconnected_at DATETIME,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO settings (key, value) VALUES 
    ('admin_password', ''),
    ('server_name', 'SAID_TÉCH VPN'),
    ('default_user_limit', '30'),
    ('max_connections_per_user', '2');
EOF
    
    log_message "INFO" "Database schema created successfully"
}

# Protocol installation functions
install_v2ray() {
    echo -e "${YELLOW}Installing V2Ray...${NC}"
    
    # Install V2Ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Create V2Ray configuration
    local vmess_port=$(generate_random_port 10000 20000)
    local vless_port=$(generate_random_port 20000 30000)
    local trojan_port=$(generate_random_port 30000 40000)
    local ws_port=$(generate_random_port 8000 9000)
    
    cat > "/usr/local/etc/v2ray/config.json" << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log"
    },
    "inbounds": [
        {
            "tag": "vmess-in",
            "port": $vmess_port,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$SSL_CERT",
                            "keyFile": "$SSL_KEY"
                        }
                    ]
                }
            }
        },
        {
            "tag": "vless-in",
            "port": $vless_port,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless"
                }
            }
        },
        {
            "tag": "trojan-in",
            "port": $trojan_port,
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$SSL_CERT",
                            "keyFile": "$SSL_KEY"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
    
    # Create log directory
    mkdir -p /var/log/v2ray
    
    # Start and enable V2Ray
    systemctl enable v2ray
    systemctl start v2ray
    
    # Save port configuration
    cat > "$CONFIG_DIR/v2ray_ports.conf" << EOF
VMESS_PORT=$vmess_port
VLESS_PORT=$vless_port
TROJAN_PORT=$trojan_port
WS_PORT=$ws_port
EOF
    
    log_message "INFO" "V2Ray installed successfully on ports: VMess($vmess_port), VLess($vless_port), Trojan($trojan_port)"
}

install_ssh_websocket() {
    echo -e "${YELLOW}Installing SSH WebSocket...${NC}"
    
    # Install Python dependencies
    pip3 install websockets asyncio python-socks
    
    # Create SSH WebSocket server
    local ws_port=$(generate_random_port 8080 8090)
    
    cat > "$INSTALL_DIR/ssh_websocket.py" << 'EOF'
#!/usr/bin/env python3
import asyncio
import websockets
import socket
import struct
import base64
import json
import logging

class SSHWebSocketProxy:
    def __init__(self, host='0.0.0.0', port=8080, ssh_host='127.0.0.1', ssh_port=22):
        self.host = host
        self.port = port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/saidtech/ssh_websocket.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def handle_websocket(self, websocket, path):
        try:
            # Connect to SSH server
            ssh_reader, ssh_writer = await asyncio.open_connection(
                self.ssh_host, self.ssh_port
            )
            
            self.logger.info(f"New WebSocket connection from {websocket.remote_address}")
            
            # Handle bidirectional data transfer
            await asyncio.gather(
                self.websocket_to_ssh(websocket, ssh_writer),
                self.ssh_to_websocket(ssh_reader, websocket)
            )
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            try:
                ssh_writer.close()
                await ssh_writer.wait_closed()
            except:
                pass
    
    async def websocket_to_ssh(self, websocket, ssh_writer):
        try:
            async for message in websocket:
                if isinstance(message, str):
                    data = base64.b64decode(message)
                else:
                    data = message
                ssh_writer.write(data)
                await ssh_writer.drain()
        except Exception as e:
            self.logger.error(f"WebSocket to SSH error: {e}")
    
    async def ssh_to_websocket(self, ssh_reader, websocket):
        try:
            while True:
                data = await ssh_reader.read(4096)
                if not data:
                    break
                await websocket.send(base64.b64encode(data).decode())
        except Exception as e:
            self.logger.error(f"SSH to WebSocket error: {e}")
    
    def start_server(self):
        self.logger.info(f"Starting SSH WebSocket proxy on {self.host}:{self.port}")
        return websockets.serve(self.handle_websocket, self.host, self.port)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    proxy = SSHWebSocketProxy(port=port)
    
    loop = asyncio.get_event_loop()
    start_server = proxy.start_server()
    loop.run_until_complete(start_server)
    loop.run_forever()
EOF
    
    chmod +x "$INSTALL_DIR/ssh_websocket.py"
    
    # Create systemd service
    cat > "/etc/systemd/system/ssh-websocket.service" << EOF
[Unit]
Description=SSH WebSocket Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ssh_websocket.py $ws_port
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ssh-websocket
    systemctl start ssh-websocket
    
    echo "SSH_WS_PORT=$ws_port" >> "$CONFIG_DIR/ssh_ports.conf"
    
    log_message "INFO" "SSH WebSocket installed on port $ws_port"
}

install_ssh_ssl() {
    echo -e "${YELLOW}Installing SSH over SSL (Stunnel)...${NC}"
    
    local ssl_port=$(generate_random_port 443 543)
    
    # Configure Stunnel
    cat > "/etc/stunnel/ssh-ssl.conf" << EOF
[ssh-ssl]
accept = $ssl_port
connect = 22
cert = $SSL_CERT
key = $SSL_KEY
EOF
    
    # Enable and start stunnel
    systemctl enable stunnel4
    systemctl start stunnel4
    
    echo "SSH_SSL_PORT=$ssl_port" >> "$CONFIG_DIR/ssh_ports.conf"
    
    log_message "INFO" "SSH over SSL installed on port $ssl_port"
}

install_shadowsocks() {
    echo -e "${YELLOW}Installing Shadowsocks...${NC}"
    
    # Install shadowsocks-libev
    case $PACKAGE_MANAGER in
        apt)
            apt install -y shadowsocks-libev
            ;;
        pkg)
            pkg install -y shadowsocks-libev
            ;;
    esac
    
    local ss_port=$(generate_random_port 8388 8400)
    local ss_password=$(openssl rand -base64 32)
    
    # Create Shadowsocks configuration
    cat > "/etc/shadowsocks-libev/config.json" << EOF
{
    "server": "0.0.0.0",
    "server_port": $ss_port,
    "password": "$ss_password",
    "timeout": 300,
    "method": "aes-256-gcm",
    "fast_open": false,
    "workers": 1,
    "prefer_ipv6": false,
    "no_delay": true,
    "reuse_port": true,
    "mode": "tcp_and_udp"
}
EOF
    
    # Enable and start shadowsocks
    systemctl enable shadowsocks-libev
    systemctl start shadowsocks-libev
    
    # Save configuration
    cat > "$CONFIG_DIR/shadowsocks.conf" << EOF
SS_PORT=$ss_port
SS_PASSWORD=$ss_password
SS_METHOD=aes-256-gcm
EOF
    
    log_message "INFO" "Shadowsocks installed on port $ss_port"
}

install_trojan_go() {
    echo -e "${YELLOW}Installing Trojan-Go...${NC}"
    
    # Download and install Trojan-Go
    local trojan_version="v0.10.6"
    local trojan_url="https://github.com/p4gefau1t/trojan-go/releases/download/$trojan_version/trojan-go-linux-amd64.zip"
    
    cd /tmp
    wget "$trojan_url" -O trojan-go.zip
    unzip trojan-go.zip
    chmod +x trojan-go
    mv trojan-go /usr/local/bin/
    
    local trojan_port=$(generate_random_port 443 543)
    local trojan_password=$(openssl rand -base64 32)
    
    # Create Trojan-Go configuration
    mkdir -p /etc/trojan-go
    cat > "/etc/trojan-go/config.json" << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $trojan_port,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["$trojan_password"],
    "ssl": {
        "cert": "$SSL_CERT",
        "key": "$SSL_KEY",
        "sni": "$(cat $CONFIG_DIR/.domain 2>/dev/null || get_server_ip)"
    },
    "websocket": {
        "enabled": true,
        "path": "/trojan",
        "host": "$(cat $CONFIG_DIR/.domain 2>/dev/null || get_server_ip)"
    }
}
EOF
    
    # Create systemd service
    cat > "/etc/systemd/system/trojan-go.service" << EOF
[Unit]
Description=Trojan-Go Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable trojan-go
    systemctl start trojan-go
    
    # Save configuration
    cat > "$CONFIG_DIR/trojan.conf" << EOF
TROJAN_PORT=$trojan_port
TROJAN_PASSWORD=$trojan_password
EOF
    
    log_message "INFO" "Trojan-Go installed on port $trojan_port"
}

install_openvpn() {
    echo -e "${YELLOW}Installing OpenVPN...${NC}"
    
    # Install OpenVPN
    case $PACKAGE_MANAGER in
        apt)
            apt install -y openvpn easy-rsa
            ;;
        pkg)
            pkg install -y openvpn
            ;;
    esac
    
    # Setup Easy-RSA
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Configure Easy-RSA
    cat > vars << 'EOF'
export KEY_COUNTRY="US"
export KEY_PROVINCE="State"
export KEY_CITY="City"
export KEY_ORG="SAID_TECH"
export KEY_EMAIL="admin@saidtech.com"
export KEY_OU="IT"
export KEY_NAME="server"
EOF
    
    source vars
    ./clean-all
    ./build-ca --batch
    ./build-key-server --batch server
    ./build-dh
    openvpn --genkey --secret keys/ta.key
    
    local ovpn_port_tcp=$(generate_random_port 1194 1200)
    local ovpn_port_udp=$(generate_random_port 1194 1200)
    
    # Create OpenVPN server configurations
    cat > "/etc/openvpn/server-tcp.conf" << EOF
port $ovpn_port_tcp
proto tcp
dev tun
ca easy-rsa/keys/ca.crt
cert easy-rsa/keys/server.crt
key easy-rsa/keys/server.key
dh easy-rsa/keys/dh2048.pem
tls-auth easy-rsa/keys/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status-tcp.log
log openvpn-tcp.log
verb 3
EOF
    
    cat > "/etc/openvpn/server-udp.conf" << EOF
port $ovpn_port_udp
proto udp
dev tun
ca easy-rsa/keys/ca.crt
cert easy-rsa/keys/server.crt
key easy-rsa/keys/server.key
dh easy-rsa/keys/dh2048.pem
tls-auth easy-rsa/keys/ta.key 0
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status-udp.log
log openvpn-udp.log
verb 3
EOF
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Start OpenVPN services
    systemctl enable openvpn@server-tcp
    systemctl enable openvpn@server-udp
    systemctl start openvpn@server-tcp
    systemctl start openvpn@server-udp
    
    # Save configuration
    cat > "$CONFIG_DIR/openvpn.conf" << EOF
OVPN_TCP_PORT=$ovpn_port_tcp
OVPN_UDP_PORT=$ovpn_port_udp
EOF
    
    log_message "INFO" "OpenVPN installed on ports TCP($ovpn_port_tcp), UDP($ovpn_port_udp)"
}

install_slowdns() {
    echo -e "${YELLOW}Installing SlowDNS...${NC}"
    
    # Clone and compile SlowDNS
    cd /tmp
    git clone https://github.com/kumparan/slow-dns.git
    cd slow-dns
    make
    cp slowdns /usr/local/bin/
    chmod +x /usr/local/bin/slowdns
    
    local dns_port=53
    local ns_domain
    ns_domain=$(whiptail --inputbox "Enter your NS domain (e.g., ns.yourdomain.com):" 10 60 3>&1 1>&2 2>&3)
    
    if [[ -z "$ns_domain" ]]; then
        ns_domain="ns.$(cat $CONFIG_DIR/.domain 2>/dev/null || echo "saidtech.local")"
    fi
    
    # Create SlowDNS service
    cat > "/etc/systemd/system/slowdns.service" << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/slowdns -udp 8.8.8.8:53 -pubkey-file /etc/slowdns/server.pub -privkey-file /etc/slowdns/server.key
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Generate keys
    mkdir -p /etc/slowdns
    /usr/local/bin/slowdns -gen-key -privkey-file /etc/slowdns/server.key -pubkey-file /etc/slowdns/server.pub
    
    systemctl daemon-reload
    systemctl enable slowdns
    systemctl start slowdns
    
    # Save configuration
    cat > "$CONFIG_DIR/slowdns.conf" << EOF
DNS_PORT=$dns_port
NS_DOMAIN=$ns_domain
PUBKEY=$(cat /etc/slowdns/server.pub)
EOF
    
    log_message "INFO" "SlowDNS installed with NS domain: $ns_domain"
}

install_psiphon3() {
    echo -e "${YELLOW}Installing Psiphon3 configuration generator...${NC}"
    
    # Create Psiphon3 config generator
    cat > "$INSTALL_DIR/psiphon_generator.py" << 'EOF'
#!/usr/bin/env python3
import json
import base64
import random
import string

class PsiphonConfigGenerator:
    def __init__(self):
        self.config_template = {
            "ClientVersion": "1",
            "SponsorId": "FFFFFFFFFFFFFFFF",
            "PropagationChannelId": "FFFFFFFFFFFFFFFF"
        }
    
    def generate_config(self, server_ip, ssh_port=22, obfuscated_ssh_port=None):
        config = self.config_template.copy()
        
        # Add server entries
        servers = []
        
        # Regular SSH
        servers.append({
            "ipAddress": server_ip,
            "portNumber": ssh_port,
            "protocol": "SSH",
            "sshUsername": "root",
            "sshPassword": "",
            "sshHostKey": ""
        })
        
        # Obfuscated SSH if available
        if obfuscated_ssh_port:
            servers.append({
                "ipAddress": server_ip,
                "portNumber": obfuscated_ssh_port,
                "protocol": "OSSH",
                "sshUsername": "root",
                "sshPassword": "",
                "sshHostKey": "",
                "sshObfuscatedKey": self.generate_obfuscated_key()
            })
        
        config["ServerList"] = servers
        return json.dumps(config, indent=2)
    
    def generate_obfuscated_key(self):
        return base64.b64encode(''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()).decode()

if __name__ == "__main__":
    generator = PsiphonConfigGenerator()
    config = generator.generate_config("SERVER_IP", 22, 2222)
    print(config)
EOF
    
    chmod +x "$INSTALL_DIR/psiphon_generator.py"
    
    log_message "INFO" "Psiphon3 configuration generator installed"
}

# Firewall and security functions
configure_firewall() {
    echo -e "${YELLOW}Configuring firewall rules...${NC}"
    
    # Install ufw if not present
    if ! command -v ufw >/dev/null 2>&1; then
        apt install -y ufw
    fi
    
    # Reset firewall
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow 22/tcp
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow VPN ports from config files
    if [[ -f "$CONFIG_DIR/v2ray_ports.conf" ]]; then
        source "$CONFIG_DIR/v2ray_ports.conf"
        ufw allow "$VMESS_PORT"/tcp
        ufw allow "$VLESS_PORT"/tcp
        ufw allow "$TROJAN_PORT"/tcp
    fi
    
    if [[ -f "$CONFIG_DIR/ssh_ports.conf" ]]; then
        source "$CONFIG_DIR/ssh_ports.conf"
        [[ -n "$SSH_WS_PORT" ]] && ufw allow "$SSH_WS_PORT"/tcp
        [[ -n "$SSH_SSL_PORT" ]] && ufw allow "$SSH_SSL_PORT"/tcp
    fi
    
    if [[ -f "$CONFIG_DIR/shadowsocks.conf" ]]; then
        source "$CONFIG_DIR/shadowsocks.conf"
        ufw allow "$SS_PORT"/tcp
        ufw allow "$SS_PORT"/udp
    fi
    
    if [[ -f "$CONFIG_DIR/openvpn.conf" ]]; then
        source "$CONFIG_DIR/openvpn.conf"
        ufw allow "$OVPN_TCP_PORT"/tcp
        ufw allow "$OVPN_UDP_PORT"/udp
    fi
    
    # Enable firewall
    ufw --force enable
    
    log_message "INFO" "Firewall configured successfully"
}

setup_fail2ban() {
    echo -e "${YELLOW}Setting up Fail2ban...${NC}"
    
    # Configure SSH protection
    cat > "/etc/fail2ban/jail.local" << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-dos]
enabled = true
filter = nginx-dos
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 10
findtime = 60
bantime = 600
EOF
    
    # Create nginx DOS filter
    cat > "/etc/fail2ban/filter.d/nginx-dos.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" (404|444) .*$
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_message "INFO" "Fail2ban configured and started"
}

# User management functions
create_user() {
    local username=$1
    local protocol=$2
    local expires_days=${3:-30}
    local max_connections=${4:-2}
    
    local password=$(openssl rand -base64 12)
    local expires_at=$(date -d "+$expires_days days" '+%Y-%m-%d %H:%M:%S')
    
    # Insert user into database
    sqlite3 "$DB_FILE" "INSERT INTO users (username, password, protocol, expires_at, max_connections) 
                       VALUES ('$username', '$password', '$protocol', '$expires_at', $max_connections);"
    
    log_message "INFO" "User $username created for protocol $protocol"
    echo "$password"
}

delete_user() {
    local username=$1
    
    sqlite3 "$DB_FILE" "DELETE FROM users WHERE username='$username';"
    
    log_message "INFO" "User $username deleted"
}

list_users() {
    sqlite3 -header -column "$DB_FILE" "SELECT username, protocol, created_at, expires_at, is_active FROM users ORDER BY created_at DESC;"
}

# Configuration generators
generate_client_config() {
    local username=$1
    local protocol=$2
    local server_ip=$(get_server_ip)
    local domain=$(cat "$CONFIG_DIR/.domain" 2>/dev/null || echo "$server_ip")
    
    local config_file="$CONFIG_DIR/clients/${username}_${protocol}.conf"
    mkdir -p "$CONFIG_DIR/clients"
    
    case $protocol in
        "v2ray")
            generate_v2ray_client_config "$username" "$config_file" "$domain"
            ;;
        "ssh")
            generate_ssh_client_config "$username" "$config_file" "$domain"
            ;;
        "shadowsocks")
            generate_shadowsocks_client_config "$username" "$config_file" "$domain"
            ;;
        "openvpn")
            generate_openvpn_client_config "$username" "$config_file" "$domain"
            ;;
    esac
    
    echo "$config_file"
}

generate_v2ray_client_config() {
    local username=$1
    local config_file=$2
    local domain=$3
    
    source "$CONFIG_DIR/v2ray_ports.conf"
    local uuid=$(uuidgen)
    
    # Add user to V2Ray config
    python3 << EOF
import json
import uuid

# Read existing config
with open('/usr/local/etc/v2ray/config.json', 'r') as f:
    config = json.load(f)

# Add user to VMess inbound
for inbound in config['inbounds']:
    if inbound['tag'] == 'vmess-in':
        inbound['settings']['clients'].append({
            'id': '$uuid',
            'email': '$username'
        })

# Write updated config
with open('/usr/local/etc/v2ray/config.json', 'w') as f:
    json.dump(config, f, indent=2)
EOF
    
    # Generate client configuration
    cat > "$config_file" << EOF
{
    "v": "2",
    "ps": "SAID_TECH-$username",
    "add": "$domain",
    "port": "$VMESS_PORT",
    "id": "$uuid",
    "aid": "0",
    "net": "tcp",
    "type": "none",
    "host": "",
    "path": "",
    "tls": "tls"
}
EOF
    
    systemctl restart v2ray
}

# System status and monitoring
create_service_status_page() {
    local status_file="$WEB_DIR/status.html"
    
    cat > "$status_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SAID_TÉCH PREMIUM INTERNET - Service Status</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .header { text-align: center; margin-bottom: 30px; }
        .brand { color: #00ff00; font-size: 24px; font-weight: bold; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .service-card { background: #2a2a2a; padding: 20px; border-radius: 10px; border-left: 4px solid #00ff00; }
        .service-name { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .service-status { padding: 5px 10px; border-radius: 5px; font-size: 14px; }
        .status-running { background: #00aa00; }
        .status-stopped { background: #aa0000; }
        .footer { text-align: center; margin-top: 30px; color: #888; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">SAID_TÉCH PREMIUM INTERNET</div>
        <div>Powered by joshuasaid.tech</div>
    </div>
    
    <div class="status-grid" id="services">
        <!-- Services will be loaded here -->
    </div>
    
    <div class="footer">
        <p>Last updated: <span id="lastUpdate"></span></p>
        <p>Server: <span id="serverInfo"></span></p>
    </div>

    <script>
        function updateStatus() {
            // This would be populated by a backend script
            const services = [
                {name: 'V2Ray', status: 'running', port: '10443'},
                {name: 'SSH WebSocket', status: 'running', port: '8080'},
                {name: 'Shadowsocks', status: 'running', port: '8388'},
                {name: 'OpenVPN TCP', status: 'running', port: '1194'},
                {name: 'OpenVPN UDP', status: 'running', port: '1195'},
                {name: 'Trojan-Go', status: 'running', port: '443'},
                {name: 'SlowDNS', status: 'running', port: '53'},
                {name: 'Nginx', status: 'running', port: '80/443'}
            ];
            
            const container = document.getElementById('services');
            container.innerHTML = '';
            
            services.forEach(service => {
                const card = document.createElement('div');
                card.className = 'service-card';
                card.innerHTML = `
                    <div class="service-name">${service.name}</div>
                    <div class="service-status status-${service.status}">${service.status.toUpperCase()}</div>
                    <div>Port: ${service.port}</div>
                `;
                container.appendChild(card);
            });
            
            document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
        }
        
        updateStatus();
        setInterval(updateStatus, 30000); // Update every 30 seconds
    </script>
</body>
</html>
EOF
}

# Menu functions
user_management_menu() {
    while true; do
        choice=$(whiptail --title "User Management" --menu \
            "Select an option:" 15 70 8 \
            "1" "Add New User" \
            "2" "Delete User" \
            "3" "List All Users" \
            "4" "Generate Client Config" \
            "5" "View User Statistics" \
            "6" "Extend User Expiry" \
            "7" "Reset User Password" \
            "8" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) add_user_interactive ;;
            2) delete_user_interactive ;;
            3) list_users_interactive ;;
            4) generate_config_interactive ;;
            5) show_user_statistics ;;
            6) extend_user_expiry ;;
            7) reset_user_password ;;
            8) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

# Continue with remaining menu functions and utilities...