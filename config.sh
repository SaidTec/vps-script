#!/bin/bash

#################################################################################
#                         SAID_TÉCH VPN Installer Configuration                #
#                          Default settings and variables                      #
#################################################################################

# System configuration
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Default ports configuration
DEFAULT_PORTS=(
    "SSH_PORT=22"
    "SSH_WS_PORT=8080"
    "SSH_SSL_PORT=443"
    "V2RAY_VMESS_PORT=10443"
    "V2RAY_VLESS_PORT=10080"
    "V2RAY_TROJAN_PORT=10000"
    "SHADOWSOCKS_PORT=8388"
    "TROJAN_GO_PORT=8443"
    "OPENVPN_TCP_PORT=1194"
    "OPENVPN_UDP_PORT=1195"
    "SLOWDNS_PORT=53"
    "NGINX_HTTP_PORT=80"
    "NGINX_HTTPS_PORT=443"
)

# Server configuration
SERVER_CONFIG=(
    "MAX_USERS=100"
    "DEFAULT_USER_EXPIRY_DAYS=30"
    "MAX_CONNECTIONS_PER_USER=2"
    "BANDWIDTH_LIMIT_MB=0"  # 0 = unlimited
    "AUTO_BACKUP_ENABLED=true"
    "BACKUP_RETENTION_DAYS=7"
    "LOG_RETENTION_DAYS=30"
    "SSL_AUTO_RENEWAL=true"
)

# DNS and CDN configuration
DNS_CONFIG=(
    "PRIMARY_DNS=1.1.1.1"
    "SECONDARY_DNS=8.8.8.8"
    "CLOUDFLARE_DNS=1.1.1.1"
    "QUAD9_DNS=9.9.9.9"
    "OPENDNS=208.67.222.222"
)

CDN_CONFIG=(
    "CLOUDFLARE_API_URL=https://api.cloudflare.com/client/v4"
    "CDN_ENABLED=false"
    "DOMAIN_FRONTING=false"
    "SNI_HOST=www.cloudflare.com"
    "HOST_HEADER=www.speedtest.net"
)

# Free internet optimizations
FREE_INTERNET_HOSTS=(
    "www.speedtest.net"
    "fast.com"
    "www.whatismyip.com"
    "ipinfo.io"
    "httpbin.org"
    "detectportal.firefox.com"
    "connectivitycheck.gstatic.com"
    "clients3.google.com"
    "www.msftncsi.com"
    "www.apple.com"
)

SNI_BYPASS_HOSTS=(
    "www.cloudflare.com"
    "cdnjs.cloudflare.com"
    "ajax.googleapis.com"
    "fonts.googleapis.com"
    "www.gstatic.com"
    "ssl.gstatic.com"
    "www.google.com"
    "developers.facebook.com"
    "graph.facebook.com"
    "www.youtube.com"
    "i.ytimg.com"
)

# ISP-specific configurations
ISP_CONFIGS=(
    # Safaricom Kenya
    "SAFARICOM_APN=safaricom"
    "SAFARICOM_SNI=www.safaricom.co.ke"
    "SAFARICOM_HOST=zero.facebook.com"
    
    # Airtel
    "AIRTEL_APN=internet"
    "AIRTEL_SNI=www.airtel.com"
    "AIRTEL_HOST=web.facebook.com"
    
    # MTN
    "MTN_APN=internet"
    "MTN_SNI=www.mtn.com"
    "MTN_HOST=0.facebook.com"
    
    # Vodacom
    "VODACOM_APN=internet"
    "VODACOM_SNI=www.vodacom.co.za"
    "VODACOM_HOST=m.facebook.com"
)

# Protocol-specific configurations
V2RAY_CONFIG=(
    "VMESS_ENCRYPTION=auto"
    "VMESS_SECURITY=aes-128-gcm"
    "VLESS_ENCRYPTION=none"
    "TROJAN_PASSWORD_LENGTH=32"
    "WS_PATH=/v2ray"
    "GRPC_PATH=/v2raygrpc"
    "CDN_WS_PATH=/cdnws"
)

SSH_CONFIG=(
    "SSH_COMPRESSION=yes"
    "SSH_KEEPALIVE=yes"
    "SSH_PROTOCOL_VERSION=2"
    "WS_CDN_PATH=/ssh-ws"
    "SSL_SNI_HOST=bug.com"
    "OBFUSCATION_METHOD=tls1.2_ticket_auth"
)

SHADOWSOCKS_CONFIG=(
    "SS_METHOD=aes-256-gcm"
    "SS_TIMEOUT=300"
    "SS_FAST_OPEN=true"
    "SS_NO_DELAY=true"
    "SS_PLUGIN=v2ray-plugin"
    "SS_PLUGIN_OPTS=server;tls;host=cloudflare.com"
)

OPENVPN_CONFIG=(
    "OVPN_PROTOCOL_TCP=tcp"
    "OVPN_PROTOCOL_UDP=udp"
    "OVPN_CIPHER=AES-256-CBC"
    "OVPN_AUTH=SHA256"
    "OVPN_TLS_VERSION=1.2"
    "OVPN_COMPRESSION=lz4"
    "OVPN_TOPOLOGY=subnet"
)

TROJAN_CONFIG=(
    "TROJAN_PROTOCOL=trojan-go"
    "TROJAN_WEBSOCKET=true"
    "TROJAN_SHADOWSOCKS=true"
    "TROJAN_ROUTER=true"
    "TROJAN_CDN_HOST=cloudflare.com"
)

# User interface configuration
UI_CONFIG=(
    "MENU_TIMEOUT=30"
    "AUTO_SCROLL=true"
    "COLOR_SCHEME=dark"
    "SHOW_BANNER=true"
    "PROGRESS_BAR=true"
    "CONFIRMATION_PROMPTS=true"
)

# Security configuration
SECURITY_CONFIG=(
    "FAIL2BAN_ENABLED=true"
    "FAIL2BAN_MAX_RETRY=3"
    "FAIL2BAN_BAN_TIME=3600"
    "UFW_ENABLED=true"
    "SSH_KEY_AUTH=false"
    "ROOT_LOGIN=true"
    "PASSWORD_AUTH=true"
    "RATE_LIMITING=true"
)

# Monitoring configuration
MONITORING_CONFIG=(
    "BANDWIDTH_MONITORING=true"
    "CONNECTION_LOGGING=true"
    "PERFORMANCE_MONITORING=true"
    "DISK_USAGE_ALERT=80"
    "MEMORY_USAGE_ALERT=85"
    "CPU_USAGE_ALERT=90"
    "LOG_ROTATION=true"
)

# Database configuration
DATABASE_CONFIG=(
    "DB_TYPE=sqlite"
    "DB_NAME=saidtech_vpn"
    "DB_USER=saidtech"
    "DB_BACKUP_INTERVAL=daily"
    "DB_COMPRESSION=gzip"
    "CONNECTION_POOL_SIZE=10"
)

# Telegram bot configuration
TELEGRAM_CONFIG=(
    "BOT_ENABLED=false"
    "BOT_TOKEN="
    "ADMIN_CHAT_ID="
    "WEBHOOK_ENABLED=false"
    "COMMANDS_ENABLED=true"
    "USER_MANAGEMENT=true"
    "NOTIFICATIONS=true"
)

# API configuration
API_CONFIG=(
    "API_ENABLED=false"
    "API_PORT=3000"
    "API_AUTH=bearer"
    "API_RATE_LIMIT=100"
    "API_CORS=true"
    "API_HTTPS=true"
    "API_DOCS=true"
)

# Backup configuration
BACKUP_CONFIG=(
    "BACKUP_ENABLED=true"
    "BACKUP_LOCATION=/var/backups/saidtech"
    "REMOTE_BACKUP=false"
    "BACKUP_ENCRYPTION=true"
    "BACKUP_COMPRESSION=gzip"
    "GITHUB_BACKUP=false"
    "GOOGLE_DRIVE_BACKUP=false"
)

# Update configuration
UPDATE_CONFIG=(
    "AUTO_UPDATE=false"
    "UPDATE_CHANNEL=stable"
    "UPDATE_CHECK_INTERVAL=daily"
    "BACKUP_BEFORE_UPDATE=true"
    "ROLLBACK_ENABLED=true"
    "NOTIFY_UPDATES=true"
)

# Web interface configuration
WEB_CONFIG=(
    "WEB_ENABLED=true"
    "WEB_PORT=8000"
    "WEB_THEME=dark"
    "WEB_AUTH=basic"
    "WEB_SSL=true"
    "WEB_COMPRESSION=true"
    "WEB_CACHING=true"
)

# Load configuration from files
load_config() {
    local config_file="$CONFIG_DIR/saidtech.conf"
    
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        log_message "INFO" "Configuration loaded from $config_file"
    else
        create_default_config
    fi
}

# Create default configuration file
create_default_config() {
    local config_file="$CONFIG_DIR/saidtech.conf"
    
    cat > "$config_file" << 'EOF'
# SAID_TÉCH VPN Server Configuration
# Generated automatically - modify with caution

# Server information
SERVER_NAME="SAID_TÉCH PREMIUM INTERNET"
SERVER_LOCATION="Cloud VPS"
ADMIN_EMAIL="admin@saidtech.com"
SUPPORT_URL="https://joshuasaid.tech"

# Feature flags
ENABLE_V2RAY=true
ENABLE_SSH_WS=true
ENABLE_SSH_SSL=true
ENABLE_SHADOWSOCKS=true
ENABLE_TROJAN_GO=true
ENABLE_OPENVPN=true
ENABLE_SLOWDNS=true
ENABLE_PSIPHON=true

# Free internet features
ENABLE_SNI_BYPASS=true
ENABLE_DOMAIN_FRONTING=true
ENABLE_HOST_ROTATION=true
ENABLE_CDN_INTEGRATION=true

# User management
DEFAULT_USER_LIMIT=30
MAX_USERS_TOTAL=100
USER_BANDWIDTH_LIMIT=0
USER_CONNECTION_LIMIT=2

# Security settings
ENABLE_FIREWALL=true
ENABLE_FAIL2BAN=true
ENABLE_DDoS_PROTECTION=true
ENABLE_RATE_LIMITING=true

# Monitoring and logging
ENABLE_LOGGING=true
ENABLE_MONITORING=true
ENABLE_ALERTS=true
LOG_LEVEL=INFO

# Backup and updates
ENABLE_AUTO_BACKUP=true
ENABLE_AUTO_UPDATE=false
BACKUP_RETENTION_DAYS=7

# Web interface
ENABLE_WEB_UI=true
WEB_THEME=dark
ENABLE_API=false

# Telegram integration
ENABLE_TELEGRAM_BOT=false
TELEGRAM_BOT_TOKEN=""
TELEGRAM_ADMIN_ID=""

# CDN and DNS
CLOUDFLARE_API_KEY=""
CLOUDFLARE_EMAIL=""
CLOUDFLARE_ZONE_ID=""
EOF
    
    chmod 600 "$config_file"
    log_message "INFO" "Default configuration created at $config_file"
}

# Save current configuration
save_config() {
    local config_file="$CONFIG_DIR/saidtech.conf"
    local backup_file="$BACKUP_DIR/saidtech.conf.$(date +%Y%m%d_%H%M%S)"
    
    # Backup existing config
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "$backup_file"
    fi
    
    # Save new configuration
    cat > "$config_file" << EOF
# SAID_TÉCH VPN Server Configuration
# Last updated: $(date)

# Server information
SERVER_NAME="$SERVER_NAME"
SERVER_LOCATION="$SERVER_LOCATION"
ADMIN_EMAIL="$ADMIN_EMAIL"
SUPPORT_URL="$SUPPORT_URL"

# Current configuration values
$(env | grep -E '^(ENABLE_|DEFAULT_|MAX_|SERVER_|ADMIN_|SUPPORT_)' | sort)
EOF
    
    log_message "INFO" "Configuration saved to $config_file"
}

# Protocol port assignments
assign_ports() {
    local used_ports=()
    
    # Get currently used ports
    while read -r line; do
        if [[ $line =~ :([0-9]+) ]]; then
            used_ports+=("${BASH_REMATCH[1]}")
        fi
    done < <(netstat -tlnp 2>/dev/null)
    
    # Assign available ports for each protocol
    for protocol in "${!DEFAULT_PORTS[@]}"; do
        local port_var="${DEFAULT_PORTS[$protocol]}"
        local port_name="${port_var%=*}"
        local default_port="${port_var#*=}"
        
        if [[ " ${used_ports[*]} " =~ " ${default_port} " ]]; then
            # Port is in use, find alternative
            local new_port=$(generate_random_port 1024 65535)
            export "$port_name=$new_port"
            log_message "WARN" "Port $default_port in use, assigned $new_port for $port_name"
        else
            export "$port_name=$default_port"
        fi
    done
}

# Initialize configuration
init_config() {
    log_message "INFO" "Initializing configuration system"
    
    # Create configuration directories
    mkdir -p "$CONFIG_DIR/protocols"
    mkdir -p "$CONFIG_DIR/users"
    mkdir -p "$CONFIG_DIR/ssl"
    mkdir -p "$CONFIG_DIR/clients"
    mkdir -p "$CONFIG_DIR/templates"
    
    # Load or create configuration
    load_config
    
    # Assign ports
    assign_ports
    
    # Initialize database
    setup_database
    
    # Create configuration templates
    create_config_templates
    
    log_message "INFO" "Configuration initialization completed"
}

# Create configuration templates
create_config_templates() {
    local template_dir="$CONFIG_DIR/templates"
    
    # V2Ray VMess template
    cat > "$template_dir/vmess.json" << 'EOF'
{
    "v": "2",
    "ps": "SAID_TECH-VMESS-{{USERNAME}}",
    "add": "{{SERVER_IP}}",
    "port": "{{VMESS_PORT}}",
    "id": "{{UUID}}",
    "aid": "0",
    "net": "tcp",
    "type": "none",
    "host": "",
    "path": "",
    "tls": "tls",
    "sni": "{{SNI_HOST}}"
}
EOF

    # SSH WebSocket template
    cat > "$template_dir/ssh_ws.json" << 'EOF'
{
    "name": "SAID_TECH SSH-WS {{USERNAME}}",
    "server": "{{SERVER_IP}}",
    "port": {{SSH_WS_PORT}},
    "type": "ssh",
    "username": "{{USERNAME}}",
    "password": "{{PASSWORD}}",
    "websocket": {
        "enabled": true,
        "path": "/ssh-ws",
        "headers": {
            "Host": "{{CDN_HOST}}"
        }
    }
}
EOF

    # Shadowsocks template
    cat > "$template_dir/shadowsocks.json" << 'EOF'
{
    "server": "{{SERVER_IP}}",
    "server_port": {{SS_PORT}},
    "password": "{{SS_PASSWORD}}",
    "method": "{{SS_METHOD}}",
    "plugin": "v2ray-plugin",
    "plugin_opts": "tls;host={{CDN_HOST}};path=/ss-ws",
    "remarks": "SAID_TECH-SS-{{USERNAME}}"
}
EOF

    # OpenVPN template
    cat > "$template_dir/openvpn.ovpn" << 'EOF'
# SAID_TECH OpenVPN Configuration
# User: {{USERNAME}}
# Generated: {{DATE}}

client
dev tun
proto {{PROTOCOL}}
remote {{SERVER_IP}} {{PORT}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3

<ca>
{{CA_CERT}}
</ca>

<cert>
{{CLIENT_CERT}}
</cert>

<key>
{{CLIENT_KEY}}
</key>

<tls-auth>
{{TLS_AUTH}}
</tls-auth>
key-direction 1
EOF

    # Trojan-Go template
    cat > "$template_dir/trojan.json" << 'EOF'
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "{{SERVER_IP}}",
    "remote_port": {{TROJAN_PORT}},
    "password": ["{{TROJAN_PASSWORD}}"],
    "ssl": {
        "verify": false,
        "verify_hostname": false,
        "fingerprint": "",
        "sni": "{{SNI_HOST}}"
    },
    "websocket": {
        "enabled": true,
        "path": "/trojan",
        "host": "{{CDN_HOST}}"
    }
}
EOF

    log_message "INFO" "Configuration templates created"
}

# Environment setup
setup_environment() {
    # Set locale
    export LC_ALL=C.UTF-8
    export LANG=C.UTF-8
    
    # Set timezone
    if [[ -f /etc/timezone ]]; then
        export TZ=$(cat /etc/timezone)
    else
        export TZ=UTC
    fi
    
    # Create required users/groups
    if ! getent group saidtech >/dev/null; then
        groupadd saidtech
    fi
    
    if ! getent passwd saidtech >/dev/null; then
        useradd -r -g saidtech -s /bin/false -d "$INSTALL_DIR" saidtech
    fi
    
    # Set file permissions
    chown -R saidtech:saidtech "$CONFIG_DIR"
    chown -R saidtech:saidtech "$LOG_DIR"
    
    log_message "INFO" "Environment setup completed"
}

# Feature detection
detect_features() {
    # Check for systemd
    if command -v systemctl >/dev/null 2>&1; then
        export HAS_SYSTEMD=true
    else
        export HAS_SYSTEMD=false
    fi
    
    # Check for Docker
    if command -v docker >/dev/null 2>&1; then
        export HAS_DOCKER=true
    else
        export HAS_DOCKER=false
    fi
    
    # Check for IPv6
    if [[ -f /proc/net/if_inet6 ]]; then
        export HAS_IPV6=true
    else
        export HAS_IPV6=false
    fi
    
    # Check available memory
    local mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    export MEMORY_MB=$((mem_total / 1024))
    
    # Check available disk space
    local disk_available=$(df "$INSTALL_DIR" | awk 'NR==2 {print $4}' 2>/dev/null || echo "0")
    export DISK_AVAILABLE_MB=$((disk_available / 1024))
    
    # Check CPU cores
    export CPU_CORES=$(nproc 2>/dev/null || echo "1")
    
    log_message "INFO" "Feature detection completed: systemd=$HAS_SYSTEMD, ipv6=$HAS_IPV6, memory=${MEMORY_MB}MB, cores=$CPU_CORES"
}

# Validate configuration
validate_config() {
    local errors=()
    
    # Check required directories
    for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR"; do
        if [[ ! -d "$dir" ]]; then
            errors+=("Directory $dir does not exist")
        fi
    done
    
    # Check port conflicts
    local ports=(22 80 443)
    for port in "${ports[@]}"; do
        if check_port "$port"; then
            errors+=("Critical port $port is already in use")
        fi
    done
    
    # Check disk space (minimum 1GB)
    if [[ $DISK_AVAILABLE_MB -lt 1024 ]]; then
        errors+=("Insufficient disk space: ${DISK_AVAILABLE_MB}MB available, minimum 1GB required")
    fi
    
    # Check memory (minimum 512MB)
    if [[ $MEMORY_MB -lt 512 ]]; then
        errors+=("Insufficient memory: ${MEMORY_MB}MB available, minimum 512MB recommended")
    fi
    
    # Report errors
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_message "ERROR" "Configuration validation failed:"
        for error in "${errors[@]}"; do
            log_message "ERROR" "  - $error"
        done
        return 1
    fi
    
    log_message "INFO" "Configuration validation passed"
    return 0
}

# Export all configuration functions
export -f load_config save_config init_config validate_config
export -f create_default_config create_config_templates
export -f setup_environment detect_features assign_ports

# Initialize configuration when sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    detect_features
    setup_environment
fi