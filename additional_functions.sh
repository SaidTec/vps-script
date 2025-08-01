#!/bin/bash

#################################################################################
#                    SAID_TÉCH VPN Additional Functions Module                 #
#                 Interactive menus, optimizations, and features               #
#################################################################################

# Interactive user management functions
add_user_interactive() {
    local username protocol expires_days max_connections
    
    username=$(whiptail --inputbox "Enter username:" 10 60 3>&1 1>&2 2>&3)
    if [[ -z "$username" ]]; then
        whiptail --msgbox "Username cannot be empty" 8 50
        return 1
    fi
    
    protocol=$(whiptail --menu "Select protocol:" 15 60 8 \
        "v2ray" "V2Ray (VMess/VLess/Trojan)" \
        "ssh" "SSH WebSocket" \
        "shadowsocks" "Shadowsocks" \
        "openvpn" "OpenVPN" \
        "trojan" "Trojan-Go" \
        "all" "All Protocols" 3>&1 1>&2 2>&3)
    
    expires_days=$(whiptail --inputbox "Expiry (days):" 10 60 "30" 3>&1 1>&2 2>&3)
    max_connections=$(whiptail --inputbox "Max connections:" 10 60 "2" 3>&1 1>&2 2>&3)
    
    local password=$(create_user "$username" "$protocol" "$expires_days" "$max_connections")
    
    if [[ $? -eq 0 ]]; then
        whiptail --msgbox "User '$username' created successfully!\nPassword: $password\nExpires in $expires_days days" 12 60
        
        if whiptail --yesno "Generate client configuration?" 8 50; then
            generate_config_interactive "$username" "$protocol"
        fi
    else
        whiptail --msgbox "Failed to create user '$username'" 8 50
    fi
}

delete_user_interactive() {
    local users_list
    users_list=$(sqlite3 "$DB_FILE" "SELECT username FROM users WHERE is_active=1;" | tr '\n' ' ')
    
    if [[ -z "$users_list" ]]; then
        whiptail --msgbox "No active users found" 8 50
        return 1
    fi
    
    local menu_items=()
    while read -r username; do
        [[ -n "$username" ]] && menu_items+=("$username" "Delete user $username")
    done <<< "$(echo "$users_list" | tr ' ' '\n')"
    
    local selected_user
    selected_user=$(whiptail --menu "Select user to delete:" 15 60 8 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    
    if [[ -n "$selected_user" ]]; then
        if whiptail --yesno "Are you sure you want to delete user '$selected_user'?" 8 60; then
            delete_user "$selected_user"
            whiptail --msgbox "User '$selected_user' deleted successfully" 8 50
        fi
    fi
}

list_users_interactive() {
    local users_file="/tmp/users_list.txt"
    
    cat > "$users_file" << EOF
SAID_TÉCH PREMIUM INTERNET - User List
=====================================

$(list_users)

Active Users: $(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users WHERE is_active=1;")
Total Users: $(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users;")
Expired Users: $(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users WHERE expires_at < datetime('now');")

Last Updated: $(date)
EOF
    
    whiptail --textbox "$users_file" 20 80
    rm -f "$users_file"
}

generate_config_interactive() {
    local username=${1:-}
    local protocol=${2:-}
    
    if [[ -z "$username" ]]; then
        username=$(whiptail --inputbox "Enter username:" 10 60 3>&1 1>&2 2>&3)
    fi
    
    if [[ -z "$protocol" ]]; then
        protocol=$(whiptail --menu "Select protocol:" 15 60 6 \
            "v2ray" "V2Ray Configuration" \
            "ssh" "SSH Configuration" \
            "shadowsocks" "Shadowsocks Configuration" \
            "openvpn" "OpenVPN Configuration" \
            "trojan" "Trojan-Go Configuration" 3>&1 1>&2 2>&3)
    fi
    
    local config_file
    config_file=$(generate_client_config "$username" "$protocol")
    
    if [[ -f "$config_file" ]]; then
        whiptail --msgbox "Configuration generated: $config_file" 8 60
        
        if whiptail --yesno "View configuration?" 8 50; then
            whiptail --textbox "$config_file" 20 80
        fi
        
        if whiptail --yesno "Upload to GitHub/Telegram?" 8 50; then
            upload_config_interactive "$config_file"
        fi
    else
        whiptail --msgbox "Failed to generate configuration" 8 50
    fi
}

# Free Internet Optimization Functions
setup_sni_bypass() {
    echo -e "${YELLOW}Setting up SNI bypass...${NC}"
    
    # Create SNI proxy
    cat > "$INSTALL_DIR/sni_proxy.py" << 'EOF'
#!/usr/bin/env python3
import asyncio
import socket
import ssl
import struct
import logging
from typing import Optional, Tuple

class SNIProxy:
    def __init__(self, listen_port: int = 443):
        self.listen_port = listen_port
        self.sni_hosts = [
            'www.cloudflare.com',
            'cdnjs.cloudflare.com',
            'ajax.googleapis.com',
            'fonts.googleapis.com',
            'www.gstatic.com',
            'ssl.gstatic.com'
        ]
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/saidtech/sni_proxy.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def extract_sni(self, data: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello"""
        try:
            if len(data) < 5:
                return None
            
            # Check if it's a TLS handshake
            if data[0] != 0x16:  # Handshake
                return None
            
            # Skip TLS record header
            pos = 5
            
            # Check handshake type (should be ClientHello = 1)
            if pos >= len(data) or data[pos] != 0x01:
                return None
            
            # Skip handshake header
            pos += 4
            
            # Skip client random
            pos += 32
            
            # Skip session ID
            if pos >= len(data):
                return None
            session_id_length = data[pos]
            pos += 1 + session_id_length
            
            # Skip cipher suites
            if pos + 1 >= len(data):
                return None
            cipher_suites_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_length
            
            # Skip compression methods
            if pos >= len(data):
                return None
            compression_methods_length = data[pos]
            pos += 1 + compression_methods_length
            
            # Extensions
            if pos + 1 >= len(data):
                return None
            extensions_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            while pos < len(data):
                if pos + 3 >= len(data):
                    break
                
                ext_type = struct.unpack('!H', data[pos:pos+2])[0]
                ext_length = struct.unpack('!H', data[pos+2:pos+4])[0]
                pos += 4
                
                if ext_type == 0:  # SNI extension
                    # Skip server name list length
                    pos += 2
                    # Skip name type
                    pos += 1
                    # Get name length
                    if pos + 1 >= len(data):
                        break
                    name_length = struct.unpack('!H', data[pos:pos+2])[0]
                    pos += 2
                    # Extract name
                    if pos + name_length <= len(data):
                        return data[pos:pos+name_length].decode('utf-8', errors='ignore')
                
                pos += ext_length
            
            return None
        except Exception:
            return None
    
    async def handle_connection(self, reader, writer):
        """Handle incoming connection with SNI manipulation"""
        try:
            # Read initial data to extract SNI
            data = await reader.read(4096)
            if not data:
                return
            
            original_sni = self.extract_sni(data)
            
            # Replace SNI with bypass host
            bypass_host = self.sni_hosts[hash(original_sni or '') % len(self.sni_hosts)]
            
            # Connect to actual server
            target_reader, target_writer = await asyncio.open_connection(
                bypass_host, 443, ssl=ssl.create_default_context()
            )
            
            # Forward initial data
            target_writer.write(data)
            await target_writer.drain()
            
            # Bidirectional forwarding
            await asyncio.gather(
                self.forward_data(reader, target_writer),
                self.forward_data(target_reader, writer)
            )
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def forward_data(self, reader, writer):
        """Forward data between connections"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
    
    async def start_server(self):
        """Start the SNI proxy server"""
        server = await asyncio.start_server(
            self.handle_connection, '0.0.0.0', self.listen_port
        )
        
        self.logger.info(f"SNI proxy listening on port {self.listen_port}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    proxy = SNIProxy(port)
    asyncio.run(proxy.start_server())
EOF
    
    chmod +x "$INSTALL_DIR/sni_proxy.py"
    
    # Create systemd service
    cat > "/etc/systemd/system/sni-proxy.service" << EOF
[Unit]
Description=SNI Bypass Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/sni_proxy.py 8443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sni-proxy
    systemctl start sni-proxy
    
    log_message "INFO" "SNI bypass proxy installed and started"
}

setup_domain_fronting() {
    echo -e "${YELLOW}Setting up domain fronting...${NC}"
    
    # Create domain fronting configuration
    cat > "$CONFIG_DIR/domain_fronting.conf" << 'EOF'
# Domain Fronting Configuration
# Maps real domains to CDN endpoints

# Cloudflare fronting
cloudflare.com -> www.cloudflare.com
cdnjs.cloudflare.com -> ajax.googleapis.com
ajax.googleapis.com -> fonts.googleapis.com

# Google fronting
www.google.com -> www.gstatic.com
fonts.googleapis.com -> ssl.gstatic.com
developers.google.com -> www.youtube.com

# Facebook fronting
www.facebook.com -> developers.facebook.com
graph.facebook.com -> web.facebook.com
0.facebook.com -> m.facebook.com

# Microsoft fronting
www.microsoft.com -> www.msftncsi.com
outlook.com -> login.microsoftonline.com
EOF
    
    # Create domain fronting proxy
    cat > "$INSTALL_DIR/domain_fronting.py" << 'EOF'
#!/usr/bin/env python3
import asyncio
import aiohttp
import random
import logging
from aiohttp import web, ClientSession, ClientTimeout

class DomainFrontingProxy:
    def __init__(self, port=8080):
        self.port = port
        self.fronting_map = {}
        self.load_fronting_config()
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/saidtech/domain_fronting.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_fronting_config(self):
        """Load domain fronting configuration"""
        config_file = '/etc/saidtech/configs/domain_fronting.conf'
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '->' in line:
                        original, fronted = [x.strip() for x in line.split('->')]
                        self.fronting_map[original] = fronted
        except FileNotFoundError:
            self.logger.warning("Domain fronting config not found")
    
    def get_fronted_domain(self, original_domain):
        """Get fronted domain for the original domain"""
        return self.fronting_map.get(original_domain, original_domain)
    
    async def proxy_request(self, request):
        """Proxy HTTP request with domain fronting"""
        try:
            # Extract original host
            original_host = request.headers.get('Host', '')
            fronted_host = self.get_fronted_domain(original_host)
            
            # Build target URL
            target_url = f"{request.scheme}://{fronted_host}{request.path_qs}"
            
            # Prepare headers
            headers = dict(request.headers)
            headers['Host'] = original_host  # Keep original host in headers
            headers.pop('Content-Length', None)
            
            # Create session with timeout
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    data=await request.read() if request.method in ['POST', 'PUT'] else None
                ) as response:
                    # Prepare response
                    response_headers = dict(response.headers)
                    response_headers.pop('Content-Encoding', None)
                    response_headers.pop('Transfer-Encoding', None)
                    
                    body = await response.read()
                    
                    return web.Response(
                        body=body,
                        status=response.status,
                        headers=response_headers
                    )
        
        except Exception as e:
            self.logger.error(f"Proxy error: {e}")
            return web.Response(text="Proxy Error", status=502)
    
    async def start_server(self):
        """Start the domain fronting proxy server"""
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', self.proxy_request)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        
        self.logger.info(f"Domain fronting proxy listening on port {self.port}")
        
        # Keep server running
        while True:
            await asyncio.sleep(3600)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    proxy = DomainFrontingProxy(port)
    asyncio.run(proxy.start_server())
EOF
    
    chmod +x "$INSTALL_DIR/domain_fronting.py"
    
    # Install aiohttp
    pip3 install aiohttp
    
    # Create systemd service
    cat > "/etc/systemd/system/domain-fronting.service" << EOF
[Unit]
Description=Domain Fronting Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/domain_fronting.py 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable domain-fronting
    systemctl start domain-fronting
    
    log_message "INFO" "Domain fronting proxy installed and started"
}

setup_host_rotation() {
    echo -e "${YELLOW}Setting up automatic host rotation...${NC}"
    
    # Create host rotation script
    cat > "$INSTALL_DIR/host_rotation.py" << 'EOF'
#!/usr/bin/env python3
import random
import time
import json
import sqlite3
import logging
from typing import List, Dict

class HostRotation:
    def __init__(self, db_path='/etc/saidtech/configs/users.db'):
        self.db_path = db_path
        self.rotation_interval = 300  # 5 minutes
        self.hosts = [
            'www.speedtest.net',
            'fast.com',
            'www.whatismyip.com',
            'ipinfo.io',
            'httpbin.org',
            'detectportal.firefox.com',
            'connectivitycheck.gstatic.com',
            'clients3.google.com'
        ]
        self.sni_hosts = [
            'www.cloudflare.com',
            'cdnjs.cloudflare.com',
            'ajax.googleapis.com',
            'fonts.googleapis.com',
            'www.gstatic.com',
            'ssl.gstatic.com'
        ]
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/saidtech/host_rotation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def get_random_host(self, host_type='normal'):
        """Get random host for rotation"""
        hosts = self.sni_hosts if host_type == 'sni' else self.hosts
        return random.choice(hosts)
    
    def update_v2ray_config(self):
        """Update V2Ray configuration with new hosts"""
        config_file = '/usr/local/etc/v2ray/config.json'
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Update SNI hosts in inbounds
            for inbound in config.get('inbounds', []):
                if 'streamSettings' in inbound:
                    stream = inbound['streamSettings']
                    if stream.get('network') == 'ws':
                        if 'wsSettings' in stream:
                            stream['wsSettings']['headers'] = {
                                'Host': self.get_random_host('sni')
                            }
                    elif 'tlsSettings' in stream:
                        stream['tlsSettings']['serverName'] = self.get_random_host('sni')
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.logger.info("V2Ray configuration updated with new hosts")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update V2Ray config: {e}")
            return False
    
    def update_ssh_websocket_config(self):
        """Update SSH WebSocket configuration"""
        try:
            # Update nginx configuration for WebSocket
            nginx_config = f"""
server {{
    listen 8080;
    server_name {self.get_random_host('sni')};
    
    location /ssh-ws {{
        proxy_pass http://127.0.0.1:2222;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host {self.get_random_host('sni')};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
            
            with open('/etc/nginx/sites-available/ssh-websocket', 'w') as f:
                f.write(nginx_config)
            
            self.logger.info("SSH WebSocket configuration updated")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update SSH WebSocket config: {e}")
            return False
    
    def update_shadowsocks_config(self):
        """Update Shadowsocks configuration with plugin options"""
        config_file = '/etc/shadowsocks-libev/config.json'
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Update v2ray-plugin options
            config['plugin_opts'] = f"server;tls;host={self.get_random_host('sni')};path=/ss-ws"
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.logger.info("Shadowsocks configuration updated with new host")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update Shadowsocks config: {e}")
            return False
    
    def restart_services(self):
        """Restart services to apply new configurations"""
        import subprocess
        
        services = ['v2ray', 'nginx', 'shadowsocks-libev']
        
        for service in services:
            try:
                subprocess.run(['systemctl', 'reload', service], check=True)
                self.logger.info(f"Reloaded {service}")
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to reload {service}: {e}")
    
    def rotate_hosts(self):
        """Perform host rotation"""
        self.logger.info("Starting host rotation...")
        
        # Update configurations
        v2ray_updated = self.update_v2ray_config()
        ssh_updated = self.update_ssh_websocket_config()
        ss_updated = self.update_shadowsocks_config()
        
        # Restart services if any config was updated
        if v2ray_updated or ssh_updated or ss_updated:
            self.restart_services()
            self.logger.info("Host rotation completed successfully")
        else:
            self.logger.warning("No configurations were updated")
    
    def run_daemon(self):
        """Run host rotation daemon"""
        self.logger.info(f"Starting host rotation daemon (interval: {self.rotation_interval}s)")
        
        while True:
            try:
                self.rotate_hosts()
                time.sleep(self.rotation_interval)
            except KeyboardInterrupt:
                self.logger.info("Host rotation daemon stopped")
                break
            except Exception as e:
                self.logger.error(f"Error in host rotation daemon: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == "__main__":
    import sys
    
    rotation = HostRotation()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'daemon':
        rotation.run_daemon()
    else:
        rotation.rotate_hosts()
EOF
    
    chmod +x "$INSTALL_DIR/host_rotation.py"
    
    # Create systemd service
    cat > "/etc/systemd/system/host-rotation.service" << EOF
[Unit]
Description=Automatic Host Rotation Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/host_rotation.py daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable host-rotation
    systemctl start host-rotation
    
    log_message "INFO" "Automatic host rotation service installed and started"
}

# Free Internet Menu
free_internet_menu() {
    while true; do
        choice=$(whiptail --title "Free Internet Optimizations" --menu \
            "Select optimization:" 16 70 9 \
            "1" "🔄 Setup SNI Bypass" \
            "2" "🌐 Configure Domain Fronting" \
            "3" "🔀 Enable Host Rotation" \
            "4" "📱 ISP-Specific Configs" \
            "5" "🛠️  Custom Header Injection" \
            "6" "⚡ Speed Optimizations" \
            "7" "📋 Test Configurations" \
            "8" "📊 Monitor Free Internet" \
            "9" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) setup_sni_bypass ;;
            2) setup_domain_fronting ;;
            3) setup_host_rotation ;;
            4) setup_isp_configs ;;
            5) setup_header_injection ;;
            6) setup_speed_optimizations ;;
            7) test_free_internet_configs ;;
            8) monitor_free_internet ;;
            9) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

setup_isp_configs() {
    local isp
    isp=$(whiptail --menu "Select ISP:" 15 60 6 \
        "safaricom" "Safaricom Kenya" \
        "airtel" "Airtel" \
        "mtn" "MTN" \
        "vodacom" "Vodacom" \
        "custom" "Custom ISP" 3>&1 1>&2 2>&3)
    
    case $isp in
        safaricom)
            setup_safaricom_config
            ;;
        airtel)
            setup_airtel_config
            ;;
        mtn)
            setup_mtn_config
            ;;
        vodacom)
            setup_vodacom_config
            ;;
        custom)
            setup_custom_isp_config
            ;;
    esac
}

setup_safaricom_config() {
    echo -e "${YELLOW}Setting up Safaricom-specific configuration...${NC}"
    
    # Create Safaricom payload
    cat > "$CONFIG_DIR/safaricom_payload.txt" << 'EOF'
GET / HTTP/1.1[crlf]Host: zero.facebook.com[crlf]X-Online-Host: zero.facebook.com[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]
EOF
    
    # Create custom SSH config for Safaricom
    cat > "$CONFIG_DIR/ssh_safaricom.conf" << 'EOF'
# Safaricom SSH Configuration
Host safaricom-ssh
    HostName YOUR_SERVER_IP
    Port 22
    User root
    ProxyCommand corkscrew YOUR_SERVER_IP 8080 %h %p
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    Compression yes
EOF
    
    # Update payload with server IP
    local server_ip=$(get_server_ip)
    sed -i "s/YOUR_SERVER_IP/$server_ip/g" "$CONFIG_DIR/ssh_safaricom.conf"
    
    log_message "INFO" "Safaricom configuration created"
    whiptail --msgbox "Safaricom configuration created successfully!\nPayload: $CONFIG_DIR/safaricom_payload.txt\nSSH Config: $CONFIG_DIR/ssh_safaricom.conf" 10 70
}

# Telegram Bot Integration
telegram_bot_setup() {
    echo -e "${YELLOW}Setting up Telegram bot...${NC}"
    
    local bot_token
    bot_token=$(whiptail --inputbox "Enter Telegram Bot Token:" 10 60 3>&1 1>&2 2>&3)
    
    if [[ -z "$bot_token" ]]; then
        whiptail --msgbox "Bot token is required" 8 50
        return 1
    fi
    
    local admin_chat_id
    admin_chat_id=$(whiptail --inputbox "Enter Admin Chat ID:" 10 60 3>&1 1>&2 2>&3)
    
    # Create Telegram bot
    cat > "$INSTALL_DIR/telegram_bot.py" << 'EOF'
#!/usr/bin/env python3
import asyncio
import logging
import sqlite3
import json
import subprocess
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

class SaidTechBot:
    def __init__(self, token: str, admin_chat_id: str):
        self.token = token
        self.admin_chat_id = admin_chat_id
        self.db_path = '/etc/saidtech/configs/users.db'
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            level=logging.INFO,
            handlers=[
                logging.FileHandler('/var/log/saidtech/telegram_bot.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def is_admin(self, chat_id: str) -> bool:
        return str(chat_id) == self.admin_chat_id
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        keyboard = [
            [InlineKeyboardButton("👤 User Management", callback_data='user_mgmt')],
            [InlineKeyboardButton("📊 Server Status", callback_data='status')],
            [InlineKeyboardButton("⚙️ Settings", callback_data='settings')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🌟 Welcome to SAID_TÉCH PREMIUM INTERNET Bot!\n\n"
            "Choose an option below:",
            reply_markup=reply_markup
        )
    
    async def user_management(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle user management"""
        if not self.is_admin(update.effective_chat.id):
            await update.callback_query.answer("Access denied")
            return
        
        keyboard = [
            [InlineKeyboardButton("➕ Add User", callback_data='add_user')],
            [InlineKeyboardButton("🗑️ Delete User", callback_data='delete_user')],
            [InlineKeyboardButton("📋 List Users", callback_data='list_users')],
            [InlineKeyboardButton("⬅️ Back", callback_data='back')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.callback_query.edit_message_text(
            "👤 User Management\n\nSelect an action:",
            reply_markup=reply_markup
        )
    
    async def server_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show server status"""
        try:
            # Get service status
            services = ['v2ray', 'nginx', 'ssh', 'shadowsocks-libev', 'openvpn@server-tcp']
            status_text = "📊 Server Status\n\n"
            
            for service in services:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True, text=True
                )
                status = "🟢 Running" if result.stdout.strip() == "active" else "🔴 Stopped"
                status_text += f"{service}: {status}\n"
            
            # Get user count
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active=1")
            active_users = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            conn.close()
            
            status_text += f"\n👥 Users: {active_users}/{total_users} active"
            
            await update.callback_query.edit_message_text(status_text)
            
        except Exception as e:
            await update.callback_query.edit_message_text(f"Error getting status: {e}")
    
    async def add_user_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start add user process"""
        if not self.is_admin(update.effective_chat.id):
            await update.callback_query.answer("Access denied")
            return
        
        await update.callback_query.edit_message_text(
            "➕ Add New User\n\n"
            "Please send the username:"
        )
        context.user_data['state'] = 'waiting_username'
    
    async def handle_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages"""
        state = context.user_data.get('state')
        
        if state == 'waiting_username':
            username = update.message.text.strip()
            context.user_data['username'] = username
            context.user_data['state'] = 'waiting_protocol'
            
            keyboard = [
                [InlineKeyboardButton("V2Ray", callback_data='protocol_v2ray')],
                [InlineKeyboardButton("SSH", callback_data='protocol_ssh')],
                [InlineKeyboardButton("Shadowsocks", callback_data='protocol_shadowsocks')],
                [InlineKeyboardButton("All Protocols", callback_data='protocol_all')]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                f"Username: {username}\n\nSelect protocol:",
                reply_markup=reply_markup
            )
    
    async def create_user(self, protocol: str, context: ContextTypes.DEFAULT_TYPE, chat_id: int):
        """Create user in database"""
        try:
            username = context.user_data.get('username')
            if not username:
                return "Error: No username specified"
            
            # Generate password
            import secrets
            import string
            password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            
            # Add to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                "INSERT INTO users (username, password, protocol, expires_at, max_connections) VALUES (?, ?, ?, ?, ?)",
                (username, password, protocol, expires_at, 2)
            )
            conn.commit()
            conn.close()
            
            return f"✅ User created successfully!\n\n" \
                   f"Username: {username}\n" \
                   f"Password: {password}\n" \
                   f"Protocol: {protocol}\n" \
                   f"Expires: {expires_at}"
        
        except Exception as e:
            return f"❌ Error creating user: {e}"
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data == 'user_mgmt':
            await self.user_management(update, context)
        elif data == 'status':
            await self.server_status(update, context)
        elif data == 'add_user':
            await self.add_user_start(update, context)
        elif data.startswith('protocol_'):
            protocol = data.replace('protocol_', '')
            result = await self.create_user(protocol, context, query.message.chat_id)
            await query.edit_message_text(result)
    
    def run(self):
        """Run the bot"""
        app = Application.builder().token(self.token).build()
        
        app.add_handler(CommandHandler("start", self.start))
        app.add_handler(CallbackQueryHandler(self.button_callback))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text))
        
        self.logger.info("Starting Telegram bot...")
        app.run_polling()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python3 telegram_bot.py <token> <admin_chat_id>")
        sys.exit(1)
    
    bot = SaidTechBot(sys.argv[1], sys.argv[2])
    bot.run()
EOF
    
    chmod +x "$INSTALL_DIR/telegram_bot.py"
    
    # Install python-telegram-bot
    pip3 install python-telegram-bot
    
    # Create systemd service
    cat > "/etc/systemd/system/saidtech-telegram-bot.service" << EOF
[Unit]
Description=SAID_TECH Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/telegram_bot.py $bot_token $admin_chat_id
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable saidtech-telegram-bot
    systemctl start saidtech-telegram-bot
    
    # Save configuration
    cat > "$CONFIG_DIR/telegram.conf" << EOF
BOT_TOKEN=$bot_token
ADMIN_CHAT_ID=$admin_chat_id
BOT_ENABLED=true
EOF
    
    log_message "INFO" "Telegram bot installed and started"
    whiptail --msgbox "Telegram bot setup completed!\nBot Token: $bot_token\nAdmin Chat ID: $admin_chat_id\n\nThe bot is now running and ready to receive commands." 12 70
}

# Additional menu functions
security_menu() {
    while true; do
        choice=$(whiptail --title "Security Configuration" --menu \
            "Select security option:" 15 70 8 \
            "1" "🔒 SSL/TLS Configuration" \
            "2" "🛡️  Firewall Settings" \
            "3" "🚫 Fail2ban Configuration" \
            "4" "🔐 SSH Key Authentication" \
            "5" "🛡️  DDoS Protection" \
            "6" "📊 Security Monitoring" \
            "7" "🔍 Security Audit" \
            "8" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) ssl_config_menu ;;
            2) firewall_config_menu ;;
            3) fail2ban_config_menu ;;
            4) ssh_key_setup ;;
            5) ddos_protection_setup ;;
            6) security_monitoring ;;
            7) security_audit ;;
            8) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

dns_cdn_menu() {
    while true; do
        choice=$(whiptail --title "DNS & CDN Configuration" --menu \
            "Select option:" 15 70 8 \
            "1" "🌐 Configure Cloudflare DNS" \
            "2" "📡 Setup SlowDNS" \
            "3" "🔀 DNS over HTTPS" \
            "4" "⚡ CDN Integration" \
            "5" "📋 DNS Records Management" \
            "6" "🧪 DNS Testing" \
            "7" "📊 DNS Monitoring" \
            "8" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) setup_cloudflare_dns ;;
            2) install_slowdns ;;
            3) setup_dns_over_https ;;
            4) setup_cdn_integration ;;
            5) manage_dns_records ;;
            6) test_dns_configuration ;;
            7) monitor_dns ;;
            8) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

show_help() {
    local help_file="/tmp/saidtech_help.txt"
    
    cat > "$help_file" << EOF
SAID_TÉCH PREMIUM INTERNET VPN Installer Help
============================================

OVERVIEW:
This script installs and configures multiple VPN protocols and tunneling technologies
to provide premium internet access services.

SUPPORTED PROTOCOLS:
• V2Ray (VMess, VLess, Trojan with CDN support)
• SSH WebSocket & SSH CDN (Cloudflare integration)
• SSH over SSL (Stunnel)
• SlowDNS (with domain and NS support)
• Shadowsocks (with plugins and obfuscation)
• Trojan-Go (with WebSocket and CDN)
• OpenVPN (TCP, UDP, and TLS variants)
• Psiphon3 (configuration generator)

FREE INTERNET FEATURES:
• SNI Host injection for ISP bypass
• Domain fronting via Cloudflare
• Custom host checkers and header injection
• Automatic host rotation and fallback
• ISP-specific configurations (Safaricom, Airtel, MTN, Vodacom)

SECURITY FEATURES:
• Let's Encrypt SSL with auto-renewal
• Self-signed certificate fallback
• Fail2ban intrusion prevention
• UFW firewall configuration
• DDoS protection
• Rate limiting

USER MANAGEMENT:
• SQLite database for user storage
• Bandwidth and connection limits
• User expiry management
• Client configuration generation
• Real-time monitoring

ADDITIONAL FEATURES:
• Telegram bot integration
• Web-based management interface
• Automatic backups
• GitHub/Telegram config upload
• Performance monitoring
• Log management

REQUIREMENTS:
• Ubuntu 20.04+ or Debian 10+
• Minimum 512MB RAM
• Minimum 1GB disk space
• Root access (except Termux)

USAGE:
1. Run the script as root: sudo ./saidtech-vpn-installer.sh
2. Select "Full Installation" for all protocols
3. Configure your domain (optional)
4. Add users through the User Management menu
5. Generate client configurations
6. Test connections

SUPPORT:
• Website: https://joshuasaid.tech
• Email: admin@saidtech.com
• Documentation: Available in /etc/saidtech/docs/

TROUBLESHOOTING:
• Check logs in /var/log/saidtech/
• Verify service status: systemctl status <service>
• Test port connectivity: telnet <server> <port>
• Check firewall: ufw status
• Review configuration files in /etc/saidtech/configs/

For advanced configuration and customization, refer to the
configuration files in /etc/saidtech/configs/ directory.
EOF
    
    whiptail --textbox "$help_file" 30 90
    rm -f "$help_file"
}

# System monitoring functions
monitoring_menu() {
    while true; do
        choice=$(whiptail --title "Monitoring & Logs" --menu \
            "Select monitoring option:" 15 70 8 \
            "1" "📊 Service Status" \
            "2" "📋 View Logs" \
            "3" "👥 Connected Users" \
            "4" "📈 Bandwidth Usage" \
            "5" "💾 System Resources" \
            "6" "🔍 Real-time Monitor" \
            "7" "📧 Alert Configuration" \
            "8" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) show_service_status ;;
            2) view_logs_menu ;;
            3) show_connected_users ;;
            4) show_bandwidth_usage ;;
            5) show_system_resources ;;
            6) start_realtime_monitor ;;
            7) configure_alerts ;;
            8) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

# Create branded SSH login banner
create_ssh_banner() {
    cat > "/etc/motd" << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                          SAID_TÉCH PREMIUM INTERNET                              ║
║                             Powered by joshuasaid.tech                           ║
╚═══════════════════════════════════════════════════════════════════════════════════╝

🌟 Welcome to your premium VPN server!

📊 Server Information:
   • Location: Cloud VPS
   • Protocols: V2Ray, SSH, Shadowsocks, OpenVPN, Trojan-Go
   • Security: SSL/TLS, Fail2ban, Firewall

👤 Account Status:
   • Username: %USER%
   • Expires: %EXPIRY%
   • Data Used: %DATA_USED%
   • Connections: %CONNECTIONS%/%MAX_CONNECTIONS%

⚡ Quick Commands:
   • Check status: systemctl status v2ray
   • View logs: tail -f /var/log/saidtech/installer.log
   • Manage users: /etc/saidtech/saidtech-vpn-installer.sh

🆘 Support:
   • Website: https://joshuasaid.tech
   • Email: admin@saidtech.com
   • Telegram: @saidtech_support

╔═══════════════════════════════════════════════════════════════════════════════════╗
║ NOTICE: This server is for authorized users only. Unauthorized access is prohibited ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
EOF

    # Update SSH configuration to show banner
    if ! grep -q "Banner /etc/motd" /etc/ssh/sshd_config; then
        echo "Banner /etc/motd" >> /etc/ssh/sshd_config
        systemctl reload ssh
    fi
    
    log_message "INFO" "SSH login banner created"
}

# Export all additional functions
export -f add_user_interactive delete_user_interactive list_users_interactive
export -f generate_config_interactive setup_sni_bypass setup_domain_fronting
export -f setup_host_rotation free_internet_menu setup_isp_configs
export -f telegram_bot_setup security_menu dns_cdn_menu show_help
export -f monitoring_menu create_ssh_banner