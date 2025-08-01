#!/bin/bash

# SAID_TÉCH PREMIUM INTERNET VPN Installer
# Version: 2.0.0
# Author: Joshua Said
# Website: joshuasaid.tech

# Load configuration
source /etc/saidtech/config.conf

# Telegram Bot Functions
function setup_telegram_bot() {
    echo -e "${GREEN}[*] Setting up Telegram Bot Integration${NC}"
    
    # Create Telegram bot service
    cat > /usr/local/bin/saidtech-bot <<EOF
#!/bin/python3
import telebot
import sqlite3
from datetime import datetime

# Configuration
BOT_TOKEN = "$TELEGRAM_BOT_TOKEN"
ADMIN_IDS = [$TELEGRAM_ADMIN_IDS]
DB_PATH = "/etc/saidtech/users.db"

bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Welcome to SAID_TÉCH VPN Bot! Use /help for commands.")

@bot.message_handler(commands=['help'])
def send_help(message):
    help_text = """
Available commands:
/adduser <username> <password> <days> <mb_limit> - Add new user
/deluser <username> - Delete user
/listusers - List all users
/stats - Show server statistics
"""
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['adduser'])
def add_user(message):
    if message.from_user.id not in ADMIN_IDS:
        bot.reply_to(message, "⚠️ Unauthorized")
        return
    
    try:
        _, username, password, days, mb_limit = message.text.split()
        expiry = (datetime.now() + timedelta(days=int(days))).strftime('%Y-%m-%d')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users VALUES (?,?,?,?,0)", (username, password, expiry, mb_limit))
        conn.commit()
        conn.close()
        
        bot.reply_to(message, f"✅ User {username} added successfully!\nExpiry: {expiry}\nLimit: {mb_limit}MB")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

if __name__ == "__main__":
    bot.polling()
EOF

    chmod +x /usr/local/bin/saidtech-bot

    # Create systemd service
    cat > /etc/systemd/system/saidtech-bot.service <<EOF
[Unit]
Description=SAID_TÉCH VPN Telegram Bot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/saidtech-bot
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable saidtech-bot
    systemctl start saidtech-bot

    echo -e "${GREEN}[*] Telegram Bot setup complete${NC}"
}

# API Endpoints
function setup_api() {
    echo -e "${GREEN}[*] Setting up REST API${NC}"
    
    apt-get install -y python3-flask python3-flask-sqlalchemy
    
    # Create API service
    cat > /usr/local/bin/saidtech-api <<EOF
#!/bin/python3
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////etc/saidtech/users.db'
db = SQLAlchemy(app)

class User(db.Model):
    username = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(120))
    expiry = db.Column(db.String(10))
    bandwidth_limit = db.Column(db.Integer)
    used_bandwidth = db.Column(db.Integer)

@app.route('/api/users')
def get_users():
    users = User.query.all()
    return jsonify([{
        'username': u.username,
        'expiry': u.expiry,
        'bandwidth': f"{u.used_bandwidth}/{u.bandwidth_limit}MB"
    } for u in users])

@app.route('/api/stats')
def get_stats():
    total_users = User.query.count()
    active_users = User.query.filter(User.expiry >= datetime.datetime.now().strftime('%Y-%m-%d')).count()
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'server_status': 'online'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

    chmod +x /usr/local/bin/saidtech-api

    # Create systemd service
    cat > /etc/systemd/system/saidtech-api.service <<EOF
[Unit]
Description=SAID_TÉCH VPN API Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/saidtech-api
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable saidtech-api
    systemctl start saidtech-api

    echo -e "${GREEN}[*] REST API setup complete${NC}"
    echo -e "${YELLOW}API Endpoint: http://your-server-ip:5000/api/users${NC}"
}

# Enhanced Reporting
function setup_reporting() {
    echo -e "${GREEN}[*] Setting up Enhanced Reporting${NC}"
    
    # Create daily report script
    cat > /usr/local/bin/saidtech-reports <<EOF
#!/bin/bash
# Generate daily reports
TODAY=\$(date +%Y-%m-%d)
REPORT_FILE="/var/log/saidtech/report-\$TODAY.txt"

# Get stats from database
TOTAL_USERS=\$(sqlite3 /etc/saidtech/users.db "SELECT COUNT(*) FROM users;")
ACTIVE_USERS=\$(sqlite3 /etc/saidtech/users.db "SELECT COUNT(*) FROM users WHERE expiry >= '\$TODAY';")
BW_USAGE=\$(sqlite3 /etc/saidtech/users.db "SELECT SUM(used_bandwidth) FROM users;")

# Generate report
echo "SAID_TÉCH VPN Daily Report - \$TODAY" > \$REPORT_FILE
echo "=================================" >> \$REPORT_FILE
echo "Total Users: \$TOTAL_USERS" >> \$REPORT_FILE
echo "Active Users: \$ACTIVE_USERS" >> \$REPORT_FILE
echo "Total Bandwidth Used: \$BW_USAGE MB" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE
echo "Top 10 Users by Bandwidth:" >> \$REPORT_FILE
sqlite3 -column -header /etc/saidtech/users.db "SELECT username, used_bandwidth FROM users ORDER BY used_bandwidth DESC LIMIT 10;" >> \$REPORT_FILE

# Send to Telegram if configured
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
    curl -F chat_id="$TELEGRAM_CHAT_ID" -F document=@"\$REPORT_FILE" \
    https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument
fi
EOF

    chmod +x /usr/local/bin/saidtech-reports

    # Add to cron
    (crontab -l 2>/dev/null; echo "0 23 * * * /usr/local/bin/saidtech-reports") | crontab -

    echo -e "${GREEN}[*] Daily reporting setup complete${NC}"
}

# QR Code Generation
function generate_qr() {
    echo -e "${GREEN}[*] Generating QR Codes${NC}"
    
    apt-get install -y qrencode
    
    # Create QR code directory
    mkdir -p /etc/saidtech/qrcodes
    
    # Function to generate QR for a user
    generate_user_qr() {
        local username=$1
        local password=$2
        
        # Get user config
        local config=$(sqlite3 /etc/saidtech/users.db "SELECT * FROM users WHERE username='$username';")
        [ -z "$config" ] && return
        
        # Generate QR for each protocol
        # Shadowsocks
        local ss_uri="ss://$(echo -n "aes-256-gcm:$password@$DOMAIN:8388" | base64 -w 0)#SAID_TECH_SS_$username"
        qrencode -o "/etc/saidtech/qrcodes/$username-ss.png" "$ss_uri"
        
        # VMess
        local vmess_config=$(cat <<EOF
{
  "v": "2",
  "ps": "SAID_TECH_VMESS_$username",
  "add": "$DOMAIN",
  "port": "443",
  "id": "$(sqlite3 /etc/saidtech/users.db "SELECT password FROM users WHERE username='$username';")",
  "aid": "64",
  "net": "ws",
  "type": "none",
  "path": "/saidtech",
  "tls": "tls"
}
EOF
        )
        qrencode -o "/etc/saidtech/qrcodes/$username-vmess.png" "vmess://$(echo "$vmess_config" | base64 -w 0)"
        
        echo -e "${GREEN}QR codes generated for $username in /etc/saidtech/qrcodes/${NC}"
    }
    
    if [ $# -eq 0 ]; then
        echo "Usage: generate_qr <username>"
        echo "Or leave blank to generate for all users"
        read -p "Enter username (blank for all): " username
        
        if [ -z "$username" ]; then
            # Generate for all users
            users=$(sqlite3 /etc/saidtech/users.db "SELECT username FROM users;")
            for user in $users; do
                password=$(sqlite3 /etc/saidtech/users.db "SELECT password FROM users WHERE username='$user';")
                generate_user_qr "$user" "$password"
            done
        else
            # Generate for specific user
            password=$(sqlite3 /etc/saidtech/users.db "SELECT password FROM users WHERE username='$username';")
            generate_user_qr "$username" "$password"
        fi
    else
        # Generate for specified user
        password=$(sqlite3 /etc/saidtech/users.db "SELECT password FROM users WHERE username='$1';")
        generate_user_qr "$1" "$password"
    fi
}

# Add to main menu
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
        echo -e "${BLUE}SAID_TÉCH PREMIUM INTERNET VPN INSTALLER v2.0${NC}"
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
        echo -e "${YELLOW}9. Telegram Bot Setup${NC}"
        echo -e "${YELLOW}10. REST API Setup${NC}"
        echo -e "${YELLOW}11. Generate QR Codes${NC}"
        echo -e "${YELLOW}12. Update Script${NC}"
        echo -e "${YELLOW}13. Backup/Restore${NC}"
        echo -e "${YELLOW}14. Uninstall${NC}"
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
            9) setup_telegram_bot ;;
            10) setup_api ;;
            11) generate_qr ;;
            12) update_script ;;
            13) backup_restore ;;
            14) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# Update install_full_vpn to include new services
function install_full_vpn() {
    # ... (previous installation code)
    
    # Add new services
    setup_telegram_bot
    setup_api
    setup_reporting
    
    echo -e "${GREEN}[*] Installation completed with all new features!${NC}"
    sleep 3
}

# Main execution
main_menu
