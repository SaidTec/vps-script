#!/bin/bash

#################################################################################
#                    SAID_TÉCH PREMIUM INTERNET VPN Installer                  #
#                           Powered by joshuasaid.tech                         #
#                                                                               #
# Description: Comprehensive VPS installer for premium VPN tunneling protocols #
# Supported OS: Ubuntu 20.04/22.04+, Debian 10/11+, Termux                   #
# Protocols: V2Ray, SSH WS/CDN, Shadowsocks, Trojan-Go, OpenVPN, SlowDNS      #
# Features: SSL, User Management, CDN Integration, SNI Bypass                  #
#                                                                               #
# Author: Joshua Said (joshuasaid.tech)                                        #
# Version: 1.0.0                                                               #
# License: MIT                                                                  #
#################################################################################

# Script configuration
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="SAID_TÉCH VPN Installer"
AUTHOR_SITE="joshuasaid.tech"
BRAND_NAME="SAID_TÉCH PREMIUM INTERNET"

# Directory structure
INSTALL_DIR="/etc/saidtech"
LOG_DIR="/var/log/saidtech"
CONFIG_DIR="/etc/saidtech/configs"
BACKUP_DIR="/etc/saidtech/backups"
WEB_DIR="/var/www/saidtech"

# Color definitions for UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Load modular components
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/functions.sh" 2>/dev/null || { echo "Error: functions.sh not found"; exit 1; }
source "${SCRIPT_DIR}/config.sh" 2>/dev/null || { echo "Error: config.sh not found"; exit 1; }
source "${SCRIPT_DIR}/additional_functions.sh" 2>/dev/null || { echo "Error: additional_functions.sh not found"; exit 1; }
source "${SCRIPT_DIR}/setup_web_interface.sh" 2>/dev/null || { echo "Error: setup_web_interface.sh not found"; exit 1; }

# Error handling
set -euo pipefail
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_number=$2
    echo -e "${RED}Error occurred on line $line_number with exit code $exit_code${NC}"
    log_message "ERROR" "Script error on line $line_number with exit code $exit_code"
    exit $exit_code
}

# Main functions
show_banner() {
    clear
    echo -e "${PURPLE}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║${WHITE}                            ${BRAND_NAME}                           ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${CYAN}                              Powered by ${AUTHOR_SITE}                              ${PURPLE}║${NC}"
    echo -e "${PURPLE}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ ${YELLOW}Comprehensive VPN Installation Script v${SCRIPT_VERSION}                           ${GREEN}║${NC}"
    echo -e "${GREEN}║ ${WHITE}Protocols: V2Ray • SSH WS/CDN • Shadowsocks • Trojan-Go • OpenVPN • SlowDNS   ${GREEN}║${NC}"
    echo -e "${GREEN}║ ${WHITE}Features: SSL/TLS • User Management • CDN Integration • SNI Bypass            ${GREEN}║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 && "$PREFIX" != *"com.termux"* ]]; then
        echo -e "${RED}This script must be run as root (except on Termux)${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ "$PREFIX" == *"com.termux"* ]]; then
        OS="termux"
        OS_VERSION="latest"
    else
        echo -e "${RED}Unsupported operating system${NC}"
        exit 1
    fi
    
    case $OS in
        ubuntu)
            if [[ $(echo "$OS_VERSION >= 20.04" | bc -l) -eq 0 ]]; then
                echo -e "${RED}Ubuntu version $OS_VERSION not supported. Minimum: 20.04${NC}"
                exit 1
            fi
            PACKAGE_MANAGER="apt"
            ;;
        debian)
            if [[ $(echo "$OS_VERSION >= 10" | bc -l) -eq 0 ]]; then
                echo -e "${RED}Debian version $OS_VERSION not supported. Minimum: 10${NC}"
                exit 1
            fi
            PACKAGE_MANAGER="apt"
            ;;
        termux)
            PACKAGE_MANAGER="pkg"
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac
    
    log_message "INFO" "Detected OS: $OS $OS_VERSION"
}

create_directory_structure() {
    local dirs=("$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR" "$WEB_DIR")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_message "INFO" "Created directory: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$INSTALL_DIR"
    chmod 750 "$LOG_DIR"
    chmod 600 "$CONFIG_DIR"
    chmod 700 "$BACKUP_DIR"
}

install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    case $PACKAGE_MANAGER in
        apt)
            apt update -qq
            apt install -y \
                curl wget git unzip zip \
                nginx certbot python3-certbot-nginx \
                sqlite3 mysql-client \
                iptables-persistent fail2ban \
                jq bc whiptail dialog \
                stunnel4 openvpn \
                net-tools dnsutils \
                htop screen tmux \
                python3 python3-pip
            ;;
        pkg)
            pkg update -y
            pkg install -y \
                curl wget git unzip zip \
                nginx \
                sqlite \
                jq bc \
                stunnel openvpn \
                net-tools dnsutils \
                htop screen tmux \
                python python-pip
            ;;
    esac
    
    # Install Node.js for some features
    install_nodejs
    
    log_message "INFO" "System dependencies installed successfully"
}

show_main_menu() {
    while true; do
        show_banner
        
        choice=$(whiptail --title "SAID_TÉCH VPN Installer" --menu \
            "Choose an option:" 20 78 12 \
            "1" "🚀 Full Installation (All Protocols)" \
            "2" "📦 Install Individual Protocols" \
            "3" "👤 User Management" \
            "4" "🔒 SSL/Security Configuration" \
            "5" "🌐 DNS & CDN Setup" \
            "6" "⚙️  System Configuration" \
            "7" "📊 Monitor & Logs" \
            "8" "🔄 Update & Backup" \
            "9" "🤖 Telegram Bot Setup" \
            "10" "🌍 Free Internet Optimizations" \
            "11" "ℹ️  About & Help" \
            "12" "❌ Exit" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) full_installation ;;
            2) protocol_menu ;;
            3) user_management_menu ;;
            4) security_menu ;;
            5) dns_cdn_menu ;;
            6) system_config_menu ;;
            7) monitoring_menu ;;
            8) backup_menu ;;
            9) telegram_bot_setup ;;
            10) free_internet_menu ;;
            11) show_help ;;
            12) exit_script ;;
            *) 
                whiptail --msgbox "Invalid option. Please try again." 8 50
                ;;
        esac
    done
}

full_installation() {
    if whiptail --yesno "This will install all VPN protocols and features.\nProceed with full installation?" 10 60; then
        echo -e "${GREEN}Starting full installation...${NC}"
        
        # Create progress indicator
        {
            echo "10"; echo "# Installing dependencies..."
            install_dependencies
            
            echo "20"; echo "# Setting up SSL certificates..."
            setup_ssl_certificates
            
            echo "30"; echo "# Installing V2Ray..."
            install_v2ray
            
            echo "40"; echo "# Installing SSH WebSocket..."
            install_ssh_websocket
            
            echo "50"; echo "# Installing Shadowsocks..."
            install_shadowsocks
            
            echo "60"; echo "# Installing Trojan-Go..."
            install_trojan_go
            
            echo "70"; echo "# Installing OpenVPN..."
            install_openvpn
            
            echo "80"; echo "# Installing SlowDNS..."
            install_slowdns
            
            echo "90"; echo "# Configuring firewall and security..."
            configure_firewall
            setup_fail2ban
            
            echo "100"; echo "# Installation complete!"
        } | whiptail --gauge "Full Installation Progress" 6 60 0
        
        create_service_status_page
        setup_web_interface
        
        # Mark installation as complete
        touch "$INSTALL_DIR/.installed"
        echo "$(date)" > "$INSTALL_DIR/.install_date"
        
        show_installation_summary
    fi
}

protocol_menu() {
    while true; do
        choice=$(whiptail --title "Protocol Installation" --menu \
            "Select a protocol to install:" 16 70 9 \
            "1" "V2Ray (VMess, VLess, Trojan)" \
            "2" "SSH WebSocket & CDN" \
            "3" "SSH over SSL (Stunnel)" \
            "4" "SlowDNS" \
            "5" "Shadowsocks" \
            "6" "Trojan-Go" \
            "7" "OpenVPN" \
            "8" "Psiphon3" \
            "9" "⬅️  Back to Main Menu" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) install_v2ray ;;
            2) install_ssh_websocket ;;
            3) install_ssh_ssl ;;
            4) install_slowdns ;;
            5) install_shadowsocks ;;
            6) install_trojan_go ;;
            7) install_openvpn ;;
            8) install_psiphon3 ;;
            9) break ;;
            *) whiptail --msgbox "Invalid option" 8 40 ;;
        esac
    done
}

show_installation_summary() {
    local summary_file="/tmp/installation_summary.txt"
    
    cat > "$summary_file" << EOF
SAID_TÉCH PREMIUM INTERNET - Installation Summary
================================================

Installation completed successfully!

Installed Protocols:
- V2Ray (VMess, VLess, Trojan)
- SSH WebSocket & CDN  
- SSH over SSL (Stunnel)
- SlowDNS
- Shadowsocks
- Trojan-Go  
- OpenVPN
- Psiphon3

Services Status:
$(systemctl is-active v2ray 2>/dev/null || echo "v2ray: Not installed")
$(systemctl is-active nginx 2>/dev/null || echo "nginx: Not installed")
$(systemctl is-active ssh 2>/dev/null || echo "ssh: Not installed")

Configuration Files: $CONFIG_DIR
Log Files: $LOG_DIR
Web Interface: https://$(get_server_ip)/saidtech/

Default Admin Credentials:
Username: admin
Password: $(cat $CONFIG_DIR/.admin_password 2>/dev/null || echo "Not set")

Next Steps:
1. Access the web interface to manage users
2. Configure your domain and SSL certificates
3. Add users and generate client configurations
4. Test connections with provided configs

For support, visit: https://$AUTHOR_SITE
EOF
    
    whiptail --textbox "$summary_file" 25 80
    rm -f "$summary_file"
}

exit_script() {
    echo -e "${GREEN}Thank you for using ${BRAND_NAME}!${NC}"
    echo -e "${CYAN}For support and updates, visit: https://$AUTHOR_SITE${NC}"
    exit 0
}

# Main execution
main() {
    show_banner
    check_root
    detect_os
    create_directory_structure
    
    # Initialize logging
    setup_logging
    
    log_message "INFO" "Starting $SCRIPT_NAME v$SCRIPT_VERSION"
    log_message "INFO" "Detected OS: $OS $OS_VERSION"
    
    # Initialize configuration and database
    init_config
    
    # Setup web interface if not already installed
    if [[ ! -f "$WEB_DIR/index.php" ]]; then
        setup_web_interface
    fi
    
    # Create SSH banner
    create_ssh_banner
    
    # Check if this is a fresh installation
    if [[ ! -f "$INSTALL_DIR/.installed" ]]; then
        if whiptail --yesno "Welcome to $SCRIPT_NAME!\n\nThis appears to be a fresh installation.\nWould you like to proceed with the setup?" 12 60; then
            show_main_menu
        else
            exit_script
        fi
    else
        show_main_menu
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi