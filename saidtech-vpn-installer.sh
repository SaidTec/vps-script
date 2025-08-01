#!/usr/bin/env bash
# saidtech-vpn-installer.sh
# SAID_TÉCH PREMIUM INTERNET | Powered by joshuasaid.tech
# Modular VPN Installer Script

# === Branding Banner ===
show_banner() {
  clear
  echo -e "\e[1;35m"
  echo "====================================================="
  echo "   < SAID_TÉCH PREMIUM INTERNET >"
  echo "   Powered by joshuasaid.tech"
  echo "====================================================="
  echo -e "\e[0m"
}

# === Modular Sourcing ===
#BASE_DIR="/etc/saidtech"
#mkdir -p "$BASE_DIR"

#if [[ -f "$BASE_DIR/functions.sh" ]]; then
#  source "$BASE_DIR/functions.sh"
#fi
#if [[ -f "$BASE_DIR/config.sh" ]]; then
#  source "$BASE_DIR/config.sh"
#fi

# For development/testing, source from workspace root
if [[ -f "./functions.sh" ]]; then
  source "./functions.sh"
fi
if [[ -f "./config.sh" ]]; then
  source "./config.sh"
fi

# === Main Menu ===
main_menu() {
  show_banner
  echo "1) Install VPN Protocols"
  echo "2) User Management"
  echo "3) Security & SSL"
  echo "4) DNS & CDN Setup"
  echo "5) Script Features"
  echo "6) Exit"
  read -rp "Select an option: " opt
  case $opt in
    1) install_vpn_menu ;;
    2) user_management_menu ;;
    3) security_ssl_menu ;;
    4) dns_cdn_menu ;;
    5) script_features_menu ;;
    6) exit 0 ;;
    *) echo "Invalid option."; sleep 1; main_menu ;;
  esac
}

# === Placeholder Menus ===
install_vpn_menu() {
  echo "[Install VPN Protocols] - Coming soon."
  read -n1 -r -p "Press any key to return..."; main_menu
}
user_management_menu() {
  echo "[User Management] - Coming soon."
  read -n1 -r -p "Press any key to return..."; main_menu
}
security_ssl_menu() {
  echo "[Security & SSL] - Coming soon."
  read -n1 -r -p "Press any key to return..."; main_menu
}
dns_cdn_menu() {
  echo "[DNS & CDN Setup] - Coming soon."
  read -n1 -r -p "Press any key to return..."; main_menu
}
script_features_menu() {
  echo "[Script Features] - Coming soon."
  read -n1 -r -p "Press any key to return..."; main_menu
}

# === Entry Point ===
main_menu