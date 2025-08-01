# SAID_TÉCH PREMIUM INTERNET VPN Installer

![SAID_TÉCH Logo](https://img.shields.io/badge/SAID_TÉCH-PREMIUM%20INTERNET-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.0.0-green?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-orange?style=for-the-badge)

A comprehensive, modular VPS installation script for premium VPN tunneling protocols. Designed for managing premium internet access services with advanced features including SNI bypass, domain fronting, and ISP-specific optimizations.

**Powered by [joshuasaid.tech](https://joshuasaid.tech)**

## 🌟 Features

### Supported Protocols
- **V2Ray** (VMess, VLess, Trojan with CDN support)
- **SSH WebSocket & SSH CDN** (Cloudflare integration)
- **SSH over SSL** (Stunnel)
- **SlowDNS** (with domain and NS support)
- **Shadowsocks** (with plugins and obfuscation)
- **Trojan-Go** (with WebSocket and CDN)
- **OpenVPN** (TCP, UDP, and TLS variants)
- **Psiphon3** (configuration generator)

### Free Internet Optimizations
- **SNI Host injection** for ISP bypass
- **Domain fronting** via Cloudflare
- **Custom host checkers** and header injection
- **Automatic host rotation** and fallback
- **ISP-specific configurations** (Safaricom, Airtel, MTN, Vodacom)

### Security Features
- **Let's Encrypt SSL** with auto-renewal
- **Self-signed certificate** fallback
- **Fail2ban** intrusion prevention
- **UFW firewall** configuration
- **DDoS protection**
- **Rate limiting**

### User Management
- **SQLite database** for user storage
- **Bandwidth and connection limits**
- **User expiry management**
- **Client configuration generator**
- **Real-time monitoring**

### Additional Features
- **Web-based management interface**
- **Telegram bot integration**
- **Automatic backups**
- **GitHub/Telegram config upload**
- **Performance monitoring**
- **Log management**

## 🚀 Quick Start

### Prerequisites
- **Operating System**: Ubuntu 20.04+, Debian 10+, or Termux
- **Memory**: Minimum 512MB RAM (1GB+ recommended)
- **Storage**: Minimum 1GB free disk space
- **Access**: Root privileges (except on Termux)
- **Network**: Public IP address for VPS

### Installation

1. **Download the installer:**
```bash
wget https://raw.githubusercontent.com/yourusername/saidtech-vpn-installer/main/saidtech-vpn-installer.sh
chmod +x saidtech-vpn-installer.sh
```

2. **Run the installer:**
```bash
sudo ./saidtech-vpn-installer.sh
```

3. **Follow the interactive setup:**
   - Choose "Full Installation" for all protocols
   - Configure your domain (optional)
   - Set up SSL certificates
   - Configure firewall and security

## 📋 Menu Options

### Main Menu
```
🚀 Full Installation (All Protocols)
📦 Install Individual Protocols
👤 User Management
🔒 SSL/Security Configuration
🌐 DNS & CDN Setup
⚙️  System Configuration
📊 Monitor & Logs
🔄 Update & Backup
🤖 Telegram Bot Setup
🌍 Free Internet Optimizations
ℹ️  About & Help
❌ Exit
```

### Protocol Menu
```
V2Ray (VMess, VLess, Trojan)
SSH WebSocket & CDN
SSH over SSL (Stunnel)
SlowDNS
Shadowsocks
Trojan-Go
OpenVPN
Psiphon3
```

### Free Internet Menu
```
🔄 Setup SNI Bypass
🌐 Configure Domain Fronting
🔀 Enable Host Rotation
📱 ISP-Specific Configs
🛠️  Custom Header Injection
⚡ Speed Optimizations
📋 Test Configurations
📊 Monitor Free Internet
```

## 🌐 Web Management Interface

Access the web interface at: `https://your-server-ip/saidtech/`

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

### Web Features
- **Dashboard** with real-time statistics
- **User management** (add, delete, modify users)
- **Service monitoring** and control
- **Configuration generator** with QR codes
- **System information** and resource usage
- **Responsive design** for mobile and desktop

## 🤖 Telegram Bot Integration

The script includes a Telegram bot for remote management:

1. **Create a Telegram bot:**
   - Message @BotFather on Telegram
   - Create new bot and get token

2. **Setup during installation:**
   - Choose "Telegram Bot Setup" from main menu
   - Enter bot token and admin chat ID

3. **Bot commands:**
   - `/start` - Show main menu
   - User management functions
   - Server status monitoring
   - Configuration generation

## 🔧 Configuration Files

### Directory Structure
```
/etc/saidtech/
├── configs/
│   ├── saidtech.conf          # Main configuration
│   ├── users.db               # User database
│   ├── v2ray_ports.conf       # V2Ray port settings
│   ├── ssh_ports.conf         # SSH port settings
│   ├── shadowsocks.conf       # Shadowsocks settings
│   ├── openvpn.conf           # OpenVPN settings
│   ├── ssl/                   # SSL certificates
│   ├── clients/               # Client configurations
│   └── templates/             # Configuration templates
├── backups/                   # Automatic backups
└── docs/                      # Documentation

/var/log/saidtech/
├── installer.log              # Installation logs
├── error.log                  # Error logs
├── web_interface.log          # Web interface logs
└── telegram_bot.log           # Telegram bot logs
```

### Port Assignments
The script automatically assigns available ports or uses defaults:

| Service | Default Port | Protocol |
|---------|-------------|----------|
| SSH | 22 | TCP |
| SSH WebSocket | 8080 | TCP |
| SSH SSL | 443 | TCP |
| V2Ray VMess | 10443 | TCP |
| V2Ray VLess | 10080 | TCP |
| V2Ray Trojan | 10000 | TCP |
| Shadowsocks | 8388 | TCP/UDP |
| Trojan-Go | 8443 | TCP |
| OpenVPN TCP | 1194 | TCP |
| OpenVPN UDP | 1195 | UDP |
| SlowDNS | 53 | UDP |
| Web Interface | 8000 | TCP |

## 👥 User Management

### Creating Users
```bash
# Interactive mode
./saidtech-vpn-installer.sh
# Choose "User Management" > "Add New User"

# Or use the web interface
https://your-server-ip/saidtech/
```

### User Database Schema
```sql
CREATE TABLE users (
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
```

## 🌍 ISP-Specific Configurations

### Safaricom (Kenya)
```
Payload: GET / HTTP/1.1[crlf]Host: zero.facebook.com[crlf]...
SNI: www.safaricom.co.ke
Host: zero.facebook.com
```

### Airtel
```
SNI: www.airtel.com
Host: web.facebook.com
```

### MTN
```
SNI: www.mtn.com
Host: 0.facebook.com
```

### Vodacom
```
SNI: www.vodacom.co.za
Host: m.facebook.com
```

## 🔒 Security Features

### Firewall Configuration
```bash
# Automatically configured ports
ufw allow 22/tcp      # SSH
ufw allow 80/tcp      # HTTP
ufw allow 443/tcp     # HTTPS
ufw allow 8080/tcp    # SSH WebSocket
ufw allow 10443/tcp   # V2Ray VMess
# ... other protocol ports
```

### Fail2ban Protection
```bash
# SSH protection
[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 3600

# Nginx protection
[nginx-http-auth]
enabled = true
maxretry = 3
```

### SSL/TLS
- **Let's Encrypt** certificates with auto-renewal
- **Self-signed fallback** for development
- **TLS 1.2+** encryption
- **Perfect Forward Secrecy**

## 📊 Monitoring and Logs

### Service Status
```bash
# Check all services
systemctl status v2ray nginx ssh shadowsocks-libev openvpn@server-tcp

# View logs
tail -f /var/log/saidtech/installer.log
tail -f /var/log/saidtech/error.log
```

### Web Monitoring
- Real-time service status
- System resource usage
- User connection statistics
- Bandwidth monitoring
- Error tracking

## 🔄 Updates and Backups

### Automatic Backups
- **Daily backups** of configurations
- **7-day retention** by default
- **Compressed archives** to save space
- **Backup verification**

### Manual Backup
```bash
# Create backup
./saidtech-vpn-installer.sh
# Choose "Update & Backup" > "Create Backup"

# Restore backup
./saidtech-vpn-installer.sh
# Choose "Update & Backup" > "Restore Backup"
```

### Updates
```bash
# Check for updates
./saidtech-vpn-installer.sh
# Choose "Update & Backup" > "Check Updates"

# Update script
./saidtech-vpn-installer.sh
# Choose "Update & Backup" > "Update Script"
```

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts:**
```bash
# Check port usage
netstat -tlnp | grep :8080
# Kill conflicting process
sudo kill -9 PID
```

2. **SSL certificate issues:**
```bash
# Renew Let's Encrypt
certbot renew --dry-run
# Check certificate
openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -text -noout
```

3. **Service not starting:**
```bash
# Check service status
systemctl status v2ray
# View service logs
journalctl -u v2ray -f
```

4. **Database issues:**
```bash
# Check database
sqlite3 /etc/saidtech/configs/users.db ".tables"
# Repair database
sqlite3 /etc/saidtech/configs/users.db "PRAGMA integrity_check;"
```

### Debug Mode
```bash
# Run with debug output
bash -x ./saidtech-vpn-installer.sh
```

### Log Locations
- Installation: `/var/log/saidtech/installer.log`
- Errors: `/var/log/saidtech/error.log`
- Web interface: `/var/log/saidtech/web_interface.log`
- Services: `/var/log/` (systemd journals)

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Development Setup
```bash
git clone https://github.com/yourusername/saidtech-vpn-installer.git
cd saidtech-vpn-installer
```

### Coding Standards
- Use **bash best practices**
- **Comment your code**
- Follow **existing style**
- **Test on multiple OS**
- **Update documentation**

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided for educational and legitimate use only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. The developers are not responsible for any misuse of this software.

## 📞 Support

- **Website**: [joshuasaid.tech](https://joshuasaid.tech)
- **Email**: admin@saidtech.com
- **Telegram**: @saidtech_support
- **Issues**: [GitHub Issues](https://github.com/yourusername/saidtech-vpn-installer/issues)

## 🙏 Acknowledgments

- **V2Ray Project** for the excellent proxy software
- **OpenVPN** for the VPN protocol
- **Shadowsocks** for the proxy protocol
- **Let's Encrypt** for free SSL certificates
- **Cloudflare** for CDN services
- **All contributors** who help improve this project

---

**Made with ❤️ by [Joshua Said](https://joshuasaid.tech)**

*Empowering premium internet access worldwide*