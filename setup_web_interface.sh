#!/bin/bash

# Web interface setup function
setup_web_interface() {
    echo -e "${YELLOW}Setting up web management interface...${NC}"
    
    # Install PHP and required modules
    case $PACKAGE_MANAGER in
        apt)
            apt update -qq
            apt install -y php php-fpm php-sqlite3 php-curl php-json php-mbstring
            ;;
        pkg)
            pkg install -y php php-fpm
            ;;
    esac
    
    # Create web directory structure
    mkdir -p "$WEB_DIR"
    mkdir -p "$WEB_DIR/assets"
    mkdir -p "$WEB_DIR/includes"
    
    # Copy web files to web directory
    cp "$SCRIPT_DIR/web_interface.php" "$WEB_DIR/index.php"
    cp "$SCRIPT_DIR/login.php" "$WEB_DIR/login.php"
    cp "$SCRIPT_DIR/logout.php" "$WEB_DIR/logout.php"
    
    # Set proper permissions
    chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || chown -R nginx:nginx "$WEB_DIR" 2>/dev/null || true
    chmod -R 755 "$WEB_DIR"
    
    # Configure Nginx
    cat > "/etc/nginx/sites-available/saidtech-web" << EOF
server {
    listen 8000;
    server_name _;
    root $WEB_DIR;
    index index.php index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # PHP handling
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ ^/(config|logs|backups)/ {
        deny all;
    }
    
    # WebSocket proxy for SSH
    location /ssh-ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # V2Ray WebSocket proxy
    location /v2ray {
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Trojan WebSocket proxy
    location /trojan {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# HTTPS configuration (if SSL is available)
server {
    listen 8443 ssl http2;
    server_name _;
    root $WEB_DIR;
    index index.php index.html;
    
    # SSL configuration
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # PHP handling
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ ^/(config|logs|backups)/ {
        deny all;
    }
}
EOF
    
    # Enable the site
    if [[ -d "/etc/nginx/sites-enabled" ]]; then
        ln -sf /etc/nginx/sites-available/saidtech-web /etc/nginx/sites-enabled/
    fi
    
    # Test Nginx configuration
    nginx -t
    
    if [[ $? -eq 0 ]]; then
        # Restart services
        systemctl restart php*-fpm 2>/dev/null || true
        systemctl restart nginx
        
        # Generate admin password if not exists
        if [[ ! -f "$CONFIG_DIR/.admin_password" ]]; then
            openssl rand -base64 12 > "$CONFIG_DIR/.admin_password"
            chmod 600 "$CONFIG_DIR/.admin_password"
        fi
        
        # Allow web ports in firewall
        ufw allow 8000/tcp 2>/dev/null || true
        ufw allow 8443/tcp 2>/dev/null || true
        
        log_message "INFO" "Web interface installed successfully"
        
        local server_ip=$(get_server_ip)
        local admin_password=$(cat "$CONFIG_DIR/.admin_password" 2>/dev/null || echo "admin123")
        
        whiptail --msgbox "Web interface installed successfully!\n\nAccess URLs:\nHTTP: http://$server_ip:8000\nHTTPS: https://$server_ip:8443\n\nDefault Login:\nUsername: admin\nPassword: $admin_password\n\nPlease change the password after first login." 16 70
    else
        log_message "ERROR" "Nginx configuration test failed"
        whiptail --msgbox "Web interface installation failed!\nNginx configuration error." 8 50
    fi
}

# Export the function
export -f setup_web_interface