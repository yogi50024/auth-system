#!/bin/bash

# EC2 Ubuntu Installation Script for Auth System
# This script installs all dependencies and sets up the environment
# Run with: sudo ./install_ec2_ubuntu.sh

set -e

echo "🚀 Starting Auth System installation on Ubuntu EC2..."

# Update system packages
echo "📦 Updating system packages..."
apt update && apt upgrade -y

# Install essential packages
echo "🛠️ Installing essential packages..."
apt install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release

# Install Node.js 18
echo "📦 Installing Node.js 18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Verify Node.js installation
node_version=$(node --version)
npm_version=$(npm --version)
echo "✅ Node.js $node_version and npm $npm_version installed"

# Install PostgreSQL 13+
echo "🐘 Installing PostgreSQL..."
apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL
systemctl start postgresql
systemctl enable postgresql

# Install MongoDB 5.0
echo "🍃 Installing MongoDB..."
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/5.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-5.0.list
apt update
apt install -y mongodb-org

# Start and enable MongoDB
systemctl start mongod
systemctl enable mongod

# Install Redis
echo "🚀 Installing Redis..."
apt install -y redis-server

# Configure Redis
sed -i 's/^# maxmemory <bytes>/maxmemory 256mb/' /etc/redis/redis.conf
sed -i 's/^# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf

# Start and enable Redis
systemctl start redis-server
systemctl enable redis-server

# Install Nginx
echo "🌐 Installing Nginx..."
apt install -y nginx

# Start and enable Nginx
systemctl start nginx
systemctl enable nginx

# Install PM2 globally (for process management)
echo "⚙️ Installing PM2..."
npm install -g pm2

# Install Let's Encrypt Certbot
echo "🔒 Installing Certbot for SSL..."
apt install -y certbot python3-certbot-nginx

# Create application directory
echo "📁 Creating application directory..."
mkdir -p /opt/auth-system
chown www-data:www-data /opt/auth-system

# Create logs directory
mkdir -p /var/log/auth-system
chown www-data:www-data /var/log/auth-system

# Create exports directory for GDPR
mkdir -p /opt/auth-system/exports
chown www-data:www-data /opt/auth-system/exports

# Configure PostgreSQL
echo "🔧 Configuring PostgreSQL..."
sudo -u postgres psql << EOF
CREATE DATABASE auth_system;
CREATE USER auth_user WITH ENCRYPTED PASSWORD 'change_this_password_in_production';
GRANT ALL PRIVILEGES ON DATABASE auth_system TO auth_user;
ALTER USER auth_user CREATEDB;
\q
EOF

# Configure firewall
echo "🔥 Configuring UFW firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 'Nginx Full'
ufw allow 80
ufw allow 443

# Install fail2ban for additional security
echo "🛡️ Installing fail2ban..."
apt install -y fail2ban

# Create fail2ban configuration for auth service
cat > /etc/fail2ban/jail.d/auth-service.conf << EOF
[auth-service]
enabled = true
port = http,https
filter = auth-service
logpath = /var/log/auth-system/auth-system.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create fail2ban filter for auth service
cat > /etc/fail2ban/filter.d/auth-service.conf << EOF
[Definition]
failregex = ^.*"level":"warn".*"message":"Failed login attempt".*"ip":"<HOST>".*$
            ^.*"level":"warn".*"message":"Rate limit exceeded".*"ip":"<HOST>".*$
ignoreregex =
EOF

# Restart fail2ban
systemctl restart fail2ban

# Set up log rotation
echo "📋 Setting up log rotation..."
cat > /etc/logrotate.d/auth-system << EOF
/var/log/auth-system/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload auth-service || true
    endscript
}
EOF

# Install monitoring tools
echo "📊 Installing monitoring tools..."
apt install -y htop iotop nethogs

# Create environment file template
cat > /opt/auth-system/.env.template << EOF
# Server Configuration
NODE_ENV=production
PORT=3000
HOST=localhost

# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=change_this_password_in_production
POSTGRES_DATABASE=auth_system

MONGODB_URI=mongodb://localhost:27017/auth_system
MONGODB_GRIDFS_BUCKET=uploads

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT Configuration (CHANGE THESE IN PRODUCTION!)
JWT_SECRET=your_super_secret_jwt_key_minimum_64_characters_required_for_security
JWT_REFRESH_SECRET=your_super_secret_refresh_key_minimum_64_characters_required_for_security
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Session Configuration
SESSION_SECRET=your_super_secret_session_key_minimum_64_characters_required_for_security
SESSION_TIMEOUT=1800000

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
EMAIL_FROM=noreply@yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_MAX=5
REGISTER_RATE_LIMIT_MAX=3

# Security
BCRYPT_ROUNDS=12
ARGON2_MEMORY_COST=65536
ARGON2_TIME_COST=3
ARGON2_PARALLELISM=4

# MFA Configuration
MFA_ISSUER=AuthSystem
MFA_SERVICE_NAME=Auth System

# GDPR Configuration
GDPR_DATA_RETENTION_DAYS=365
GDPR_EXPORT_LIMIT_PER_DAY=3

# File Upload Configuration
MAX_FILE_SIZE=5242880
ALLOWED_FILE_TYPES=pdf,jpg,jpeg,png,doc,docx

# API Configuration
API_VERSION=v1
API_PREFIX=/api/v1

# Frontend URL
FRONTEND_URL=https://yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FILE=/var/log/auth-system/auth-system.log

# Health Check
HEALTH_CHECK_INTERVAL=30000

# Provider Verification
PROVIDER_VERIFICATION_REQUIRED=true
PROVIDER_AUTO_APPROVAL=false
EOF

# Set permissions
chown www-data:www-data /opt/auth-system/.env.template

# Print installation summary
echo ""
echo "✅ Auth System installation completed!"
echo ""
echo "📋 Installation Summary:"
echo "  • Node.js $(node --version)"
echo "  • PostgreSQL $(sudo -u postgres psql -c 'SELECT version();' | grep PostgreSQL | cut -d' ' -f3)"
echo "  • MongoDB $(mongod --version | head -n1 | cut -d' ' -f3)"
echo "  • Redis $(redis-server --version | cut -d' ' -f3)"
echo "  • Nginx $(nginx -v 2>&1 | cut -d' ' -f3)"
echo "  • PM2 $(pm2 --version)"
echo ""
echo "🔧 Next Steps:"
echo "  1. Clone your application to /opt/auth-system"
echo "  2. Copy .env.template to .env and configure with your settings"
echo "  3. Install application dependencies with 'npm install --production'"
echo "  4. Import database schema"
echo "  5. Configure SSL certificate with certbot"
echo "  6. Start the application with systemd"
echo ""
echo "⚠️  Security Reminders:"
echo "  • Change default PostgreSQL password"
echo "  • Generate strong JWT secrets"
echo "  • Configure proper email settings"
echo "  • Set up SSL certificate"
echo "  • Review firewall settings"
echo "  • Configure domain name in Nginx"
echo ""
echo "📚 Documentation: https://github.com/yogi50024/auth-system"
echo ""

# Display service status
echo "🔍 Service Status:"
systemctl is-active --quiet postgresql && echo "  ✅ PostgreSQL is running" || echo "  ❌ PostgreSQL is not running"
systemctl is-active --quiet mongod && echo "  ✅ MongoDB is running" || echo "  ❌ MongoDB is not running"
systemctl is-active --quiet redis-server && echo "  ✅ Redis is running" || echo "  ❌ Redis is not running"
systemctl is-active --quiet nginx && echo "  ✅ Nginx is running" || echo "  ❌ Nginx is not running"

echo ""
echo "🎉 Installation complete! Ready for application deployment."