#!/bin/bash

# Auth System Deployment Script
# This script deploys the auth system to production environment
# Run with: ./deploy.sh

set -e

# Configuration
APP_DIR="/opt/auth-system"
SERVICE_NAME="auth-service"
NGINX_CONFIG="auth-service.conf"
BACKUP_DIR="/opt/backups/auth-system"
USER="www-data"
GROUP="www-data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

log_info "🚀 Starting Auth System deployment..."

# Check if required directories exist
if [ ! -d "$APP_DIR" ]; then
    log_error "Application directory $APP_DIR does not exist"
    exit 1
fi

# Create backup directory
log_info "📦 Creating backup directory..."
mkdir -p "$BACKUP_DIR/$(date +%Y%m%d_%H%M%S)"

# Backup current deployment if it exists
if [ -f "$APP_DIR/package.json" ]; then
    log_info "💾 Backing up current deployment..."
    cp -r "$APP_DIR" "$BACKUP_DIR/$(date +%Y%m%d_%H%M%S)/app_backup" || true
fi

# Stop existing service if running
if systemctl is-active --quiet $SERVICE_NAME; then
    log_info "🛑 Stopping existing service..."
    systemctl stop $SERVICE_NAME
fi

# Update application code
log_info "📥 Updating application code..."
cd "$APP_DIR"

# If this is a git repository, pull latest changes
if [ -d ".git" ]; then
    log_info "🔄 Pulling latest changes from git..."
    sudo -u $USER git fetch origin
    sudo -u $USER git reset --hard origin/main || sudo -u $USER git reset --hard origin/master
else
    log_warning "Not a git repository. Manual code update required."
fi

# Install/update dependencies
log_info "📦 Installing dependencies..."
sudo -u $USER npm ci --production --silent

# Check if .env file exists
if [ ! -f ".env" ]; then
    if [ -f ".env.template" ]; then
        log_warning "No .env file found. Copying from template..."
        cp .env.template .env
        chown $USER:$GROUP .env
        chmod 600 .env
        log_error "Please configure .env file before continuing!"
        exit 1
    else
        log_error "No .env file or template found!"
        exit 1
    fi
fi

# Validate environment configuration
log_info "🔍 Validating environment configuration..."
if ! sudo -u $USER node -e "
require('dotenv').config();
const required = [
    'JWT_SECRET', 'JWT_REFRESH_SECRET', 'SESSION_SECRET',
    'POSTGRES_PASSWORD', 'SMTP_USER', 'SMTP_PASS'
];
const missing = required.filter(key => !process.env[key] || process.env[key].includes('change_this') || process.env[key].includes('your_'));
if (missing.length > 0) {
    console.error('Missing or placeholder environment variables:', missing.join(', '));
    process.exit(1);
}
console.log('Environment configuration is valid');
"; then
    log_error "Environment configuration validation failed!"
    exit 1
fi

# Run database migrations
log_info "🗄️ Running database migrations..."
if [ -f "database/schema.sql" ]; then
    # Check if database is accessible
    if sudo -u postgres psql -d auth_system -c "SELECT 1;" > /dev/null 2>&1; then
        log_info "Database connection verified"
        
        # Run schema updates (if any)
        sudo -u postgres psql -d auth_system -f database/schema.sql > /dev/null 2>&1 || log_warning "Schema update may have failed or no changes"
    else
        log_error "Cannot connect to database!"
        exit 1
    fi
else
    log_warning "No database schema file found"
fi

# Set proper file permissions
log_info "🔐 Setting file permissions..."
chown -R $USER:$GROUP "$APP_DIR"
chmod -R 755 "$APP_DIR"
chmod 600 "$APP_DIR/.env"

# Ensure log directory exists and has correct permissions
mkdir -p /var/log/auth-system
chown $USER:$GROUP /var/log/auth-system
chmod 755 /var/log/auth-system

# Ensure exports directory exists for GDPR
mkdir -p "$APP_DIR/exports"
chown $USER:$GROUP "$APP_DIR/exports"
chmod 755 "$APP_DIR/exports"

# Copy systemd service file
if [ -f "systemd/auth-service.service" ]; then
    log_info "⚙️ Installing systemd service..."
    cp systemd/auth-service.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
fi

# Copy nginx configuration
if [ -f "nginx/$NGINX_CONFIG" ]; then
    log_info "🌐 Installing nginx configuration..."
    cp "nginx/$NGINX_CONFIG" "/etc/nginx/sites-available/"
    
    # Enable site if not already enabled
    if [ ! -L "/etc/nginx/sites-enabled/$NGINX_CONFIG" ]; then
        ln -s "/etc/nginx/sites-available/$NGINX_CONFIG" "/etc/nginx/sites-enabled/"
    fi
    
    # Test nginx configuration
    if nginx -t; then
        log_success "Nginx configuration is valid"
    else
        log_error "Nginx configuration is invalid!"
        exit 1
    fi
fi

# Health check function
health_check() {
    local max_attempts=30
    local attempt=1
    
    log_info "🏥 Performing health check..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s http://localhost:3000/health > /dev/null 2>&1; then
            log_success "Health check passed!"
            return 0
        fi
        
        log_info "Health check attempt $attempt/$max_attempts failed, retrying in 2 seconds..."
        sleep 2
        ((attempt++))
    done
    
    log_error "Health check failed after $max_attempts attempts"
    return 1
}

# Start services
log_info "🚀 Starting services..."

# Start the application service
systemctl start $SERVICE_NAME

# Wait a moment for service to start
sleep 5

# Check if service is running
if systemctl is-active --quiet $SERVICE_NAME; then
    log_success "Auth service is running"
else
    log_error "Auth service failed to start"
    systemctl status $SERVICE_NAME
    exit 1
fi

# Perform health check
if ! health_check; then
    log_error "Deployment failed health check"
    systemctl stop $SERVICE_NAME
    exit 1
fi

# Reload nginx
log_info "🔄 Reloading nginx..."
systemctl reload nginx

# Verify nginx is running
if systemctl is-active --quiet nginx; then
    log_success "Nginx is running"
else
    log_error "Nginx is not running"
    systemctl status nginx
fi

# Display deployment summary
log_success "🎉 Deployment completed successfully!"
echo ""
echo "📋 Deployment Summary:"
echo "  • Application: $(cd $APP_DIR && node -e "console.log(require('./package.json').version)")"
echo "  • Service Status: $(systemctl is-active $SERVICE_NAME)"
echo "  • Nginx Status: $(systemctl is-active nginx)"
echo "  • Log File: /var/log/auth-system/auth-system.log"
echo ""

# Show service status
log_info "🔍 Service Status:"
systemctl --no-pager status $SERVICE_NAME

# Show recent logs
log_info "📋 Recent Logs (last 10 lines):"
journalctl -u $SERVICE_NAME -n 10 --no-pager

echo ""
log_info "📚 Useful Commands:"
echo "  • View logs: sudo journalctl -u $SERVICE_NAME -f"
echo "  • Restart service: sudo systemctl restart $SERVICE_NAME"
echo "  • Check status: sudo systemctl status $SERVICE_NAME"
echo "  • Test nginx: sudo nginx -t"
echo "  • View app logs: tail -f /var/log/auth-system/auth-system.log"
echo ""

log_success "✅ Deployment completed! Your Auth System is now running."