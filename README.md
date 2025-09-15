# Authentication Microservice

A production-ready authentication microservice with comprehensive security features, RBAC, JWT tokens, MFA, and GDPR compliance.

## 🚀 Features

### Authentication & Authorization
- **User Registration & Login** with email verification
- **Role-Based Access Control (RBAC)** - Users, Providers, Admins
- **JWT Token Management** with access & refresh tokens
- **Multi-Factor Authentication (MFA)** using TOTP
- **Password Management** with reset functionality
- **Session Management** with Redis-based storage
- **Rate Limiting** on all endpoints

### Security
- **Argon2id Password Hashing** - Industry standard
- **MFA Secret Encryption** for secure storage
- **Comprehensive Rate Limiting** per endpoint
- **CORS Protection** with configurable origins
- **Helmet.js Security Headers**
- **Input Validation & Sanitization**
- **Audit Logging** for all user actions

### Provider Management
- **Provider Registration** with verification workflow
- **Document Upload** via MongoDB GridFS
- **License & Certificate Management**
- **Admin Approval Workflow**
- **Business Profile Management**

### GDPR Compliance
- **Data Export** - Complete user data download
- **Right to Erasure** - Account deletion requests
- **Consent Management** - Track and update consent
- **Data Retention Policies** - Automated cleanup
- **Audit Trail** - Complete activity logging

### Infrastructure
- **PostgreSQL** for structured data
- **MongoDB GridFS** for file storage
- **Redis** for sessions and caching
- **Docker Support** with docker-compose
- **Health Checks** for monitoring
- **Comprehensive Logging** with Winston

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL 13+
- MongoDB 5+
- Redis 6+
- SMTP Server (for emails)

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/yogi50024/auth-system.git
cd auth-system
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Server Configuration
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DATABASE=auth_system

MONGODB_URI=mongodb://localhost:27017/auth_system
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT Secrets (Generate strong random strings)
JWT_SECRET=your_super_secret_jwt_key_64_chars_minimum_length_required
JWT_REFRESH_SECRET=your_super_secret_refresh_key_64_chars_minimum_length
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
EMAIL_FROM=noreply@yourdomain.com

# Frontend URL
FRONTEND_URL=https://yourdomain.com
```

### 4. Database Setup

#### PostgreSQL Setup
```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Run the following commands:
CREATE DATABASE auth_system;
CREATE USER auth_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE auth_system TO auth_user;
\q

# Import schema
psql -h localhost -U auth_user -d auth_system -f database/schema.sql
```

#### MongoDB Setup
```bash
# Start MongoDB service
sudo systemctl start mongod

# MongoDB will automatically create the database on first connection
```

#### Redis Setup
```bash
# Start Redis service
sudo systemctl start redis-server
```

### 5. Start the Application
```bash
# Development
npm run dev

# Production
npm start
```

## 🐳 Docker Deployment

### Using Docker Compose
```bash
# Copy environment file
cp .env.example .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f auth-service
```

### Environment-specific Deployments
```bash
# Development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## 🚀 EC2 Deployment (Ubuntu)

### Automated Installation
```bash
# Run the installation script
chmod +x scripts/install_ec2_ubuntu.sh
sudo ./scripts/install_ec2_ubuntu.sh

# Deploy the application
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

### Manual Installation Steps

#### 1. System Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Install MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
sudo apt update
sudo apt install -y mongodb-org

# Install Redis
sudo apt install redis-server -y

# Install PM2 (Process Manager)
sudo npm install -g pm2
```

#### 2. Application Setup
```bash
# Clone and setup application
git clone https://github.com/yogi50024/auth-system.git /opt/auth-system
cd /opt/auth-system
npm install --production

# Copy configuration
cp .env.example .env
# Edit .env with production values

# Setup database schema
sudo -u postgres psql -c "CREATE DATABASE auth_system;"
sudo -u postgres psql -c "CREATE USER auth_user WITH ENCRYPTED PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE auth_system TO auth_user;"
psql -h localhost -U auth_user -d auth_system -f database/schema.sql
```

#### 3. Service Configuration
```bash
# Copy systemd service file
sudo cp systemd/auth-service.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable auth-service
sudo systemctl start auth-service

# Setup Nginx reverse proxy
sudo cp nginx/auth-service.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/auth-service.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 📚 API Documentation

### Base URL
```
Production: https://your-domain.com/api/v1
Development: http://localhost:3000/api/v1
```

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "role": "user",
  "gdprConsent": true
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "mfaCode": "123456"
}
```

#### Setup MFA
```http
POST /api/v1/auth/mfa/setup
Authorization: Bearer {access_token}
```

#### Verify Email
```http
POST /api/v1/auth/verify-email
Content-Type: application/json

{
  "token": "verification_token_from_email"
}
```

### Provider Endpoints

#### Register as Provider
```http
POST /api/v1/providers/register
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "businessName": "Acme Corp",
  "businessType": "corporation",
  "licenseNumber": "LIC123456",
  "businessAddress": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zipCode": "12345",
    "country": "US"
  }
}
```

#### Upload Documents
```http
POST /api/v1/providers/documents
Authorization: Bearer {access_token}
Content-Type: multipart/form-data

documents: [file1.pdf, file2.jpg]
fileType: "license"
```

### GDPR Endpoints

#### Request Data Export
```http
POST /api/v1/gdpr/export
Authorization: Bearer {access_token}
```

#### Request Account Deletion
```http
POST /api/v1/gdpr/delete-account
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "confirmPassword": "current_password"
}
```

### Admin Endpoints

#### Get All Users
```http
GET /api/v1/users?page=1&limit=20&role=user&isActive=true
Authorization: Bearer {admin_access_token}
```

#### Verify Provider
```http
PATCH /api/v1/providers/{providerId}/verify
Authorization: Bearer {admin_access_token}
Content-Type: application/json

{
  "verificationDocuments": ["doc1.pdf", "doc2.jpg"]
}
```

## 🔐 Security Best Practices

### Password Requirements
- Minimum 8 characters, maximum 128
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- At least one special character (@$!%*?&)

### Rate Limiting
- Global: 100 requests per 15 minutes per IP
- Login: 5 attempts per 15 minutes per IP
- Registration: 3 attempts per hour per IP
- Password Reset: 3 attempts per hour per IP
- MFA: 10 attempts per 15 minutes per IP/user

### Token Security
- Access tokens expire in 15 minutes
- Refresh tokens expire in 7 days
- Tokens are blacklisted on logout
- JTI (JWT ID) prevents token reuse

### MFA Implementation
- TOTP (Time-based One-Time Password)
- 30-second time window
- 6-digit codes
- Encrypted secret storage
- Backup codes (future feature)

## 📊 Monitoring & Health Checks

### Health Endpoints
```http
GET /health                 # Basic health check
GET /health/detailed        # Database connection status
GET /health/ready          # Kubernetes readiness probe
GET /health/live           # Kubernetes liveness probe
GET /health/metrics        # System metrics
```

### Logging
- Structured JSON logging with Winston
- Request/response logging with Morgan
- Error tracking with stack traces
- Audit trail for all user actions
- Log rotation and retention policies

### Metrics
- Response times
- Error rates
- Authentication success/failure rates
- Database connection status
- Memory and CPU usage

## 🛡️ GDPR Compliance

### Data Subject Rights
1. **Right of Access** - Users can export their data
2. **Right to Rectification** - Users can update their information
3. **Right to Erasure** - Users can request account deletion
4. **Right to Data Portability** - JSON export format
5. **Right to Object** - Users can withdraw consent

### Data Processing
- Explicit consent collection
- Purpose limitation
- Data minimization
- Storage limitation (configurable retention)
- Audit logging for compliance

### Data Export Format
```json
{
  "personal_data": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "created_at": "2024-01-01T00:00:00Z"
  },
  "provider_profile": {...},
  "file_uploads": [...],
  "activity_log": [...],
  "export_date": "2024-01-01T00:00:00Z"
}
```

## 🔧 Configuration Options

### Environment Variables

#### Server Configuration
- `NODE_ENV` - Environment (development/production)
- `PORT` - Server port (default: 3000)
- `HOST` - Server host (default: localhost)

#### Database Configuration
- `POSTGRES_*` - PostgreSQL connection settings
- `MONGODB_URI` - MongoDB connection string
- `REDIS_*` - Redis connection settings

#### Security Configuration
- `JWT_SECRET` - JWT signing secret (minimum 64 characters)
- `JWT_REFRESH_SECRET` - Refresh token secret
- `SESSION_SECRET` - Session encryption secret
- `ARGON2_*` - Argon2 hashing parameters

#### Rate Limiting
- `RATE_LIMIT_*` - Global rate limiting settings
- `LOGIN_RATE_LIMIT_MAX` - Login attempt limits
- `REGISTER_RATE_LIMIT_MAX` - Registration limits

#### Email Configuration
- `SMTP_*` - Email server settings
- `EMAIL_FROM` - Sender email address

#### GDPR Configuration
- `GDPR_DATA_RETENTION_DAYS` - Data retention period
- `GDPR_EXPORT_LIMIT_PER_DAY` - Export request limits

## 🧪 Testing

### Run Tests
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Test Categories
- Unit tests for utilities and services
- Integration tests for API endpoints
- Database tests for models
- Security tests for authentication
- Load tests for performance

## 📈 Performance Optimization

### Database Optimization
- Connection pooling
- Query optimization with indexes
- Read replicas for scaling
- Query result caching with Redis

### Caching Strategy
- Session data in Redis
- Rate limiting counters in Redis
- Password reset tokens in Redis
- MFA setup tokens in Redis

### File Storage Optimization
- MongoDB GridFS for large files
- File integrity validation
- Automatic cleanup of old files
- Virus scanning integration ready

## 🚨 Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check MongoDB status
sudo systemctl status mongod

# Check Redis status
sudo systemctl status redis-server

# View application logs
sudo journalctl -u auth-service -f
```

#### Permission Errors
```bash
# Fix file permissions
sudo chown -R www-data:www-data /opt/auth-system
sudo chmod -R 755 /opt/auth-system

# Fix log directory permissions
sudo mkdir -p /var/log/auth-system
sudo chown www-data:www-data /var/log/auth-system
```

#### Email Issues
```bash
# Test SMTP connection
npm run test:email

# Check email logs
grep "email" /var/log/auth-system/auth-system.log
```

### Debug Mode
```bash
# Enable debug logging
NODE_ENV=development LOG_LEVEL=debug npm start

# View debug logs
tail -f logs/auth-system.log | grep DEBUG
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/auth-system.git
cd auth-system

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start development server
npm run dev
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review troubleshooting guide
- Contact: support@yourdomain.com

## 🎯 Roadmap

### Upcoming Features
- [ ] OAuth2/OpenID Connect integration
- [ ] SAML SSO support
- [ ] Advanced audit reporting
- [ ] Mobile app authentication
- [ ] Biometric authentication
- [ ] Advanced threat detection
- [ ] API versioning
- [ ] Microservice decomposition

### Version History
- **v1.0.0** - Initial release with core authentication features
- **v1.1.0** - Provider management and file uploads
- **v1.2.0** - GDPR compliance features
- **v1.3.0** - Enhanced security and monitoring

---

**Production Ready** ✅ | **GDPR Compliant** ✅ | **Fully Documented** ✅ | **Security Tested** ✅