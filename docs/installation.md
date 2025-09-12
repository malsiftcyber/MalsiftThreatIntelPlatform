# Installation Guide

This guide will walk you through installing and setting up Malsift on your system.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 50GB+ available space
- **Network**: Internet access for threat intelligence feeds

### Software Requirements

- **Docker**: 20.10+ and Docker Compose
- **Git**: Latest version
- **Python**: 3.11+ (for development)
- **Node.js**: 18+ (for frontend development)

### SSL Requirements (Optional)

- **Domain Name**: For SSL certificate setup
- **Ports 80 & 443**: Open and accessible (for SSL)
- **DNS Configuration**: Domain pointing to your server

## Installation Methods

### Method 1: Docker (Recommended)

The easiest way to get started with Malsift is using Docker Compose.

#### 1. Clone the Repository

```bash
git clone https://github.com/rebaker501/malsift.git
cd malsift
```

#### 2. Configure Environment

```bash
# Copy the example environment file
cp backend/.env.example backend/.env

# Edit the environment file with your settings
nano backend/.env
```

#### 3. Start the Services

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps
```

#### 4. Initialize the Database

```bash
# Run database migrations
docker-compose exec backend alembic upgrade head

# Create initial admin user
docker-compose exec backend python -m app.scripts.create_admin
```

#### 5. Access the Application

- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Grafana Dashboard**: http://localhost:3001

### Method 2: SSL-Enabled Deployment

For production deployments with SSL certificates:

#### 1. SSL Setup with Let's Encrypt (Recommended)

```bash
# Make the SSL setup script executable
chmod +x scripts/ssl-setup.sh

# Run SSL setup with your domain
./scripts/ssl-setup.sh -d your-domain.com -e your-email@domain.com
```

#### 2. SSL Setup with Custom Certificate

```bash
# Place your certificate files
cp your-certificate.crt nginx/ssl/cert.pem
cp your-private-key.key nginx/ssl/key.pem

# Run SSL setup
./scripts/ssl-setup.sh -d your-domain.com -t custom
```

#### 3. Access the Secure Application

- **Web Interface**: https://your-domain.com
- **API Documentation**: https://your-domain.com/docs
- **Grafana Dashboard**: https://your-domain.com:3001

## Configuration

### Environment Variables

Key configuration options in `backend/.env`:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/malsift

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# SSL Configuration
DOMAIN=your-domain.com
SSL_TYPE=letsencrypt  # or custom

# API Keys (optional)
VIRUSTOTAL_API_KEY=your-vt-api-key
ALIENVAULT_API_KEY=your-otx-api-key
THREATFOX_API_KEY=your-threatfox-api-key

# Azure AD (optional)
AZURE_AD_TENANT_ID=your-tenant-id
AZURE_AD_CLIENT_ID=your-client-id
AZURE_AD_CLIENT_SECRET=your-client-secret
AZURE_AD_REDIRECT_URI=https://your-domain.com/auth/azure-ad/callback
```

### SSL Configuration

#### Let's Encrypt Settings

The SSL setup script automatically configures:
- Nginx reverse proxy with SSL termination
- Let's Encrypt certificate generation
- Automatic certificate renewal (cron job)
- Security headers (HSTS, CSP, etc.)
- Rate limiting and protection

#### Custom SSL Settings

For custom certificates, ensure:
- Certificate file: `nginx/ssl/cert.pem`
- Private key file: `nginx/ssl/key.pem`
- Proper file permissions (644 for cert, 600 for key)

## Authentication Setup

### Default Admin Account

After installation, use these default credentials:
- **Username**: `admin`
- **Password**: `admin123`

**Important**: Change these credentials immediately after first login!

### Internal Authentication

The system includes a complete internal authentication system:
- User registration and management
- Password hashing with bcrypt
- JWT token-based sessions
- Role-based access control

### Azure AD Integration (Optional)

1. **Create Azure AD App Registration**:
   - Go to Azure Portal > App Registrations
   - Create new registration
   - Set redirect URI: `https://your-domain.com/auth/azure-ad/callback`

2. **Configure Environment Variables**:
   ```env
   AZURE_AD_TENANT_ID=your-tenant-id
   AZURE_AD_CLIENT_ID=your-client-id
   AZURE_AD_CLIENT_SECRET=your-client-secret
   AZURE_AD_REDIRECT_URI=https://your-domain.com/auth/azure-ad/callback
   ```

3. **Enable in Web Interface**:
   - Go to Authentication settings
   - Enable Azure AD integration
   - Configure allowed domains

### Multi-Factor Authentication (Optional)

1. **Enable MFA for Your Account**:
   - Go to your profile settings
   - Enable Multi-Factor Authentication
   - Scan QR code with Google/Microsoft Authenticator

2. **Complete Setup**:
   - Enter verification code from authenticator
   - Save backup codes for recovery

## Verification

### Health Checks

```bash
# Check API health
curl http://localhost:8000/health

# Check SSL certificate (if using SSL)
curl -I https://your-domain.com/health

# Check database connection
docker-compose exec backend python -c "from app.core.database import engine; print('Database OK')"

# Check Redis connection
docker-compose exec redis redis-cli ping
```

### SSL Certificate Verification

```bash
# Check certificate expiration
openssl x509 -in nginx/ssl/cert.pem -noout -dates

# Test SSL configuration
./scripts/ssl-setup.sh --test

# Check automatic renewal
crontab -l | grep malsift-ssl-renewal
```

## Next Steps

After installation:

1. **Configure Feeds**: Set up your threat intelligence sources
2. **Create Users**: Add team members and configure permissions
3. **Set Up Monitoring**: Configure alerts and dashboards
4. **Customize**: Add custom feed parsers and exclusions
5. **Enable SSL**: Set up SSL certificates for production use

## Troubleshooting

### Common Issues

#### SSL Certificate Issues

```bash
# Check certificate files
ls -la nginx/ssl/

# Test Nginx configuration
docker-compose -f docker-compose.ssl.yml exec nginx nginx -t

# Check SSL logs
docker-compose -f docker-compose.ssl.yml logs nginx
```

#### Authentication Issues

```bash
# Check authentication logs
docker-compose logs backend | grep auth

# Reset admin password
docker-compose exec backend python -m app.scripts.create_admin --reset
```

#### Database Issues

```bash
# Check database connection
docker-compose exec postgres psql -U malsift_user -d malsift -c "SELECT 1;"

# Run migrations
docker-compose exec backend alembic upgrade head
```

### Logs

Check application logs:

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f nginx

# SSL-related logs
tail -f /var/log/malsift-ssl-renewal.log
```

## Support

If you encounter issues:

1. Check the [Troubleshooting Guide](../troubleshooting/common-issues.md)
2. Review SSL logs and configuration
3. Test SSL configuration with online tools
4. Open an issue on [GitHub](https://github.com/rebaker501/malsift/issues)
5. Join discussions on [GitHub Discussions](https://github.com/rebaker501/malsift/discussions)
