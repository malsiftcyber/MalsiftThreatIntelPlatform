# SSL Certificate Setup

Malsift supports SSL certificates for secure HTTPS access. You can use either Let's Encrypt (free) or custom SSL certificates.

## Overview

The SSL setup includes:

- **Nginx Reverse Proxy**: Handles SSL termination and routing
- **Let's Encrypt Integration**: Automatic certificate generation and renewal
- **Custom Certificate Support**: Use your own SSL certificates
- **Security Headers**: HSTS, CSP, and other security enhancements
- **Rate Limiting**: Protection against abuse

## Prerequisites

- Domain name pointing to your server
- Ports 80 and 443 open and accessible
- Docker and Docker Compose installed
- Root or sudo access

## Quick Setup

### Let's Encrypt (Recommended)

```bash
# Make the SSL setup script executable
chmod +x scripts/ssl-setup.sh

# Run the SSL setup script
./scripts/ssl-setup.sh -d your-domain.com -e your-email@domain.com
```

### Custom SSL Certificate

```bash
# Place your certificate files
cp your-certificate.crt nginx/ssl/cert.pem
cp your-private-key.key nginx/ssl/key.pem

# Run the SSL setup script
./scripts/ssl-setup.sh -d your-domain.com -t custom
```

## Manual Setup

### 1. Let's Encrypt Setup

#### Step 1: Configure Domain

Update the Nginx configuration with your domain:

```bash
# Edit the Nginx configuration
sed -i "s/your-domain.com/YOUR_DOMAIN/g" nginx/conf.d/malsift.conf
```

#### Step 2: Start Services

```bash
# Start the SSL-enabled services
docker-compose -f docker-compose.ssl.yml up -d nginx
```

#### Step 3: Generate Certificate

```bash
# Generate Let's Encrypt certificate
docker-compose -f docker-compose.ssl.yml run --rm certbot \
  certonly --webroot --webroot-path=/var/www/html \
  --email your-email@domain.com --agree-tos --no-eff-email \
  -d your-domain.com
```

#### Step 4: Reload Nginx

```bash
# Reload Nginx with SSL configuration
docker-compose -f docker-compose.ssl.yml exec nginx nginx -s reload
```

### 2. Custom SSL Certificate Setup

#### Step 1: Prepare Certificate Files

Place your certificate files in the `nginx/ssl/` directory:

```bash
# Create SSL directory
mkdir -p nginx/ssl

# Copy your certificate files
cp your-certificate.crt nginx/ssl/cert.pem
cp your-private-key.key nginx/ssl/key.pem

# Set proper permissions
chmod 644 nginx/ssl/cert.pem
chmod 600 nginx/ssl/key.pem
```

#### Step 2: Update Configuration

Edit `nginx/conf.d/malsift.conf` and comment out the Let's Encrypt configuration, uncomment the custom SSL configuration.

#### Step 3: Start Services

```bash
# Start all services with SSL
docker-compose -f docker-compose.ssl.yml up -d
```

## Configuration Files

### Nginx Configuration

The main Nginx configuration is in `nginx/nginx.conf`:

```nginx
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
```

### SSL Configuration

SSL settings in `nginx/conf.d/malsift.conf`:

```nginx
# SSL security settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

## Certificate Renewal

### Automatic Renewal

The setup script creates a cron job for automatic renewal:

```bash
# Check renewal cron job
crontab -l | grep malsift-ssl-renewal

# Manual renewal
./scripts/renew-ssl.sh
```

### Let's Encrypt Renewal

Let's Encrypt certificates expire after 90 days. The automatic renewal runs twice daily:

```bash
# Test renewal (dry run)
docker-compose -f docker-compose.ssl.yml run --rm certbot renew --dry-run

# Force renewal
docker-compose -f docker-compose.ssl.yml run --rm certbot renew --force-renewal
```

## Security Features

### Security Headers

- **HSTS**: Forces HTTPS connections
- **CSP**: Content Security Policy
- **X-Frame-Options**: Prevents clickjacking
- **X-XSS-Protection**: XSS protection
- **X-Content-Type-Options**: Prevents MIME sniffing

### Rate Limiting

- **API endpoints**: 10 requests per second
- **Login endpoints**: 5 requests per minute
- **Burst handling**: Configurable burst limits

### SSL Configuration

- **TLS 1.2 and 1.3**: Modern TLS protocols only
- **Strong ciphers**: AES-256-GCM with ECDHE
- **Perfect Forward Secrecy**: ECDHE key exchange
- **OCSP Stapling**: Improved performance

## Troubleshooting

### Common Issues

#### Certificate Not Found

```bash
# Check certificate files
ls -la nginx/ssl/
ls -la /etc/letsencrypt/live/your-domain.com/

# Verify certificate
openssl x509 -in nginx/ssl/cert.pem -text -noout
```

#### Nginx Configuration Errors

```bash
# Test Nginx configuration
docker-compose -f docker-compose.ssl.yml exec nginx nginx -t

# Check Nginx logs
docker-compose -f docker-compose.ssl.yml logs nginx
```

#### Let's Encrypt Rate Limits

Let's Encrypt has rate limits:
- 50 certificates per registered domain per week
- 300 new orders per account per 3 hours
- 5 duplicate certificates per week

#### SSL Test

Test your SSL configuration:

```bash
# Test SSL certificate
echo | openssl s_client -servername your-domain.com -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates

# Test HTTPS access
curl -I https://your-domain.com
```

### Logs

Check SSL-related logs:

```bash
# Nginx logs
docker-compose -f docker-compose.ssl.yml logs nginx

# Certbot logs
docker-compose -f docker-compose.ssl.yml logs certbot

# SSL renewal logs
tail -f /var/log/malsift-ssl-renewal.log
```

## Advanced Configuration

### Custom SSL Configuration

For advanced SSL settings, edit `nginx/conf.d/malsift.conf`:

```nginx
# Custom SSL settings
ssl_buffer_size 4k;
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### Multiple Domains

To support multiple domains:

```nginx
server {
    listen 443 ssl http2;
    server_name domain1.com domain2.com;
    
    ssl_certificate /etc/letsencrypt/live/domain1.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain1.com/privkey.pem;
    
    # ... rest of configuration
}
```

### SSL Certificate Chain

For custom certificates, ensure the certificate chain is complete:

```bash
# Combine certificate and chain
cat your-certificate.crt your-chain.crt > nginx/ssl/cert.pem
```

## Monitoring

### SSL Certificate Monitoring

Monitor certificate expiration:

```bash
# Check certificate expiration
openssl x509 -in nginx/ssl/cert.pem -noout -dates

# Set up monitoring alerts
echo "SSL certificate expires in $(openssl x509 -in nginx/ssl/cert.pem -noout -enddate | cut -d= -f2)"
```

### SSL Configuration Monitoring

Monitor SSL configuration with tools like:
- SSL Labs SSL Test
- Mozilla Observatory
- Security Headers

## Best Practices

1. **Use Let's Encrypt**: Free, automated, and trusted
2. **Enable HSTS**: Force HTTPS connections
3. **Regular Renewal**: Monitor certificate expiration
4. **Strong Ciphers**: Use modern TLS configurations
5. **Security Headers**: Implement comprehensive security headers
6. **Rate Limiting**: Protect against abuse
7. **Monitoring**: Monitor SSL configuration and expiration

## Support

For SSL-related issues:

1. Check the [Troubleshooting Guide](../troubleshooting/common-issues.md)
2. Review SSL logs and configuration
3. Test SSL configuration with online tools
4. Open an issue on [GitHub](https://github.com/rebaker501/malsift/issues)
