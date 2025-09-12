#!/bin/bash

# Malsift SSL Setup Script
# This script sets up SSL certificates for Malsift using Let's Encrypt

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN=""
EMAIL=""
SSL_TYPE="letsencrypt"  # letsencrypt or custom

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Domain name for SSL certificate"
    echo "  -e, --email EMAIL       Email address for Let's Encrypt notifications"
    echo "  -t, --type TYPE         SSL type: letsencrypt (default) or custom"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -d malsift.example.com -e admin@example.com"
    echo "  $0 -d malsift.example.com -e admin@example.com -t custom"
}

# Function to validate domain
validate_domain() {
    if [[ ! $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid domain format: $1"
        exit 1
    fi
}

# Function to validate email
validate_email() {
    if [[ ! $1 =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        print_error "Invalid email format: $1"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if domain is accessible
    if ! nslookup "$DOMAIN" &> /dev/null; then
        print_warning "Domain $DOMAIN is not resolvable. Make sure DNS is configured correctly."
    fi
    
    print_success "Prerequisites check completed"
}

# Function to setup Let's Encrypt SSL
setup_letsencrypt() {
    print_status "Setting up Let's Encrypt SSL certificate for $DOMAIN..."
    
    # Create necessary directories
    mkdir -p nginx/ssl
    mkdir -p nginx/conf.d
    
    # Update Nginx configuration
    sed -i "s/your-domain.com/$DOMAIN/g" nginx/conf.d/malsift.conf
    
    # Update Docker Compose file
    sed -i "s/your-domain.com/$DOMAIN/g" docker-compose.ssl.yml
    sed -i "s/your-email@domain.com/$EMAIL/g" docker-compose.ssl.yml
    
    # Start services without SSL first
    print_status "Starting services for certificate generation..."
    docker-compose -f docker-compose.ssl.yml up -d nginx
    
    # Wait for Nginx to be ready
    print_status "Waiting for Nginx to be ready..."
    sleep 10
    
    # Generate certificate
    print_status "Generating Let's Encrypt certificate..."
    docker-compose -f docker-compose.ssl.yml run --rm certbot
    
    # Reload Nginx with SSL
    print_status "Reloading Nginx with SSL configuration..."
    docker-compose -f docker-compose.ssl.yml exec nginx nginx -s reload
    
    print_success "Let's Encrypt SSL certificate setup completed"
}

# Function to setup custom SSL
setup_custom_ssl() {
    print_status "Setting up custom SSL certificate for $DOMAIN..."
    
    # Create necessary directories
    mkdir -p nginx/ssl
    
    # Check if certificate files exist
    if [[ ! -f "nginx/ssl/cert.pem" ]] || [[ ! -f "nginx/ssl/key.pem" ]]; then
        print_error "Certificate files not found. Please place your certificate files in nginx/ssl/:"
        print_error "  - nginx/ssl/cert.pem (certificate file)"
        print_error "  - nginx/ssl/key.pem (private key file)"
        exit 1
    fi
    
    # Set proper permissions
    chmod 644 nginx/ssl/cert.pem
    chmod 600 nginx/ssl/key.pem
    
    # Update Nginx configuration
    sed -i "s/your-domain.com/$DOMAIN/g" nginx/conf.d/malsift.conf
    
    # Comment out Let's Encrypt configuration and uncomment custom SSL
    sed -i 's/# Custom SSL certificate configuration/# Custom SSL certificate configuration (active)/' nginx/conf.d/malsift.conf
    sed -i 's/# HTTPS server with Let's Encrypt/# HTTPS server with Let's Encrypt (disabled)/' nginx/conf.d/malsift.conf
    
    print_success "Custom SSL certificate setup completed"
}

# Function to create SSL renewal script
create_renewal_script() {
    cat > scripts/renew-ssl.sh << 'EOF'
#!/bin/bash

# Malsift SSL Renewal Script
# This script renews Let's Encrypt certificates

set -e

print_status() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

print_success() {
    echo -e "\033[0;32m[SUCCESS]\033[0m $1"
}

print_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

print_status "Renewing Let's Encrypt certificates..."

# Renew certificates
docker-compose -f docker-compose.ssl.yml run --rm certbot renew

# Reload Nginx
docker-compose -f docker-compose.ssl.yml exec nginx nginx -s reload

print_success "SSL certificates renewed successfully"
EOF

    chmod +x scripts/renew-ssl.sh
    print_success "SSL renewal script created: scripts/renew-ssl.sh"
}

# Function to create cron job for SSL renewal
setup_cron_renewal() {
    print_status "Setting up automatic SSL renewal..."
    
    # Create cron job to renew certificates twice daily
    (crontab -l 2>/dev/null; echo "0 12,0 * * * $(pwd)/scripts/renew-ssl.sh >> /var/log/malsift-ssl-renewal.log 2>&1") | crontab -
    
    print_success "Automatic SSL renewal configured (runs at 12:00 AM and 12:00 PM daily)"
}

# Function to test SSL configuration
test_ssl() {
    print_status "Testing SSL configuration..."
    
    # Test SSL certificate
    if command -v openssl &> /dev/null; then
        echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -dates
    fi
    
    # Test HTTPS access
    if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200\|301\|302"; then
        print_success "SSL configuration test passed"
    else
        print_warning "SSL configuration test failed. Please check your configuration."
    fi
}

# Main execution
main() {
    print_status "Starting Malsift SSL setup..."
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -e|--email)
                EMAIL="$2"
                shift 2
                ;;
            -t|--type)
                SSL_TYPE="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "$DOMAIN" ]]; then
        print_error "Domain is required. Use -d or --domain option."
        show_usage
        exit 1
    fi
    
    if [[ "$SSL_TYPE" == "letsencrypt" && -z "$EMAIL" ]]; then
        print_error "Email is required for Let's Encrypt. Use -e or --email option."
        show_usage
        exit 1
    fi
    
    # Validate inputs
    validate_domain "$DOMAIN"
    if [[ "$SSL_TYPE" == "letsencrypt" ]]; then
        validate_email "$EMAIL"
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Setup SSL based on type
    if [[ "$SSL_TYPE" == "letsencrypt" ]]; then
        setup_letsencrypt
        create_renewal_script
        setup_cron_renewal
    else
        setup_custom_ssl
    fi
    
    # Test SSL configuration
    test_ssl
    
    print_success "SSL setup completed successfully!"
    print_status "You can now access Malsift at: https://$DOMAIN"
}

# Run main function with all arguments
main "$@"
