# Malsift Threat Intelligence Platform

A comprehensive threat intelligence platform that aggregates, processes, and analyzes security feeds from multiple sources to provide actionable threat intelligence.

## Features

- **Multi-Source Feed Aggregation**: Collects threat intelligence from both open-source and premium feeds
- **Machine Learning Scoring**: Advanced ML algorithms for threat scoring and prioritization
- **Custom Parser Support**: Extensible framework for custom feed parsers
- **Authentication & Authorization**: Secure user management and API access control
- **Real-time Processing**: Live threat intelligence processing and alerting
- **Documentation**: Comprehensive API documentation and deployment guides

## Architecture

The platform consists of several key components:

- **Backend API**: FastAPI-based REST API with authentication and ML scoring
- **Frontend**: React-based web interface for threat intelligence visualization
- **Custom Parsers**: Extensible parser framework for various threat feed formats
- **ML Services**: Machine learning models for threat scoring and classification
- **Documentation**: MkDocs-based documentation site

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.9+
- Node.js 16+

### Installation

1. Clone the repository:
```bash
git clone https://github.com/malsiftcyber/MalsiftThreatIntelPlatform.git
cd MalsiftThreatIntelPlatform
```

2. Set up SSL certificates (for production):
```bash
chmod +x scripts/ssl-setup.sh
./scripts/ssl-setup.sh
```

3. Start the platform:
```bash
docker-compose -f docker-compose.ssl.yml up -d
```

### Development Setup

1. Backend setup:
```bash
cd backend
pip install -r requirements.txt
```

2. Frontend setup:
```bash
cd frontend
npm install
npm start
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Quick Start](docs/quick-start.md)
- [API Overview](docs/api/overview.md)
- [Authentication](docs/AUTHENTICATION.md)
- [ML and Custom Parsers](docs/ML_AND_CUSTOM_PARSERS.md)
- [SSL Deployment](docs/deployment/ssl.md)

## API Endpoints

- **Authentication**: `/api/v1/auth/` - User authentication and management
- **ML Scoring**: `/api/v1/ml-scoring/` - Threat scoring and classification
- **Custom Parsers**: `/api/v1/custom-parsers/` - Custom feed parser management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue on GitHub or contact the development team.
