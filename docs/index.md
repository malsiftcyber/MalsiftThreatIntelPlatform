# Welcome to Malsift Documentation

![Malsift Logo](assets/logo-text.svg){ width="300" }

## 🚀 Cyber Threat Intelligence Aggregation Platform

Malsift is a comprehensive cyber threat intelligence aggregation platform designed to collect, normalize, and manage threat indicators from multiple sources. Built for on-premise deployment with AWS migration capabilities, Malsift provides advanced deduplication, dark web monitoring, and flexible exclusion management.

## 🎯 Key Features

### Multi-Source Intelligence Aggregation
- **Government Sources**: CISA Known Exploited Vulnerabilities, FBI Cyber Division feeds, DHS Automated Indicator Sharing
- **Open Source Sources**: AlienVault OTX, MISP, OpenPhish, PhishTank, URLhaus (Abuse.ch)
- **Commercial Sources**: VirusTotal, ThreatFox, IBM X-Force Exchange, Recorded Future, CrowdStrike Falcon (free tiers)
- **Custom Feed Support**: Add any threat intelligence source with custom parsers

### Advanced Deduplication System
- **Intelligent Normalization**: IP addresses, domains, URLs, hashes, emails
- **Confidence Score Merging**: Automatically merges duplicate indicators with highest confidence
- **Tag Consolidation**: Combines tags and metadata from multiple sources
- **Duplicate Tracking**: Comprehensive reporting on duplicate detection and resolution

### Dark Web Monitoring
- **Tor Integration**: Built-in Tor proxy support for dark web access
- **Configurable Scraping**: Set custom intervals and source management
- **Content Extraction**: Advanced parsing and indicator extraction from dark web content
- **Source Management**: Add, configure, and monitor dark web sources

### Machine Learning & AI
- **Threat Scoring**: ML-based threat level assessment and prioritization
- **Anomaly Detection**: Identify unusual patterns and potential threats
- **Feature Engineering**: Advanced feature extraction from threat data
- **Model Management**: Train, update, and monitor ML models

### Modern Web Interface
- **React + TypeScript**: Modern, responsive frontend with Tailwind CSS
- **Real-time Dashboard**: Live statistics and threat level distributions
- **Advanced Filtering**: Search, filter, and sort indicators by multiple criteria
- **Feed Management**: Visual interface for managing threat intelligence sources

## 🏗️ Architecture

```mermaid
graph TB
    subgraph "Frontend"
        UI[React UI]
        Auth[Authentication]
    end
    
    subgraph "Backend"
        API[FastAPI]
        ML[ML Engine]
        Parsers[Custom Parsers]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL)]
        Cache[(Redis)]
        Queue[Celery]
    end
    
    subgraph "External Sources"
        CISA[CISA Feeds]
        OTX[AlienVault OTX]
        VT[VirusTotal]
        DarkWeb[Dark Web]
        Custom[Custom Feeds]
    end
    
    UI --> API
    Auth --> API
    API --> ML
    API --> Parsers
    API --> DB
    API --> Cache
    API --> Queue
    Parsers --> External Sources
    ML --> DB
```

## 🚀 Quick Start

1. **Installation**: Follow the [Installation Guide](installation.md)
2. **Configuration**: Set up your [Configuration](configuration.md)
3. **First Run**: Complete the [Quick Start Guide](quick-start.md)

## 📚 Documentation Sections

### Getting Started
- [Installation](installation.md) - Complete setup instructions
- [Quick Start](quick-start.md) - Get up and running quickly
- [Configuration](configuration.md) - Configure your deployment

### User Guide
- [Dashboard](user-guide/dashboard.md) - Overview and monitoring
- [Indicators](user-guide/indicators.md) - Managing threat indicators
- [Feeds](user-guide/feeds.md) - Threat intelligence feeds
- [Sources](user-guide/sources.md) - Data source management
- [Campaigns](user-guide/campaigns.md) - Threat campaign tracking
- [Dark Web](user-guide/darkweb.md) - Dark web monitoring
- [Exclusions](user-guide/exclusions.md) - Indicator exclusion management
- [Jobs](user-guide/jobs.md) - Background job monitoring

### Authentication
- [Overview](auth/overview.md) - Authentication system overview
- [Internal Login](auth/internal-login.md) - Username/password authentication
- [Azure AD](auth/azure-ad.md) - Single sign-on integration
- [Multi-Factor Authentication](auth/mfa.md) - MFA setup and usage

### API Reference
- [Overview](api/overview.md) - API documentation overview
- [Authentication](api/authentication.md) - API authentication
- [Indicators](api/indicators.md) - Threat indicators API
- [Feeds](api/feeds.md) - Feed management API
- [Sources](api/sources.md) - Source management API
- [Campaigns](api/campaigns.md) - Campaign management API
- [Dark Web](api/darkweb.md) - Dark web monitoring API
- [Exclusions](api/exclusions.md) - Exclusion management API
- [Jobs](api/jobs.md) - Job management API
- [ML Scoring](api/ml-scoring.md) - Machine learning API
- [Custom Parsers](api/custom-parsers.md) - Custom parser API

### Advanced Features
- [Machine Learning](advanced/ml.md) - ML threat scoring and analysis
- [Custom Feed Parsers](advanced/custom-parsers.md) - Building custom parsers
- [Dark Web Monitoring](advanced/darkweb.md) - Advanced dark web features
- [Exclusion Management](advanced/exclusions.md) - Advanced exclusion features

### Development
- [Architecture](development/architecture.md) - System architecture overview
- [Contributing](development/contributing.md) - Contributing guidelines
- [API Development](development/api.md) - Backend development guide
- [Frontend Development](development/frontend.md) - Frontend development guide

### Deployment
- [Docker](deployment/docker.md) - Docker deployment guide
- [AWS](deployment/aws.md) - AWS deployment guide
- [Monitoring](deployment/monitoring.md) - Monitoring and observability

### Troubleshooting
- [Common Issues](troubleshooting/common-issues.md) - Common problems and solutions
- [Logs](troubleshooting/logs.md) - Log analysis and debugging
- [Performance](troubleshooting/performance.md) - Performance optimization

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](development/contributing.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 🆘 Support

- **Documentation**: This site contains comprehensive documentation
- **Issues**: Report bugs and feature requests on [GitHub](https://github.com/rebaker501/malsift/issues)
- **Discussions**: Join the conversation on [GitHub Discussions](https://github.com/rebaker501/malsift/discussions)
