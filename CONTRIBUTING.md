# Contributing to Malsift Threat Intelligence Platform

Thank you for your interest in contributing to the Malsift Threat Intelligence Platform! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/MalsiftThreatIntelPlatform.git
   cd MalsiftThreatIntelPlatform
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/malsiftcyber/MalsiftThreatIntelPlatform.git
   ```

## Development Setup

### Prerequisites

- Python 3.9+
- Node.js 18+
- Docker and Docker Compose
- PostgreSQL 13+
- Redis 6+

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

### Docker Setup

1. Start all services:
   ```bash
   docker-compose up -d
   ```

2. Access the application:
   - Frontend: http://localhost:3000
   - API: http://localhost:8000
   - Documentation: http://localhost:8000/docs

## Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Test your changes** thoroughly

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add: brief description of your changes"
   ```

## Submitting Changes

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Description of changes
   - Testing performed
   - Screenshots (if applicable)
   - Breaking changes (if any)

## Coding Standards

### Python (Backend)

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for all function parameters and return values
- Write comprehensive docstrings for all functions and classes
- Use Black for code formatting
- Use isort for import sorting

Example:
```python
from typing import List, Optional
from fastapi import FastAPI, HTTPException

def process_threat_indicators(
    indicators: List[str], 
    severity_filter: Optional[str] = None
) -> List[dict]:
    """
    Process threat indicators and apply severity filtering.
    
    Args:
        indicators: List of threat indicators to process
        severity_filter: Optional severity level to filter by
        
    Returns:
        List of processed threat indicators
        
    Raises:
        HTTPException: If processing fails
    """
    # Implementation here
    pass
```

### TypeScript/React (Frontend)

- Use TypeScript for all components
- Follow React best practices
- Use functional components with hooks
- Implement proper error handling
- Use ESLint and Prettier for formatting

Example:
```typescript
import React, { useState, useEffect } from 'react';

interface ThreatIndicatorProps {
  indicator: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  onSelect: (indicator: string) => void;
}

export const ThreatIndicator: React.FC<ThreatIndicatorProps> = ({
  indicator,
  severity,
  onSelect
}) => {
  const [isSelected, setIsSelected] = useState(false);

  useEffect(() => {
    // Component logic here
  }, [indicator]);

  return (
    <div className={`threat-indicator ${severity}`}>
      {/* Component JSX */}
    </div>
  );
};
```

## Testing

### Backend Testing

- Write unit tests for all functions and classes
- Use pytest for testing framework
- Aim for >80% code coverage
- Test API endpoints with FastAPI TestClient

```bash
cd backend
pytest tests/ -v --cov=app
```

### Frontend Testing

- Write unit tests for React components
- Use Jest and React Testing Library
- Test user interactions and component behavior

```bash
cd frontend
npm test
```

## Documentation

- Update documentation for any new features
- Include code examples in docstrings
- Update API documentation for endpoint changes
- Keep README.md up to date

## Pull Request Process

1. **Ensure tests pass** and coverage requirements are met
2. **Update documentation** as needed
3. **Request review** from maintainers
4. **Address feedback** promptly
5. **Squash commits** if requested

## Issue Reporting

When reporting issues, please include:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Screenshots or error logs if applicable

## Security

- Report security vulnerabilities to security@malsiftcyber.com
- Do not create public issues for security problems
- Follow responsible disclosure practices

## Questions?

- Join our [Discussions](https://github.com/malsiftcyber/MalsiftThreatIntelPlatform/discussions)
- Check existing [Issues](https://github.com/malsiftcyber/MalsiftThreatIntelPlatform/issues)
- Contact maintainers directly

Thank you for contributing to Malsift Threat Intelligence Platform!
