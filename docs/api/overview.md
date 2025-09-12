# API Overview

Malsift provides a comprehensive REST API for managing threat intelligence data, feeds, and system configuration.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All API endpoints require authentication. Malsift supports multiple authentication methods:

- **JWT Tokens**: Primary authentication method
- **API Keys**: For service-to-service communication
- **Azure AD**: OAuth2 integration for enterprise deployments

### Getting Started

1. **Obtain Access Token**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "admin123"}'
   ```

2. **Use Token in Requests**:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/v1/indicators
   ```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Internal login |
| POST | `/auth/mfa/login` | MFA verification |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout and invalidate token |
| GET | `/auth/azure-ad/login-url` | Get Azure AD login URL |
| POST | `/auth/azure-ad/login` | Azure AD OAuth2 callback |

### Threat Indicators

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/indicators` | List threat indicators |
| GET | `/indicators/{id}` | Get specific indicator |
| POST | `/indicators` | Create new indicator |
| PUT | `/indicators/{id}` | Update indicator |
| DELETE | `/indicators/{id}` | Delete indicator |
| POST | `/indicators/deduplicate` | Run deduplication |
| GET | `/indicators/stats` | Get indicator statistics |

### Threat Intelligence Feeds

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/feeds` | List configured feeds |
| POST | `/feeds` | Add new feed |
| PUT | `/feeds/{id}` | Update feed configuration |
| DELETE | `/feeds/{id}` | Remove feed |
| POST | `/feeds/fetch/{source}` | Manually fetch feed |
| GET | `/feeds/{id}/status` | Get feed status |

### Data Sources

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sources` | List data sources |
| POST | `/sources` | Add new source |
| PUT | `/sources/{id}` | Update source |
| DELETE | `/sources/{id}` | Remove source |
| GET | `/sources/{id}/health` | Check source health |

### Threat Campaigns

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/campaigns` | List threat campaigns |
| GET | `/campaigns/{id}` | Get campaign details |
| POST | `/campaigns` | Create campaign |
| PUT | `/campaigns/{id}` | Update campaign |
| DELETE | `/campaigns/{id}` | Delete campaign |

### Dark Web Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/darkweb/sources` | List dark web sources |
| POST | `/darkweb/sources` | Add dark web source |
| PUT | `/darkweb/sources/{id}` | Update source |
| DELETE | `/darkweb/sources/{id}` | Remove source |
| POST | `/darkweb/scrape` | Manual scraping |
| GET | `/darkweb/results` | Get scraping results |

### Exclusion Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/exclusions` | List exclusions |
| POST | `/exclusions` | Add exclusion |
| PUT | `/exclusions/{id}` | Update exclusion |
| DELETE | `/exclusions/{id}` | Remove exclusion |
| POST | `/exclusions/test` | Test exclusion pattern |
| POST | `/exclusions/import` | Bulk import exclusions |

### Background Jobs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/jobs` | List background jobs |
| GET | `/jobs/{id}` | Get job details |
| POST | `/jobs/{id}/cancel` | Cancel running job |
| GET | `/jobs/stats` | Get job statistics |

### Machine Learning

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ml/train` | Train ML models |
| POST | `/ml/score/{indicator_id}` | Score indicator |
| GET | `/ml/anomalies` | Get anomaly detection results |
| GET | `/ml/feature-importance` | Get feature importance |
| POST | `/ml/bulk-score` | Bulk score indicators |
| GET | `/ml/model-status` | Get model status |

### Custom Feed Parsers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/custom-parsers/available` | List available parsers |
| POST | `/custom-parsers/validate-config` | Validate parser config |
| POST | `/custom-parsers/test` | Test parser |
| POST | `/custom-parsers/create-source` | Create source with parser |
| GET | `/custom-parsers/templates` | Get parser templates |
| POST | `/custom-parsers/upload` | Upload custom parser |

## Response Format

All API responses follow a consistent JSON format:

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "Field validation failed"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Pagination

List endpoints support pagination:

```json
{
  "success": true,
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 100,
      "pages": 5
    }
  }
}
```

### Pagination Parameters

- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `sort_by`: Sort field
- `sort_order`: asc or desc

## Filtering and Search

Many endpoints support filtering and search:

```bash
# Filter by indicator type
GET /api/v1/indicators?type=ip&confidence=high

# Search by value
GET /api/v1/indicators?search=192.168.1.1

# Date range filtering
GET /api/v1/indicators?created_after=2024-01-01&created_before=2024-01-31
```

## Rate Limiting

API requests are rate-limited to prevent abuse:

- **Authenticated users**: 1000 requests per hour
- **API keys**: 5000 requests per hour
- **Admin users**: 10000 requests per hour

Rate limit headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 422 | Validation Error - Invalid data |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |

## SDKs and Libraries

### Python

```python
from malsift import MalsiftClient

client = MalsiftClient(
    base_url="http://localhost:8000",
    api_key="your-api-key"
)

# Get indicators
indicators = client.indicators.list(
    type="ip",
    limit=100
)

# Create indicator
indicator = client.indicators.create(
    value="192.168.1.1",
    type="ip",
    source="manual"
)
```

### JavaScript/TypeScript

```typescript
import { MalsiftClient } from '@malsift/client';

const client = new MalsiftClient({
  baseUrl: 'http://localhost:8000',
  apiKey: 'your-api-key'
});

// Get indicators
const indicators = await client.indicators.list({
  type: 'ip',
  limit: 100
});

// Create indicator
const indicator = await client.indicators.create({
  value: '192.168.1.1',
  type: 'ip',
  source: 'manual'
});
```

## Webhooks

Malsift supports webhooks for real-time notifications:

```json
{
  "event": "indicator.created",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "indicator": {
      "id": "123",
      "value": "192.168.1.1",
      "type": "ip",
      "source": "cisa"
    }
  }
}
```

### Supported Events

- `indicator.created`
- `indicator.updated`
- `indicator.deleted`
- `feed.fetched`
- `campaign.created`
- `exclusion.created`

## Testing

### Interactive Documentation

Visit `http://localhost:8000/docs` for interactive API documentation powered by Swagger UI.

### Postman Collection

Download the Postman collection for testing:

```bash
curl -o malsift-api.postman_collection.json \
  http://localhost:8000/api/v1/docs/postman
```

## Support

For API support:

1. Check the [Authentication Guide](authentication.md)
2. Review [Error Handling](troubleshooting/common-issues.md)
3. Open an issue on [GitHub](https://github.com/rebaker501/malsift/issues)
4. Join discussions on [GitHub Discussions](https://github.com/rebaker501/malsift/discussions)
