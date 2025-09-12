# Machine Learning Threat Scoring & Custom Feed Parsers

## Overview

Malsift now includes advanced machine learning capabilities for threat scoring and prioritization, as well as a flexible custom feed parser system for organization-specific threat intelligence sources.

## 🧠 Machine Learning Threat Scoring

### Features

- **Automated Threat Level Prediction**: Uses Random Forest classifier to predict threat levels
- **Feature Engineering**: Extracts 18+ features from indicators and sources
- **Anomaly Detection**: Identifies unusual indicators using Isolation Forest
- **Model Training**: Trains on historical data with automatic feature importance analysis
- **Confidence Scoring**: Provides confidence levels for predictions
- **Fallback Mechanisms**: Manual scoring when ML models are unavailable

### ML Features Extracted

1. **Source Credibility**
   - Source reputation score
   - Source type weight (government, commercial, open source)

2. **Temporal Features**
   - Days since first seen
   - Days since last seen
   - Frequency score

3. **Indicator Characteristics**
   - Indicator type weight
   - Value length and complexity
   - Entropy calculation

4. **Threat Context**
   - Number of tags
   - Threat keyword count
   - Malware family mentions

5. **External Validation**
   - External reputation scores
   - Community confidence

6. **Network Features**
   - ASN reputation
   - Geolocation risk
   - TLD risk assessment

7. **Behavioral Features**
   - Attack pattern detection
   - Campaign association

### API Endpoints

#### Train ML Model
```bash
POST /api/v1/ml/train
```

Trains the machine learning model with historical data.

#### Score Individual Indicator
```bash
POST /api/v1/ml/score/{indicator_id}
```

Scores a specific indicator using ML prediction.

#### Detect Anomalies
```bash
GET /api/v1/ml/anomalies?limit=100
```

Detects anomalous indicators using Isolation Forest.

#### Get Feature Importance
```bash
GET /api/v1/ml/feature-importance
```

Returns feature importance from the trained model.

#### Bulk Score Indicators
```bash
POST /api/v1/ml/bulk-score
{
  "indicator_ids": [1, 2, 3, 4, 5]
}
```

Scores multiple indicators in batch.

#### Update Threat Levels
```bash
POST /api/v1/ml/update-threat-levels?confidence_threshold=0.7&limit=1000
```

Updates threat levels using ML predictions.

#### Model Status
```bash
GET /api/v1/ml/model-status
```

Returns the status of ML models.

### Example Usage

```python
import requests

# Train the model
response = requests.post("http://localhost:8000/api/v1/ml/train")
print(response.json())

# Score an indicator
response = requests.post("http://localhost:8000/api/v1/ml/score/123")
result = response.json()
print(f"Predicted threat level: {result['predicted_threat_level']}")
print(f"Confidence: {result['confidence']}")

# Detect anomalies
response = requests.get("http://localhost:8000/api/v1/ml/anomalies?limit=50")
anomalies = response.json()
print(f"Found {anomalies['total_detected']} anomalies")
```

## 🔧 Custom Feed Parsers

### Overview

The custom feed parser system allows organizations to integrate their own threat intelligence sources with flexible parsing capabilities.

### Supported Parser Types

1. **JSON Parser**: For JSON APIs and feeds
2. **CSV Parser**: For CSV files and tabular data
3. **XML Parser**: For XML feeds and structured data
4. **Custom Parser**: For complex or proprietary formats

### Built-in Parsers

#### JSON Parser Configuration
```json
{
  "parser_type": "json",
  "url": "https://api.example.com/threats",
  "headers": {
    "Authorization": "Bearer YOUR_API_KEY",
    "Accept": "application/json"
  },
  "indicator_path": "data.threats",
  "value_field": "indicator",
  "type_field": "type",
  "description_field": "description",
  "tags_field": "tags",
  "threat_level_field": "severity"
}
```

#### CSV Parser Configuration
```json
{
  "parser_type": "csv",
  "url": "https://example.com/threats.csv",
  "delimiter": ",",
  "has_header": true,
  "value_column": 0,
  "type_column": 1,
  "description_column": 2,
  "tags_column": 3,
  "threat_level_column": 4
}
```

#### XML Parser Configuration
```json
{
  "parser_type": "xml",
  "url": "https://example.com/threats.xml",
  "indicator_xpath": ".//threat",
  "value_xpath": "./indicator",
  "type_xpath": "./type",
  "description_xpath": "./description",
  "tags_xpath": "./tags",
  "threat_level_xpath": "./severity"
}
```

### Custom Parser Development

#### Creating a Custom Parser

1. **Create a Python file** in the `custom_parsers/` directory
2. **Extend the CustomFeedParser class**
3. **Implement required methods**

Example custom parser:

```python
from app.services.custom_feed_parsers import CustomFeedParser
from app.schemas.threat_intelligence import ThreatIndicatorCreate, IndicatorType, ThreatLevel

class MyCustomParser(CustomFeedParser):
    async def fetch_data(self):
        """Fetch data from your source"""
        url = self.config.get('url')
        headers = {'Authorization': f'Bearer {self.config.get("api_key")}'}
        
        async with self.session.get(url, headers=headers) as response:
            return await response.json()
    
    def parse_indicators(self, data):
        """Parse your data format"""
        indicators = []
        
        for item in data.get('threats', []):
            indicator = ThreatIndicatorCreate(
                value=item.get('indicator'),
                indicator_type=IndicatorType.IP_ADDRESS,
                threat_level=ThreatLevel.HIGH,
                description=item.get('description', 'Custom threat'),
                source_id=self.source.id,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=item.get('tags', []),
                metadata={'custom_feed': True}
            )
            indicators.append(indicator)
        
        return indicators
```

#### Advanced Custom Parser Features

- **Rate Limiting**: Built-in rate limiting support
- **Caching**: Cache responses to reduce API calls
- **Error Handling**: Retry logic and error recovery
- **Authentication**: Support for various auth methods
- **Data Transformation**: Complex data processing

### API Endpoints

#### Get Available Parsers
```bash
GET /api/v1/custom-parsers/available
```

Returns list of available parser types.

#### Validate Configuration
```bash
POST /api/v1/custom-parsers/validate-config
{
  "parser_type": "json",
  "url": "https://api.example.com/threats",
  "indicator_path": "data.threats"
}
```

Validates parser configuration.

#### Test Parser
```bash
POST /api/v1/custom-parsers/test
{
  "parser_type": "json",
  "url": "https://api.example.com/threats",
  "indicator_path": "data.threats"
}
```

Tests parser configuration with sample data.

#### Create Custom Source
```bash
POST /api/v1/custom-parsers/create-source
{
  "source_data": {
    "name": "My Custom Feed",
    "description": "Custom threat intelligence feed",
    "url": "https://api.example.com/threats",
    "source_type": "custom"
  },
  "parser_config": {
    "parser_type": "json",
    "indicator_path": "data.threats"
  }
}
```

Creates a new threat source with custom parser.

#### Upload Custom Parser
```bash
POST /api/v1/custom-parsers/upload-custom-parser
# Upload Python file
```

Uploads a custom parser Python file.

#### List Custom Parsers
```bash
GET /api/v1/custom-parsers/custom-parsers
```

Lists all custom parser files.

#### Get Parser Templates
```bash
GET /api/v1/custom-parsers/templates
```

Returns configuration templates for different parser types.

### Example Usage

```python
import requests

# Get available parsers
response = requests.get("http://localhost:8000/api/v1/custom-parsers/available")
parsers = response.json()
print(f"Available parsers: {parsers['all_parsers']}")

# Validate configuration
config = {
    "parser_type": "json",
    "url": "https://api.example.com/threats",
    "indicator_path": "data.threats"
}
response = requests.post("http://localhost:8000/api/v1/custom-parsers/validate-config", json=config)
print(f"Valid: {response.json()['valid']}")

# Test parser
response = requests.post("http://localhost:8000/api/v1/custom-parsers/test", json=config)
result = response.json()
print(f"Found {result['indicators_found']} indicators")
```

## 🔄 Integration with Existing Features

### ML Integration

- **Automatic Scoring**: New indicators are automatically scored
- **Deduplication**: ML scores influence deduplication decisions
- **Exclusions**: ML confidence affects exclusion processing
- **Dashboard**: ML metrics displayed in web interface

### Custom Parser Integration

- **Feed Management**: Custom sources appear in feed management
- **Job Processing**: Custom parsers run in background jobs
- **Monitoring**: Custom parser metrics in monitoring
- **API Access**: Custom indicators available through API

## 📊 Monitoring and Metrics

### ML Metrics

- Model accuracy and performance
- Feature importance rankings
- Anomaly detection rates
- Prediction confidence distributions

### Custom Parser Metrics

- Parser execution times
- Success/failure rates
- Indicators processed per parser
- Error rates and types

## 🚀 Best Practices

### ML Best Practices

1. **Regular Training**: Retrain models weekly with new data
2. **Feature Monitoring**: Monitor feature importance changes
3. **Confidence Thresholds**: Use appropriate confidence thresholds
4. **Model Validation**: Validate models on test datasets

### Custom Parser Best Practices

1. **Error Handling**: Implement robust error handling
2. **Rate Limiting**: Respect API rate limits
3. **Data Validation**: Validate parsed data
4. **Logging**: Add comprehensive logging
5. **Testing**: Test parsers thoroughly before deployment

## 🔧 Configuration

### ML Configuration

```python
# In settings
ML_MODEL_DIR = "models"
ML_TRAINING_INTERVAL = 7  # days
ML_CONFIDENCE_THRESHOLD = 0.7
ML_ANOMALY_CONTAMINATION = 0.1
```

### Custom Parser Configuration

```python
# Directory for custom parsers
CUSTOM_PARSERS_DIR = "custom_parsers"

# Parser validation settings
PARSER_VALIDATION_ENABLED = True
PARSER_TIMEOUT = 30  # seconds
```

## 📈 Performance Considerations

### ML Performance

- **Training Time**: ~5-10 minutes for 10k indicators
- **Prediction Time**: ~1ms per indicator
- **Memory Usage**: ~100MB for trained models
- **Storage**: ~50MB for model files

### Custom Parser Performance

- **Execution Time**: Varies by parser complexity
- **Memory Usage**: Minimal for most parsers
- **Network**: Depends on API response times
- **Caching**: Reduces API calls and improves performance

## 🔒 Security Considerations

### ML Security

- Model files are stored locally
- No sensitive data in model files
- Feature extraction doesn't expose raw data
- Confidence scores help identify uncertain predictions

### Custom Parser Security

- Parser files are validated before execution
- Sandboxed execution environment
- Input validation and sanitization
- Error messages don't expose sensitive data

## 🛠️ Troubleshooting

### Common ML Issues

1. **Low Accuracy**: Insufficient training data
2. **High False Positives**: Adjust confidence thresholds
3. **Model Not Loading**: Check model file permissions
4. **Slow Training**: Reduce feature set or use sampling

### Common Parser Issues

1. **Configuration Errors**: Validate configuration
2. **Network Timeouts**: Increase timeout values
3. **Authentication Failures**: Check API keys
4. **Data Format Changes**: Update parser logic

## 📚 Additional Resources

- [Scikit-learn Documentation](https://scikit-learn.org/)
- [FastAPI File Upload](https://fastapi.tiangolo.com/tutorial/file-upload/)
- [Custom Parser Examples](custom_parsers/example_custom_parser.py)
- [ML Model Training Guide](docs/ML_TRAINING_GUIDE.md)
