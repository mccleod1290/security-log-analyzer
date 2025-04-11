# Security Log Analysis and Visualization Tool

A comprehensive security log analysis platform that provides real-time monitoring, analysis, and visualization of security events across various log sources.

## Features

### Log Ingestion
- Support for multiple log formats (Syslog, Windows Event Log, Apache/Nginx, Firewall logs)
- Real-time log streaming with asyncio
- Unified log schema normalization

### Analysis Engine
- Rule-based attack pattern detection
- Statistical analysis and baseline monitoring
- Time-series anomaly detection
- IP reputation checking
- Threat intelligence integration

### Visualization Dashboard
- Interactive time-series graphs
- Geolocation attack mapping
- Attack vector distribution
- Customizable filters and views

### Alert Management
- Configurable alert thresholds
- Multi-channel notifications (Email, Slack, SMS)
- Smart alert aggregation

## Technical Architecture

### Storage Layer
- Elasticsearch: Primary log storage and search
- PostgreSQL: User management and configuration
- Redis: Real-time processing and caching

### Deployment Options
- Standalone deployment
- Docker containerization
- Kubernetes orchestration

## Prerequisites

- Python 3.9+
- Elasticsearch 8.x
- PostgreSQL 14+
- Redis 6+
- Docker (optional)
- Kubernetes (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mccleod1290/security_log_analyzer.git
cd security_log_analyzer
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

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python scripts/init_db.py
```

## Configuration

The tool can be configured through:
- Environment variables
- Configuration files (config/config.yaml)
- Web interface settings

## Usage

1. Start the application:
```bash
python run.py
```

2. Access the web interface:
```
http://localhost:8000
```

3. Configure log sources in the settings panel

## Development

### Running Tests
```bash
pytest tests/
```

### Building Docker Container
```bash
docker build -t security-log-analyzer .
docker run -p 8000:8000 security-log-analyzer
```

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request 
