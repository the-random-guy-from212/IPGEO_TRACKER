# IP Geolocation Tracker

A professional-grade IP geolocation and route monitoring service with real-time tracking capabilities.

## Features

- Real-time IP monitoring with WebSocket support
- Modern tech-themed UI
- Professional data visualization
- Bulk IP processing with async support
- Historical tracking and analytics
- Rate limiting and security features
- Comprehensive error handling

## Production Deployment

### Prerequisites

- Python 3.8+
- Redis Server
- SSL Certificates (for HTTPS)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ip-geo-tracker.git
cd ip-geo-tracker
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
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

### Running in Production

1. Using Gunicorn (recommended):
```bash
gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 4 -b 0.0.0.0:5000 ip_geo_locator:app
```

2. Using the built-in server:
```bash
python ip_geo_locator.py
```

### Docker Deployment

1. Build the Docker image:
```bash
docker build -t ip-geo-tracker .
```

2. Run the container:
```bash
docker run -d \
  --name ip-tracker \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  ip-geo-tracker
```

## Security Considerations

- Always use HTTPS in production
- Keep your API keys secure
- Regularly update dependencies
- Monitor rate limits
- Use strong secret keys
- Implement proper firewall rules

## Monitoring

The application includes comprehensive logging in the `logs` directory. Monitor these logs for:
- Application errors
- Rate limit violations
- Security incidents
- Performance metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details 