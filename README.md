# IP Geolocation Tracker 🌍

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Flask](https://img.shields.io/badge/flask-2.3.3-blue.svg)](https://flask.palletsprojects.com/)
[![Redis](https://img.shields.io/badge/redis-5.0.1-red.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![WebSocket](https://img.shields.io/badge/websocket-enabled-green.svg)](https://websocket.org/)

A professional-grade IP geolocation and route monitoring service with real-time tracking capabilities. Built with modern technologies and best practices for production deployment.

## ✨ Features

- 🌐 Real-time IP monitoring with WebSocket support
- 🎨 Modern tech-themed UI with dark mode
- 📊 Professional data visualization with interactive maps
- 🔄 Bulk IP processing with async support
- 📈 Historical tracking and analytics
- 🛡️ Rate limiting and security features
- ⚡ Comprehensive error handling and logging
- 🔍 Multiple geolocation API fallbacks
- 🗺️ Interactive map visualization
- 📱 Responsive design for all devices

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Redis Server (optional, for production)
- SSL Certificates (for HTTPS in production)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ip-geo-tracker.git
cd ip-geo-tracker
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
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

### 🏃‍♂️ Running the Application

#### Development Mode
```bash
python ip_geo_locator.py
```

#### Production Mode
```bash
# Using Gunicorn (recommended)
gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
         -w 4 \
         -b 0.0.0.0:5000 \
         ip_geo_locator:app
```

### 🐳 Docker Deployment

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

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `False` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `5000` |
| `SECRET_KEY` | Flask secret key | Random |
| `CACHE_TYPE` | Cache backend | `simple` |
| `LOG_LEVEL` | Logging level | `INFO` |

### API Keys

The application supports multiple geolocation APIs:
- IPGeolocation.io
- IPInfo.io
- MaxMind
- GeoJS

Configure your API keys in the `.env` file.

## 🛡️ Security Features

- 🔒 HTTPS support with SSL/TLS
- 🚫 Rate limiting
- 🔑 Secure session handling
- 🛡️ CORS protection
- 🔍 Input validation
- 📝 Comprehensive logging
- 🔄 API key rotation support

## 📊 Monitoring and Logging

The application includes comprehensive logging in the `logs` directory:

- 📝 Application logs
- 🔍 Error tracking
- 📊 Performance metrics
- 🚨 Security alerts
- 📈 Usage statistics

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Write unit tests for new features
- Update documentation
- Use meaningful commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/)
- [Socket.IO](https://socket.io/)
- [Leaflet](https://leafletjs.com/)
- [Redis](https://redis.io/)
- [IPGeolocation.io](https://ipgeolocation.io/)
- [IPInfo.io](https://ipinfo.io/)

## 📞 Support

For support, please:
- Open an issue
- Check the documentation
- Join our community chat

---

Made with ❤️ by ilyass basbassi