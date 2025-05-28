FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data certs

# Set permissions
RUN chmod -R 755 /app

# Expose port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "-w", "4", "-b", "0.0.0.0:5000", "ip_geo_locator:app"] 