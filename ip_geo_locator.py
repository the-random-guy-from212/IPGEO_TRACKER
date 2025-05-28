#!/usr/bin/env python3
"""
Professional IP Geolocation & Route Monitoring API
A clean, efficient web service for IP tracking and geolocation analysis.

Features:
- Real-time IP monitoring with WebSocket support
- Clean GitHub-style interface
- Professional data visualization
- Bulk IP processing with async support
- Historical tracking and analytics
- Rate limiting and security features
- Comprehensive error handling

Author: Enhanced Version
Version: 3.0.0
"""

import eventlet
eventlet.monkey_patch()

import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Production Configuration
PROD_CONFIG = {
    'DEBUG': os.getenv('DEBUG', 'False').lower() == 'true',
    'SECRET_KEY': os.getenv('SECRET_KEY', os.urandom(24)),
    'HOST': os.getenv('HOST', '0.0.0.0'),
    'PORT': int(os.getenv('PORT', 5000)),
    'WORKERS': int(os.getenv('WORKERS', 4)),
    'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
    'CACHE_TYPE': os.getenv('CACHE_TYPE', 'simple'),  # Changed to simple for development
    'CACHE_REDIS_URL': os.getenv('CACHE_REDIS_URL', 'redis://localhost:6379/0'),
    'RATE_LIMIT_STORAGE_URL': os.getenv('RATE_LIMIT_STORAGE_URL', 'memory://'),
    'DATABASE_URL': os.getenv('DATABASE_URL', 'sqlite:///data/ip_tracker.db'),
    'SSL_CERT': os.getenv('SSL_CERT', None),
    'SSL_KEY': os.getenv('SSL_KEY', None),
    'ALLOWED_ORIGINS': os.getenv('ALLOWED_ORIGINS', '*').split(','),
    'API_KEYS': {
        'ipgeolocation': os.getenv('IPGEOLOCATION_API_KEY', 'free'),
        'ipinfo': os.getenv('IPINFO_API_KEY', ''),
        'maxmind': os.getenv('MAXMIND_API_KEY', '')
    }
}

# Create necessary directories
for directory in ['logs', 'data', 'certs']:
    Path(directory).mkdir(exist_ok=True)

from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import requests
import json
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import sqlite3
from datetime import datetime, timedelta
import queue
import hashlib
import ipaddress
import asyncio
import aiohttp
from contextlib import asynccontextmanager

# Flask app configuration
app = Flask(__name__)
app.config.update(
    SECRET_KEY=PROD_CONFIG['SECRET_KEY'],
    CACHE_TYPE=PROD_CONFIG['CACHE_TYPE'],
    CACHE_REDIS_URL=PROD_CONFIG['CACHE_REDIS_URL'],
    CACHE_DEFAULT_TIMEOUT=300,
    JSON_SORT_KEYS=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)
)

# Initialize extensions with production settings
socketio = SocketIO(
    app,
    cors_allowed_origins=PROD_CONFIG['ALLOWED_ORIGINS'],
    async_mode='eventlet',
    logger=PROD_CONFIG['DEBUG'],
    engineio_logger=PROD_CONFIG['DEBUG']
)

cache = Cache(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri=PROD_CONFIG['RATE_LIMIT_STORAGE_URL']
)

# Enhanced logging configuration
logging.basicConfig(
    level=getattr(logging, PROD_CONFIG['LOG_LEVEL']),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ip_tracker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class IPLocation:
    """Enhanced data class for IP location information."""
    ip: str
    latitude: float
    longitude: float
    city: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    timezone: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    threat_level: str = "unknown"
    vpn_detected: bool = False
    proxy_detected: bool = False
    timestamp: str = ""
    accuracy_radius: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class SecurityManager:
    """Enhanced security and validation manager."""
    
    @staticmethod
    def validate_ip(ip: str) -> Tuple[bool, str]:
        """Validate IP address format and type."""
        if not ip or ip.strip() == "":
            return False, "Empty IP address"
        
        ip = ip.strip()
        
        # Allow special keywords
        if ip.lower() in ['current', 'my', 'auto']:
            return True, "Valid keyword"
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private/reserved IPs
            if ip_obj.is_private:
                return False, "Private IP address not supported"
            if ip_obj.is_reserved:
                return False, "Reserved IP address not supported"
            if ip_obj.is_loopback:
                return False, "Loopback IP address not supported"
            
            return True, "Valid public IP"
            
        except ValueError:
            return False, "Invalid IP address format"
    
    @staticmethod
    def sanitize_input(data: str, max_length: int = 100) -> str:
        """Sanitize user input."""
        if not data:
            return ""
        return str(data).strip()[:max_length]

class DatabaseManager:
    """Enhanced database manager with connection pooling and error handling."""
    
    def __init__(self, db_path: str = "data/ip_tracker.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with comprehensive schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Enable foreign keys
                conn.execute("PRAGMA foreign_keys = ON")
                
                # Create locations table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS ip_locations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        latitude REAL NOT NULL,
                        longitude REAL NOT NULL,
                        city TEXT DEFAULT '',
                        country TEXT DEFAULT '',
                        country_code TEXT DEFAULT '',
                        region TEXT DEFAULT '',
                        timezone TEXT DEFAULT '',
                        isp TEXT DEFAULT '',
                        org TEXT DEFAULT '',
                        asn TEXT DEFAULT '',
                        threat_level TEXT DEFAULT 'unknown',
                        vpn_detected BOOLEAN DEFAULT FALSE,
                        proxy_detected BOOLEAN DEFAULT FALSE,
                        accuracy_radius INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        session_id TEXT,
                        UNIQUE(ip, session_id, timestamp)
                    )
                """)
                
                # Create monitoring sessions table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_sessions (
                        session_id TEXT PRIMARY KEY,
                        name TEXT DEFAULT '',
                        target_ips TEXT NOT NULL,
                        interval_seconds INTEGER DEFAULT 30,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                        total_updates INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'active'
                    )
                """)
                
                # Create performance indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_timestamp ON ip_locations(ip, timestamp DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_session_timestamp ON ip_locations(session_id, timestamp DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_country_code ON ip_locations(country_code)")
                
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def save_location(self, location: IPLocation, session_id: str = None) -> bool:
        """Save location with error handling."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO ip_locations 
                    (ip, latitude, longitude, city, country, country_code, region, 
                     timezone, isp, org, asn, threat_level, vpn_detected, proxy_detected, 
                     accuracy_radius, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    location.ip, location.latitude, location.longitude, location.city,
                    location.country, location.country_code, location.region, location.timezone,
                    location.isp, location.org, location.asn, location.threat_level,
                    location.vpn_detected, location.proxy_detected, location.accuracy_radius,
                    session_id
                ))
                return True
        except Exception as e:
            logger.error(f"Failed to save location for {location.ip}: {e}")
            return False
    
    def get_location_history(self, ip: str, hours: int = 24) -> List[Dict]:
        """Get location history with proper error handling."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM ip_locations 
                    WHERE ip = ? AND timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """.format(int(hours)), (ip,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get history for {ip}: {e}")
            return []
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get comprehensive session statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get basic stats
                cursor = conn.execute("""
                    SELECT COUNT(*) as total_records,
                           COUNT(DISTINCT ip) as unique_ips,
                           COUNT(DISTINCT country_code) as countries,
                           AVG(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) * 100 as high_threat_pct
                    FROM ip_locations WHERE session_id = ?
                """, (session_id,))
                
                stats = dict(cursor.fetchone()) if cursor else {}
                
                # Get country distribution
                cursor = conn.execute("""
                    SELECT country, country_code, COUNT(*) as count
                    FROM ip_locations 
                    WHERE session_id = ? AND country != ''
                    GROUP BY country_code
                    ORDER BY count DESC
                    LIMIT 10
                """, (session_id,))
                
                stats['countries'] = [dict(row) for row in cursor.fetchall()]
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get session stats: {e}")
            return {}

class EnhancedGeoIPService:
    """Production-ready GeoIP service with fallback APIs."""
    
    def __init__(self):
        self.apis = [
            {
                'name': 'IPGeolocation',
                'url': 'https://api.ipgeolocation.io/ipgeo?apiKey=free&ip={ip}&fields=geo,isp,threat',
                'parser': self._parse_ipgeolocation,
                'timeout': 10,
                'priority': 1
            },
            {
                'name': 'GeoJS',
                'url': 'https://get.geojs.io/v1/ip/{ip}.json',
                'parser': self._parse_geojs,
                'timeout': 8,
                'priority': 2
            },
            {
                'name': 'IPWhois',
                'url': 'http://ipwhois.app/json/{ip}',
                'parser': self._parse_ipwhois,
                'timeout': 8,
                'priority': 3
            },
            {
                'name': 'IPInfo',
                'url': 'https://ipinfo.io/{ip}/json',
                'parser': self._parse_ipinfo,
                'timeout': 8,
                'priority': 4
            }
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Professional-IPTracker/3.0 (+https://github.com/professional-tools)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate'
        })
        
        # Sort APIs by priority
        self.apis.sort(key=lambda x: x['priority'])
    
    @cache.memoize(timeout=600)  # Cache for 10 minutes
    def get_location(self, ip: str) -> Optional[IPLocation]:
        """Get enhanced geolocation with comprehensive error handling."""
        
        # Handle special keywords
        if ip.lower() in ['current', 'my', 'auto']:
            ip = self._get_current_ip()
            if not ip:
                logger.error("Failed to determine current IP")
                return None
        
        # Validate IP
        is_valid, message = SecurityManager.validate_ip(ip)
        if not is_valid:
            logger.warning(f"Invalid IP {ip}: {message}")
            return None
        
        # Check cache first
        cache_key = f"geo_v3_{ip}"
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit for {ip}")
            return IPLocation(**cached_result)
        
        # Try each API in priority order
        for api in self.apis:
            try:
                logger.debug(f"Trying {api['name']} for IP {ip}")
                
                url = api['url'].format(ip=ip)
                response = self.session.get(
                    url, 
                    timeout=api['timeout'],
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    data = response.json()
                    location = api['parser'](data, ip)
                    
                    if location and self._validate_location(location):
                        # Cache successful result
                        cache.set(cache_key, location.to_dict(), timeout=600)
                        logger.info(f"Successfully located {ip} using {api['name']}")
                        return location
                else:
                    logger.warning(f"{api['name']} returned status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"{api['name']} timed out")
            except requests.exceptions.RequestException as e:
                logger.warning(f"{api['name']} request failed: {e}")
            except Exception as e:
                logger.error(f"{api['name']} unexpected error: {e}")
        
        logger.error(f"All APIs failed for IP {ip}")
        return None
    
    def _validate_location(self, location: IPLocation) -> bool:
        """Validate location data quality."""
        if not location:
            return False
        
        # Check coordinate validity
        if (location.latitude == 0 and location.longitude == 0 or
            abs(location.latitude) > 90 or abs(location.longitude) > 180):
            return False
        
        return True
    
    def _get_current_ip(self) -> Optional[str]:
        """Get current public IP with multiple fallbacks."""
        services = [
            'https://api.ipify.org?format=json',
            'https://get.geojs.io/v1/ip.json',
            'https://httpbin.org/ip',
            'https://api.ip.pe.edu.br/v1/simple'
        ]
        
        for service in services:
            try:
                response = self.session.get(service, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Handle different response formats
                    ip = (data.get('ip') or 
                          data.get('origin') or 
                          data.get('query') or
                          response.text.strip())
                    
                    if ip and SecurityManager.validate_ip(ip)[0]:
                        return ip
                        
            except Exception as e:
                logger.debug(f"IP service {service} failed: {e}")
                continue
        
        return None
    
    def _parse_ipgeolocation(self, data: Dict, ip: str) -> Optional[IPLocation]:
        """Parse IPGeolocation.io response."""
        try:
            return IPLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country_name', ''),
                country_code=data.get('country_code2', ''),
                region=data.get('state_prov', ''),
                timezone=data.get('time_zone', {}).get('name', ''),
                isp=data.get('isp', ''),
                org=data.get('organization', ''),
                asn=data.get('asn', ''),
                threat_level=self._assess_threat_level(data),
                vpn_detected=data.get('security', {}).get('is_vpn', False),
                proxy_detected=data.get('security', {}).get('is_proxy', False),
                accuracy_radius=int(data.get('accuracy_radius', 0))
            )
        except (ValueError, KeyError, TypeError) as e:
            logger.debug(f"IPGeolocation parsing error: {e}")
            return None
    
    def _parse_geojs(self, data: Dict, ip: str) -> Optional[IPLocation]:
        """Parse GeoJS response."""
        try:
            return IPLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country', ''),
                country_code=data.get('country_code', ''),
                region=data.get('region', ''),
                timezone=data.get('timezone', ''),
                isp=data.get('organization', ''),
                org=data.get('organization_name', ''),
                asn=data.get('asn_org', ''),
                accuracy_radius=int(data.get('accuracy_radius', 0))
            )
        except (ValueError, KeyError, TypeError):
            return None
    
    def _parse_ipwhois(self, data: Dict, ip: str) -> Optional[IPLocation]:
        """Parse IPWhois response."""
        try:
            return IPLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country', ''),
                country_code=data.get('country_code', ''),
                region=data.get('region', ''),
                timezone=data.get('timezone', {}).get('name', '') if isinstance(data.get('timezone'), dict) else data.get('timezone', ''),
                isp=data.get('isp', ''),
                org=data.get('org', ''),
                asn=data.get('asn', ''),
                threat_level=self._assess_threat_level(data)
            )
        except (ValueError, KeyError, TypeError):
            return None
    
    def _parse_ipinfo(self, data: Dict, ip: str) -> Optional[IPLocation]:
        """Parse IPInfo response."""
        try:
            loc = data.get('loc', '0,0').split(',')
            return IPLocation(
                ip=ip,
                latitude=float(loc[0]) if len(loc) > 0 else 0,
                longitude=float(loc[1]) if len(loc) > 1 else 0,
                city=data.get('city', ''),
                country=data.get('country', ''),
                region=data.get('region', ''),
                timezone=data.get('timezone', ''),
                isp=data.get('org', '').split(' ', 1)[-1] if data.get('org') else '',
                org=data.get('org', ''),
                asn=data.get('org', '').split(' ', 1)[0] if data.get('org') else ''
            )
        except (ValueError, KeyError, TypeError, IndexError):
            return None
    
    def _assess_threat_level(self, data: Dict) -> str:
        """Enhanced threat assessment."""
        security = data.get('security', {})
        
        if security.get('is_threat', False) or security.get('is_malware', False):
            return "high"
        elif (security.get('is_vpn', False) or 
              security.get('is_proxy', False) or 
              security.get('is_tor', False)):
            return "medium"
        elif security.get('is_crawler', False):
            return "low"
        else:
            return "minimal"

class MonitoringService:
    """Enhanced real-time monitoring service."""
    
    def __init__(self, geoip_service: EnhancedGeoIPService, db_manager: DatabaseManager):
        self.geoip_service = geoip_service
        self.db_manager = db_manager
        self.active_sessions = {}
        self.session_lock = threading.Lock()
    
    def start_monitoring(self, session_id: str, ip_list: List[str], interval: int = 30) -> bool:
        """Start monitoring session with enhanced error handling."""
        try:
            with self.session_lock:
                # Stop existing session if running
                if session_id in self.active_sessions:
                    self.stop_monitoring(session_id)
                
                # Validate IPs
                valid_ips = []
                for ip in ip_list:
                    is_valid, message = SecurityManager.validate_ip(ip)
                    if is_valid:
                        valid_ips.append(ip.strip())
                    else:
                        logger.warning(f"Skipping invalid IP {ip}: {message}")
                
                if not valid_ips:
                    logger.error(f"No valid IPs in session {session_id}")
                    return False
                
                # Create session
                self.active_sessions[session_id] = {
                    'ips': valid_ips,
                    'interval': max(10, min(interval, 300)),  # Clamp between 10-300 seconds
                    'active': True,
                    'thread': threading.Thread(
                        target=self._monitor_session,
                        args=(session_id, valid_ips, interval),
                        daemon=True
                    ),
                    'start_time': time.time(),
                    'update_count': 0
                }
                
                self.active_sessions[session_id]['thread'].start()
                
                logger.info(f"Started monitoring session {session_id} with {len(valid_ips)} IPs")
                return True
                
        except Exception as e:
            logger.error(f"Failed to start monitoring session {session_id}: {e}")
            return False
    
    def stop_monitoring(self, session_id: str) -> bool:
        """Stop monitoring session safely."""
        try:
            with self.session_lock:
                if session_id not in self.active_sessions:
                    return True
                
                # Mark as inactive
                self.active_sessions[session_id]['active'] = False
                
                # Wait for thread to finish
                thread = self.active_sessions[session_id]['thread']
                if thread.is_alive():
                    thread.join(timeout=10)
                
                # Clean up
                del self.active_sessions[session_id]
                
                logger.info(f"Stopped monitoring session {session_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to stop monitoring session {session_id}: {e}")
            return False
    
    def _monitor_session(self, session_id: str, ip_list: List[str], interval: int):
        """Monitor IPs in session with enhanced error handling."""
        update_count = 0
        
        while self.active_sessions.get(session_id, {}).get('active', False):
            try:
                batch_start = time.time()
                
                for ip in ip_list:
                    if not self.active_sessions.get(session_id, {}).get('active', False):
                        break
                    
                    try:
                        location = self.geoip_service.get_location(ip)
                        if location:
                            # Save to database
                            if self.db_manager.save_location(location, session_id):
                                # Emit real-time update
                                socketio.emit('location_update', {
                                    'session_id': session_id,
                                    'location': location.to_dict(),
                                    'update_count': update_count
                                }, room=session_id)
                                
                                update_count += 1
                                
                                # Update session stats
                                if session_id in self.active_sessions:
                                    self.active_sessions[session_id]['update_count'] = update_count
                                
                                logger.debug(f"Updated location for {ip} in session {session_id}")
                        
                        # Brief pause between IPs to avoid rate limits
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Error processing IP {ip} in session {session_id}: {e}")
                        continue
                
                # Calculate remaining time for interval
                batch_duration = time.time() - batch_start
                sleep_time = max(0, interval - batch_duration)
                
                # Sleep in small chunks to allow for quick shutdown
                while sleep_time > 0 and self.active_sessions.get(session_id, {}).get('active', False):
                    chunk_sleep = min(5, sleep_time)
                    time.sleep(chunk_sleep)
                    sleep_time -= chunk_sleep
                
            except Exception as e:
                logger.error(f"Critical error in monitoring session {session_id}: {e}")
                time.sleep(interval)
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get comprehensive session status."""
        if session_id not in self.active_sessions:
            return {'active': False, 'error': 'Session not found'}
        
        session = self.active_sessions[session_id]
        return {
            'active': session['active'],
            'ips': session['ips'],
            'interval': session['interval'],
            'update_count': session.get('update_count', 0),
            'runtime': time.time() - session['start_time'],
            'thread_alive': session['thread'].is_alive()
        }

# Initialize services
db_manager = DatabaseManager()
geoip_service = EnhancedGeoIPService()
monitor = MonitoringService(geoip_service, db_manager)

# GitHub-style Professional Interface Template
PROFESSIONAL_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Geolocation Tracker</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary: #64748b;
            --success: #22c55e;
            --danger: #ef4444;
            --warning: #f59e0b;
            --background: #0f172a;
            --surface: #1e293b;
            --text: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #334155;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background-color: var(--background);
            color: var(--text);
            line-height: 1.5;
        }
        
        .header {
            background-color: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 1.5rem 2rem;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, var(--primary), transparent);
        }
        
        .header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--text), var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        .container {
            display: flex;
            min-height: calc(100vh - 80px);
        }
        
        .sidebar {
            width: 360px;
            background-color: var(--surface);
            border-right: 1px solid var(--border);
            padding: 1.5rem;
            overflow-y: auto;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .map-container {
            flex: 1;
            position: relative;
            background-color: var(--background);
        }
        
        #map {
            height: 100%;
            width: 100%;
            filter: grayscale(0.5) invert(0.8) contrast(0.8) hue-rotate(180deg);
        }
        
        .form-section {
            margin-bottom: 2rem;
            padding: 1.5rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background-color: var(--surface);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        .form-section h3 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .form-section h3::before {
            content: '';
            display: inline-block;
            width: 4px;
            height: 1.25em;
            background: var(--primary);
            border-radius: 2px;
        }
        
        .form-group {
            margin-bottom: 1.25rem;
        }
        
        .form-group label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
        }
        
        .form-control {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.875rem;
            line-height: 1.45;
            background-color: var(--background);
            color: var(--text);
            transition: all 0.2s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        
        textarea.form-control {
            resize: vertical;
            min-height: 100px;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.625rem 1.25rem;
            font-size: 0.875rem;
            font-weight: 500;
            line-height: 1.5;
            text-align: center;
            text-decoration: none;
            border: 1px solid transparent;
            border-radius: 6px;
            cursor: pointer;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
            transition: all 0.2s ease;
        }
        
        .btn-primary {
            color: white;
            background-color: var(--primary);
            border-color: var(--primary);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
        }
        
        .btn-danger {
            color: white;
            background-color: var(--danger);
            border-color: var(--danger);
        }
        
        .btn-danger:hover {
            background-color: #dc2626;
            border-color: #dc2626;
        }
        
        .btn-secondary {
            color: var(--text);
            background-color: var(--surface);
            border-color: var(--border);
        }
        
        .btn-secondary:hover {
            background-color: var(--border);
            border-color: var(--border);
        }

        .status-panel {
            margin-bottom: 2rem;
            padding: 1.25rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .ip-list {
            margin-top: 1rem;
        }

        .ip-item {
            padding: 1rem;
            border-left: 4px solid var(--primary);
            background: var(--background);
            border-radius: 6px;
            margin-bottom: 0.75rem;
            font-size: 0.95rem;
            transition: all 0.2s ease;
        }

        .ip-item:hover {
            transform: translateX(4px);
        }

        .ip-item.threat-high { border-left-color: var(--danger); }
        .ip-item.threat-medium { border-left-color: var(--warning); }
        .ip-item.threat-low { border-left-color: var(--success); }
        .ip-item.threat-minimal { border-left-color: var(--primary); }

        .legend {
            position: absolute;
            top: 20px;
            right: 20px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            z-index: 1000;
            font-size: 0.9rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
        }

        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.75rem;
        }

        .legend-low { background: var(--success); }
        .legend-medium { background: var(--warning); }
        .legend-high { background: var(--danger); }
        .legend-minimal { background: var(--primary); }

        /* Loading animation */
        .loading {
            position: relative;
        }

        .loading::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            animation: loading 1.5s infinite;
        }

        @keyframes loading {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--background);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--secondary);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>IP Geolocation Tracker</h1>
        <p>Professional real-time IP location monitoring and analytics</p>
    </div>
    <div class="container">
        <div class="sidebar">
            <div class="form-section">
                <h3>Track Single IP</h3>
                <div class="form-group">
                    <label for="single-ip">IP Address or 'current'</label>
                    <input type="text" id="single-ip" class="form-control" value="current" placeholder="Enter IP or 'current'">
                </div>
                <button class="btn btn-primary" onclick="trackSingleIP()">Track</button>
            </div>
            <div class="form-section">
                <h3>Bulk Monitor</h3>
                <div class="form-group">
                    <label for="bulk-ips">IP Addresses (one per line)</label>
                    <textarea id="bulk-ips" class="form-control" placeholder="8.8.8.8&#10;1.1.1.1&#10;current"></textarea>
                </div>
                <div class="form-group">
                    <label for="interval">Update Interval (seconds)</label>
                    <input type="number" id="interval" class="form-control" value="30" min="10" max="300">
                </div>
                <button class="btn btn-primary" onclick="startMonitoring()">Start</button>
                <button class="btn btn-danger" onclick="stopMonitoring()">Stop</button>
            </div>
            <div class="form-section">
                <h3>History</h3>
                <div class="form-group">
                    <label for="history-ip">IP Address</label>
                    <input type="text" id="history-ip" class="form-control" placeholder="IP address">
                </div>
                <div class="form-group">
                    <label for="history-hours">Time Range</label>
                    <select id="history-hours" class="form-control">
                        <option value="1">Last Hour</option>
                        <option value="6">Last 6 Hours</option>
                        <option value="24" selected>Last 24 Hours</option>
                        <option value="168">Last Week</option>
                    </select>
                </div>
                <button class="btn btn-secondary" onclick="loadHistory()">Load</button>
            </div>
            <div class="status-panel">
                <strong>Status:</strong> <span id="session-status">Ready</span><br>
                <strong>Socket:</strong> <span id="connection-status">Disconnected</span>
            </div>
            <div class="status-panel">
                <strong>Tracked IPs</strong>
                <div class="ip-list" id="ip-list"></div>
            </div>
        </div>
        <div class="main-content">
            <div class="map-container">
                <div id="map"></div>
                <div class="legend">
                    <div class="legend-item"><div class="legend-color legend-low"></div>Low</div>
                    <div class="legend-item"><div class="legend-color legend-medium"></div>Medium</div>
                    <div class="legend-item"><div class="legend-color legend-high"></div>High</div>
                    <div class="legend-item"><div class="legend-color legend-minimal"></div>Minimal</div>
                </div>
            </div>
        </div>
    </div>
    <script>
        let map;
        let markers = {};
        let currentSession = null;
        let monitoringActive = false;

        // Initialize map
        function initMap() {
            map = L.map('map', {
                center: [20, 0],
                zoom: 2,
                zoomControl: true,
                attributionControl: true
            });
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap contributors'
            }).addTo(map);
            setTimeout(() => map.invalidateSize(), 200);
        }
        initMap();

        // Socket.IO connection
        const socket = io();
        socket.on('connect', function() {
            document.getElementById('connection-status').textContent = 'Connected';
        });
        socket.on('disconnect', function() {
            document.getElementById('connection-status').textContent = 'Disconnected';
        });
        socket.on('location_update', function(data) {
            updateMap(data.location);
            updateIPList(data.location);
        });

        function updateMap(location) {
            if (!location.latitude || !location.longitude) return;
            if (markers[location.ip]) map.removeLayer(markers[location.ip]);
            let color = '#218739';
            if (location.threat_level === 'medium') color = '#e6a700';
            if (location.threat_level === 'high') color = '#d1242f';
            if (location.threat_level === 'minimal') color = '#0969da';
            const marker = L.circleMarker([location.latitude, location.longitude], {
                color: color,
                fillColor: color,
                fillOpacity: 0.7,
                radius: 8
            }).addTo(map);
            marker.bindPopup(
                `<strong>${location.ip}</strong><br>
                ${location.city}, ${location.country}<br>
                ISP: ${location.isp}<br>
                Threat: <span style="color:${color}">${location.threat_level.toUpperCase()}</span><br>
                VPN: ${location.vpn_detected ? 'Yes' : 'No'}<br>
                Updated: ${new Date(location.timestamp).toLocaleString()}`
            );
            markers[location.ip] = marker;
            if (Object.keys(markers).length > 1) {
                const group = new L.featureGroup(Object.values(markers));
                map.fitBounds(group.getBounds().pad(0.1));
            } else {
                map.setView([location.latitude, location.longitude], 6);
            }
        }

        function updateIPList(location) {
            const ipList = document.getElementById('ip-list');
            const id = `ip-${location.ip.replace(/\\./g, '-')}`;
            const threatClass = `threat-${location.threat_level}`;
            const vpnBadge = location.vpn_detected ? ' 🔒' : '';
            const html = `<div class="ip-item ${threatClass}" id="${id}">
                <strong>${location.ip}${vpnBadge}</strong><br>
                ${location.city}, ${location.country}<br>
                ${location.isp}<br>
                ${location.threat_level.toUpperCase()}<br>
                ${new Date(location.timestamp).toLocaleTimeString()}
            </div>`;
            const existing = document.getElementById(id);
            if (existing) {
                existing.outerHTML = html;
            } else {
                ipList.insertAdjacentHTML('afterbegin', html);
            }
        }

        async function trackSingleIP() {
            const ip = document.getElementById('single-ip').value.trim();
            if (!ip) return;
            const resp = await fetch(`/api/locate/${ip}`);
            const data = await resp.json();
            if (data.success) {
                updateMap(data.location);
                updateIPList(data.location);
            } else {
                alert('Failed to locate IP: ' + data.error);
            }
        }

        async function startMonitoring() {
            const ips = document.getElementById('bulk-ips').value.trim().split('\\n').filter(ip => ip.trim());
            const interval = parseInt(document.getElementById('interval').value) || 30;
            if (ips.length === 0) {
                alert('Please enter at least one IP address');
                return;
            }
            const resp = await fetch('/api/monitor/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips: ips, interval: interval })
            });
            const data = await resp.json();
            if (data.success) {
                currentSession = data.session_id;
                socket.emit('join', currentSession);
                document.getElementById('session-status').textContent = `Monitoring ${ips.length} IPs`;
                monitoringActive = true;
            } else {
                alert('Failed to start monitoring: ' + data.error);
            }
        }

        async function stopMonitoring() {
            if (!currentSession) return;
            const resp = await fetch('/api/monitor/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: currentSession })
            });
            const data = await resp.json();
            if (data.success) {
                socket.emit('leave', currentSession);
                currentSession = null;
                document.getElementById('session-status').textContent = 'Ready';
                monitoringActive = false;
            } else {
                alert('Failed to stop monitoring: ' + data.error);
            }
        }

        async function loadHistory() {
            const ip = document.getElementById('history-ip').value.trim();
            const hours = document.getElementById('history-hours').value;
            if (!ip) {
                alert('Please enter an IP address');
                return;
            }
            const resp = await fetch(`/api/history/${ip}?hours=${hours}`);
            const data = await resp.json();
            if (data.success) {
                Object.values(markers).forEach(marker => map.removeLayer(marker));
                markers = {};
                data.locations.forEach(location => {
                    updateMap(location);
                    updateIPList(location);
                });
            } else {
                alert('Failed to load history: ' + data.error);
            }
        }
    </script>
</body>
</html>
"""

# Flask routes
@app.route('/')
def index():
    return render_template_string(PROFESSIONAL_TEMPLATE)

@app.route('/api/locate/<ip>')
@limiter.limit("30 per minute")
def locate_ip(ip):
    try:
        location = geoip_service.get_location(ip)
        if location:
            return jsonify({'success': True, 'location': location.to_dict()})
        return jsonify({'success': False, 'error': 'Could not locate IP'}), 404
    except Exception as e:
        logger.error(f"Error locating IP {ip}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/monitor/start', methods=['POST'])
@limiter.limit("10 per minute")
def start_monitoring_route():
    try:
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({'success': False, 'error': 'Missing IP list'}), 400
        session_id = hashlib.md5(f"{time.time()}{data['ips']}".encode()).hexdigest()
        interval = data.get('interval', 30)
        if monitor.start_monitoring(session_id, data['ips'], interval):
            return jsonify({'success': True, 'session_id': session_id})
        else:
            return jsonify({'success': False, 'error': 'Failed to start monitoring'}), 500
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/monitor/stop', methods=['POST'])
@limiter.limit("10 per minute")
def stop_monitoring_route():
    try:
        data = request.get_json()
        if not data or 'session_id' not in data:
            return jsonify({'success': False, 'error': 'Missing session ID'}), 400
        if monitor.stop_monitoring(data['session_id']):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to stop monitoring'}), 500
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/<ip>')
@limiter.limit("30 per minute")
def get_history(ip):
    try:
        hours = request.args.get('hours', default=24, type=int)
        locations = db_manager.get_location_history(ip, hours)
        return jsonify({'success': True, 'locations': locations})
    except Exception as e:
        logger.error(f"Error getting history for IP {ip}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join')
def handle_join(session_id):
    join_room(session_id)
    logger.info(f"Client {request.sid} joined session {session_id}")

@socketio.on('leave')
def handle_leave(session_id):
    leave_room(session_id)
    logger.info(f"Client {request.sid} left session {session_id}")

if __name__ == '__main__':
    try:
        # Set up SSL context if certificates are available
        ssl_args = {}
        if PROD_CONFIG['SSL_CERT'] and PROD_CONFIG['SSL_KEY']:
            import ssl
            ssl_args = {
                'certfile': PROD_CONFIG['SSL_CERT'],
                'keyfile': PROD_CONFIG['SSL_KEY']
            }

        # Print startup message
        logger.info(f"Starting server on http{'s' if ssl_args else ''}://{PROD_CONFIG['HOST']}:{PROD_CONFIG['PORT']}")
        logger.info("Press Ctrl+C to stop the server")
        
        # Run the server
        socketio.run(
            app,
            host=PROD_CONFIG['HOST'],
            port=PROD_CONFIG['PORT'],
            debug=PROD_CONFIG['DEBUG'],
            use_reloader=False,
            **ssl_args
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise