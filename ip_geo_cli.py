#!/usr/bin/env python3
"""
IP Geolocation & 3D Route Tracer
A professional-grade tool for IP geolocation, route calculation, and 3D visualization.

Author: Security Engineering Team
Version: 1.0.0
"""

import requests
import json
import argparse
import logging
import sys
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import folium
import folium.plugins
import pydeck as pdk
import pandas as pd
import numpy as np
from geopy.distance import geodesic
from geopy.geocoders import Nominatim
import urllib3
from pathlib import Path

# Suppress SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_geotracer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class GeoLocation:
    """Data class for geographic location information."""
    ip: str
    latitude: float
    longitude: float
    city: str = ""
    country: str = ""
    region: str = ""
    timezone: str = ""
    isp: str = ""
    elevation: float = 0.0

@dataclass
class RouteData:
    """Data class for route information."""
    distance_km: float
    duration_hours: float
    coordinates: List[Tuple[float, float]]
    elevations: List[float]

class GeoIPService:
    """
    Professional GeoIP service with fallback chain for reliability.
    Uses multiple free APIs to ensure high availability.
    """
    
    def __init__(self):
        self.apis = [
            {
                'name': 'GeoJS',
                'url': 'https://get.geojs.io/v1/ip/{ip}/geo.json',
                'parser': self._parse_geojs
            },
            {
                'name': 'ReallyFreeGeoIP',
                'url': 'https://reallyfreegeoip.org/json/{ip}',
                'parser': self._parse_reallyfreegeoip
            },
            {
                'name': 'SeeIP',
                'url': 'https://api.seeip.org/geoip/{ip}',
                'parser': self._parse_seeip
            },
            {
                'name': 'freeIP2GEO',
                'url': 'https://freeip2geo.net/api/{ip}',
                'parser': self._parse_freeip2geo
            },
            {
                'name': 'Country.is',
                'url': 'https://api.country.is/{ip}',
                'parser': self._parse_country_is
            }
        ]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'IP-GeoTracer/1.0 (Security Research Tool)'
        })
    
    def get_location(self, ip: str) -> Optional[GeoLocation]:
        """
        Get geolocation for IP using fallback chain.
        
        Args:
            ip: IP address to locate
            
        Returns:
            GeoLocation object or None if all APIs fail
        """
        if ip == "current":
            ip = self._get_current_ip()
            if not ip:
                logger.error("Failed to determine current IP")
                return None
        
        for api in self.apis:
            try:
                logger.info(f"Trying {api['name']} API for IP {ip}")
                url = api['url'].format(ip=ip)
                
                response = self.session.get(url, timeout=10, verify=False)
                response.raise_for_status()
                
                data = response.json()
                location = api['parser'](data, ip)
                
                if location and location.latitude and location.longitude:
                    logger.info(f"Successfully located {ip} using {api['name']}")
                    return location
                    
            except Exception as e:
                logger.warning(f"{api['name']} API failed: {str(e)}")
                continue
        
        logger.error(f"All GeoIP APIs failed for IP {ip}")
        return None
    
    def _get_current_ip(self) -> Optional[str]:
        """Get current public IP address."""
        try:
            response = self.session.get('https://api.seeip.org', timeout=5)
            return response.text.strip()
        except:
            try:
                response = self.session.get('https://get.geojs.io/v1/ip', timeout=5)
                return response.text.strip()
            except:
                return None
    
    def _parse_geojs(self, data: Dict, ip: str) -> Optional[GeoLocation]:
        """Parse GeoJS API response."""
        try:
            return GeoLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country', ''),
                region=data.get('region', ''),
                timezone=data.get('timezone', ''),
                isp=data.get('organization', '')
            )
        except (ValueError, KeyError):
            return None
    
    def _parse_reallyfreegeoip(self, data: Dict, ip: str) -> Optional[GeoLocation]:
        """Parse ReallyFreeGeoIP API response."""
        try:
            return GeoLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country_name', ''),
                region=data.get('region_name', ''),
                timezone=data.get('time_zone', '')
            )
        except (ValueError, KeyError):
            return None
    
    def _parse_seeip(self, data: Dict, ip: str) -> Optional[GeoLocation]:
        """Parse SeeIP API response."""
        try:
            return GeoLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country', ''),
                region=data.get('region', ''),
                isp=data.get('organization', '')
            )
        except (ValueError, KeyError):
            return None
    
    def _parse_freeip2geo(self, data: Dict, ip: str) -> Optional[GeoLocation]:
        """Parse freeIP2GEO API response."""
        try:
            return GeoLocation(
                ip=ip,
                latitude=float(data.get('latitude', 0)),
                longitude=float(data.get('longitude', 0)),
                city=data.get('city', ''),
                country=data.get('country_name', ''),
                region=data.get('region_name', '')
            )
        except (ValueError, KeyError):
            return None
    
    def _parse_country_is(self, data: Dict, ip: str) -> Optional[GeoLocation]:
        """Parse Country.is API response."""
        try:
            return GeoLocation(
                ip=ip,
                latitude=0,  # Country.is only provides country
                longitude=0,
                country=data.get('country', '')
            )
        except (ValueError, KeyError):
            return None

class ElevationService:
    """Service for retrieving elevation data."""
    
    def __init__(self):
        self.session = requests.Session()
    
    def get_elevation(self, lat: float, lon: float) -> float:
        """
        Get elevation for coordinates using Open-Elevation API.
        
        Args:
            lat: Latitude
            lon: Longitude
            
        Returns:
            Elevation in meters
        """
        try:
            url = f"https://api.open-elevation.com/api/v1/lookup?locations={lat},{lon}"
            response = self.session.get(url, timeout=10)
            data = response.json()
            
            if 'results' in data and len(data['results']) > 0:
                return float(data['results'][0].get('elevation', 0))
        except Exception as e:
            logger.warning(f"Elevation lookup failed: {str(e)}")
        
        return 0.0
    
    def get_elevation_profile(self, coordinates: List[Tuple[float, float]]) -> List[float]:
        """Get elevation profile for a route."""
        elevations = []
        
        # Sample coordinates to avoid API limits
        sample_size = min(50, len(coordinates))
        step = len(coordinates) // sample_size if sample_size > 1 else 1
        
        for i in range(0, len(coordinates), step):
            lat, lon = coordinates[i]
            elevation = self.get_elevation(lat, lon)
            elevations.append(elevation)
            time.sleep(0.1)  # Rate limiting
        
        # Interpolate for missing points
        if len(elevations) < len(coordinates):
            elevations = np.interp(
                range(len(coordinates)),
                range(0, len(coordinates), step),
                elevations
            ).tolist()
        
        return elevations

class RouteService:
    """Service for calculating routes between coordinates."""
    
    def __init__(self):
        self.session = requests.Session()
    
    def calculate_route(self, start: GeoLocation, end: GeoLocation) -> Optional[RouteData]:
        """
        Calculate route between two locations using OSRM.
        
        Args:
            start: Starting location
            end: Destination location
            
        Returns:
            RouteData object or None if calculation fails
        """
        try:
            # Use OSRM public API
            url = (f"http://router.project-osrm.org/route/v1/driving/"
                   f"{start.longitude},{start.latitude};"
                   f"{end.longitude},{end.latitude}")
            
            params = {
                'overview': 'full',
                'geometries': 'geojson',
                'steps': 'true'
            }
            
            logger.info("Calculating route using OSRM...")
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'routes' not in data or len(data['routes']) == 0:
                logger.error("No routes found")
                return None
            
            route = data['routes'][0]
            geometry = route['geometry']['coordinates']
            
            # Convert to lat/lon format
            coordinates = [(coord[1], coord[0]) for coord in geometry]
            
            distance_km = route['distance'] / 1000
            duration_hours = route['duration'] / 3600
            
            logger.info(f"Route calculated: {distance_km:.1f}km, {duration_hours:.1f}h")
            
            return RouteData(
                distance_km=distance_km,
                duration_hours=duration_hours,
                coordinates=coordinates,
                elevations=[]
            )
            
        except Exception as e:
            logger.error(f"Route calculation failed: {str(e)}")
            # Fallback to straight line
            return self._calculate_straight_line(start, end)
    
    def _calculate_straight_line(self, start: GeoLocation, end: GeoLocation) -> RouteData:
        """Calculate straight-line route as fallback."""
        distance = geodesic((start.latitude, start.longitude), 
                          (end.latitude, end.longitude)).kilometers
        
        # Generate intermediate points for visualization
        num_points = max(10, int(distance / 100))  # 1 point per 100km
        coordinates = []
        
        for i in range(num_points + 1):
            ratio = i / num_points
            lat = start.latitude + ratio * (end.latitude - start.latitude)
            lon = start.longitude + ratio * (end.longitude - start.longitude)
            coordinates.append((lat, lon))
        
        return RouteData(
            distance_km=distance,
            duration_hours=distance / 800,  # Assume 800km/h flight speed
            coordinates=coordinates,
            elevations=[]
        )

class Visualizer:
    """Professional 3D visualization engine."""
    
    def __init__(self):
        self.elevation_service = ElevationService()
    
    def create_plotly_3d_map(self, start: GeoLocation, end: GeoLocation, 
                           route: RouteData) -> go.Figure:
        """Create interactive 3D map using Plotly."""
        logger.info("Creating 3D Plotly visualization...")
        
        # Get elevation data if not available
        if not route.elevations:
            logger.info("Fetching elevation profile...")
            route.elevations = self.elevation_service.get_elevation_profile(route.coordinates)
        
        # Prepare data
        lats, lons = zip(*route.coordinates)
        elevations = route.elevations
        
        # Create 3D scatter plot
        fig = go.Figure()
        
        # Add route path
        fig.add_trace(go.Scatter3d(
            x=lons,
            y=lats,
            z=elevations,
            mode='lines+markers',
            line=dict(color='red', width=4),
            marker=dict(size=2, color='red'),
            name='Route Path',
            hovertemplate='<b>Route Point</b><br>' +
                         'Lat: %{y:.4f}<br>' +
                         'Lon: %{x:.4f}<br>' +
                         'Elevation: %{z:.0f}m<br>' +
                         '<extra></extra>'
        ))
        
        # Add start point
        start_elevation = self.elevation_service.get_elevation(start.latitude, start.longitude)
        fig.add_trace(go.Scatter3d(
            x=[start.longitude],
            y=[start.latitude],
            z=[start_elevation],
            mode='markers',
            marker=dict(size=15, color='green', symbol='diamond'),
            name=f'Start: {start.city or start.ip}',
            hovertemplate=f'<b>Start Location</b><br>' +
                         f'IP: {start.ip}<br>' +
                         f'City: {start.city}<br>' +
                         f'Country: {start.country}<br>' +
                         f'Lat: {start.latitude:.4f}<br>' +
                         f'Lon: {start.longitude:.4f}<br>' +
                         f'Elevation: {start_elevation:.0f}m<br>' +
                         '<extra></extra>'
        ))
        
        # Add end point
        end_elevation = self.elevation_service.get_elevation(end.latitude, end.longitude)
        fig.add_trace(go.Scatter3d(
            x=[end.longitude],
            y=[end.latitude],
            z=[end_elevation],
            mode='markers',
            marker=dict(size=15, color='blue', symbol='diamond'),
            name=f'End: {end.city or end.ip}',
            hovertemplate=f'<b>Destination</b><br>' +
                         f'IP: {end.ip}<br>' +
                         f'City: {end.city}<br>' +
                         f'Country: {end.country}<br>' +
                         f'Lat: {end.latitude:.4f}<br>' +
                         f'Lon: {end.longitude:.4f}<br>' +
                         f'Elevation: {end_elevation:.0f}m<br>' +
                         '<extra></extra>'
        ))
        
        # Configure layout
        fig.update_layout(
            title=dict(
                text=f'3D Route Visualization: {start.city or start.ip} → {end.city or end.ip}<br>' +
                     f'Distance: {route.distance_km:.1f}km | Duration: {route.duration_hours:.1f}h',
                x=0.5,
                font=dict(size=16)
            ),
            scene=dict(
                xaxis_title='Longitude',
                yaxis_title='Latitude',
                zaxis_title='Elevation (m)',
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=1.5)
                ),
                aspectmode='manual',
                aspectratio=dict(x=2, y=2, z=0.5)
            ),
            showlegend=True,
            width=1200,
            height=800
        )
        
        return fig
    
    def create_folium_map(self, start: GeoLocation, end: GeoLocation, 
                         route: RouteData) -> folium.Map:
        """Create interactive 2D map using Folium."""
        logger.info("Creating Folium map...")
        
        # Calculate map center
        center_lat = (start.latitude + end.latitude) / 2
        center_lon = (start.longitude + end.longitude) / 2
        
        # Create map
        m = folium.Map(
            location=[center_lat, center_lon],
            zoom_start=4,
            tiles='OpenStreetMap'
        )
        
        # Add route line
        folium.PolyLine(
            locations=route.coordinates,
            color='red',
            weight=3,
            opacity=0.8,
            popup=f'Route: {route.distance_km:.1f}km'
        ).add_to(m)
        
        # Add start marker
        folium.Marker(
            location=[start.latitude, start.longitude],
            popup=f"""
            <b>Start Location</b><br>
            IP: {start.ip}<br>
            City: {start.city}<br>
            Country: {start.country}<br>
            Coordinates: {start.latitude:.4f}, {start.longitude:.4f}
            """,
            icon=folium.Icon(color='green', icon='play')
        ).add_to(m)
        
        # Add end marker
        folium.Marker(
            location=[end.latitude, end.longitude],
            popup=f"""
            <b>Destination</b><br>
            IP: {end.ip}<br>
            City: {end.city}<br>
            Country: {end.country}<br>
            Coordinates: {end.latitude:.4f}, {end.longitude:.4f}
            """,
            icon=folium.Icon(color='red', icon='stop')
        ).add_to(m)
        
        # Fit bounds
        m.fit_bounds([
            [min(start.latitude, end.latitude), min(start.longitude, end.longitude)],
            [max(start.latitude, end.latitude), max(start.longitude, end.longitude)]
        ])
        
        return m
    
    def create_pydeck_3d(self, start: GeoLocation, end: GeoLocation, 
                        route: RouteData) -> pdk.Deck:
        """Create advanced 3D visualization using PyDeck."""
        logger.info("Creating PyDeck 3D visualization...")
        
        # Prepare route data
        route_df = pd.DataFrame([
            {'lat': lat, 'lon': lon, 'elevation': elev} 
            for (lat, lon), elev in zip(route.coordinates, route.elevations or [0] * len(route.coordinates))
        ])
        
        # Location markers
        locations_df = pd.DataFrame([
            {
                'lat': start.latitude,
                'lon': start.longitude,
                'elevation': 1000,
                'name': f'Start: {start.city or start.ip}',
                'color': [0, 255, 0, 200]
            },
            {
                'lat': end.latitude,
                'lon': end.longitude,
                'elevation': 1000,
                'name': f'End: {end.city or end.ip}',
                'color': [255, 0, 0, 200]
            }
        ])
        
        # Create layers
        layers = [
            pdk.Layer(
                'PathLayer',
                data=[{
                    'path': [[lon, lat, elev] for lat, lon, elev in 
                            zip(route_df['lat'], route_df['lon'], route_df['elevation'])]
                }],
                get_path='path',
                get_width=5000,
                get_color=[255, 0, 0],
                width_scale=1,
                pickable=True
            ),
            pdk.Layer(
                'ScatterplotLayer',
                data=locations_df,
                get_position=['lon', 'lat', 'elevation'],
                get_color='color',
                get_radius=50000,
                pickable=True
            )
        ]
        
        # Set viewport
        view_state = pdk.ViewState(
            latitude=(start.latitude + end.latitude) / 2,
            longitude=(start.longitude + end.longitude) / 2,
            zoom=3,
            pitch=60,
            bearing=0
        )
        
        return pdk.Deck(
            layers=layers,
            initial_view_state=view_state,
            map_style='mapbox://styles/mapbox/light-v9'
        )

class IPGeoTracer:
    """Main application class for IP geolocation and route tracing."""
    
    def __init__(self):
        self.geoip_service = GeoIPService()
        self.route_service = RouteService()
        self.visualizer = Visualizer()
        logger.info("IP GeoTracer initialized")
    
    def trace_route_to_ip(self, target_ip: str, source_ip: str = "current") -> Dict[str, Any]:
        """
        Main function to trace route from source to target IP.
        
        Args:
            target_ip: Target IP address to trace to
            source_ip: Source IP address (default: "current")
            
        Returns:
            Dictionary containing all trace results
        """
        logger.info(f"Starting route trace from {source_ip} to {target_ip}")
        
        # Get source location
        logger.info("Resolving source location...")
        start_location = self.geoip_service.get_location(source_ip)
        if not start_location:
            raise ValueError(f"Could not resolve source IP: {source_ip}")
        
        # Get target location
        logger.info("Resolving target location...")
        end_location = self.geoip_service.get_location(target_ip)
        if not end_location:
            raise ValueError(f"Could not resolve target IP: {target_ip}")
        
        # Calculate route
        logger.info("Calculating optimal route...")
        route_data = self.route_service.calculate_route(start_location, end_location)
        if not route_data:
            raise ValueError("Could not calculate route")
        
        return {
            'start_location': start_location,
            'end_location': end_location,
            'route_data': route_data,
            'summary': {
                'distance_km': route_data.distance_km,
                'duration_hours': route_data.duration_hours,
                'start_city': start_location.city,
                'end_city': end_location.city,
                'start_country': start_location.country,
                'end_country': end_location.country
            }
        }
    
    def generate_visualizations(self, trace_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate all visualization types for trace results."""
        start_location = trace_results['start_location']
        end_location = trace_results['end_location']
        route_data = trace_results['route_data']
        
        visualizations = {}
        
        try:
            # 3D Plotly visualization
            logger.info("Generating 3D Plotly visualization...")
            plotly_fig = self.visualizer.create_plotly_3d_map(start_location, end_location, route_data)
            visualizations['plotly_3d'] = plotly_fig
            
            # Save as HTML
            plotly_fig.write_html("route_3d_plotly.html")
            logger.info("3D visualization saved as route_3d_plotly.html")
            
        except Exception as e:
            logger.error(f"Failed to create Plotly visualization: {str(e)}")
        
        try:
            # 2D Folium map
            logger.info("Generating Folium map...")
            folium_map = self.visualizer.create_folium_map(start_location, end_location, route_data)
            visualizations['folium_2d'] = folium_map
            
            # Save as HTML
            folium_map.save("route_2d_folium.html")
            logger.info("2D map saved as route_2d_folium.html")
            
        except Exception as e:
            logger.error(f"Failed to create Folium visualization: {str(e)}")
        
        return visualizations
    
    def print_summary(self, trace_results: Dict[str, Any]):
        """Print a formatted summary of trace results."""
        summary = trace_results['summary']
        start = trace_results['start_location']
        end = trace_results['end_location']
        
        print("\n" + "="*80)
        print("IP GEOLOCATION & ROUTE TRACE SUMMARY")
        print("="*80)
        print(f"Source IP:      {start.ip}")
        print(f"Source Location: {start.city}, {start.country} ({start.latitude:.4f}, {start.longitude:.4f})")
        if start.isp:
            print(f"Source ISP:     {start.isp}")
        print()
        print(f"Target IP:      {end.ip}")
        print(f"Target Location: {end.city}, {end.country} ({end.latitude:.4f}, {end.longitude:.4f})")
        if end.isp:
            print(f"Target ISP:     {end.isp}")
        print()
        print(f"Route Distance: {summary['distance_km']:.1f} km")
        print(f"Estimated Time: {summary['duration_hours']:.1f} hours")
        print()
        print("Visualizations generated:")
        print("  - route_3d_plotly.html (Interactive 3D map)")
        print("  - route_2d_folium.html (Interactive 2D map)")
        print("="*80)

def main():
    """Command-line interface for IP GeoTracer."""
    parser = argparse.ArgumentParser(
        description='IP Geolocation & 3D Route Tracer - Professional Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8                    # Trace route from current location to Google DNS
  %(prog)s 1.1.1.1 --source 8.8.8.8  # Trace route from Google DNS to Cloudflare DNS
  %(prog)s 192.168.1.1 --verbose      # Trace with verbose logging
        """
    )
    
    parser.add_argument('target_ip', help='Target IP address to trace to')
    parser.add_argument('--source', '-s', default='current', 
                       help='Source IP address (default: current public IP)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--no-viz', action='store_true',
                       help='Skip visualization generation')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize tracer
        tracer = IPGeoTracer()
        
        # Perform trace
        print(f"Tracing route from {args.source} to {args.target_ip}...")
        trace_results = tracer.trace_route_to_ip(args.target_ip, args.source)
        
        # Print summary
        tracer.print_summary(trace_results)
        
        # Generate visualizations
        if not args.no_viz:
            print("\nGenerating visualizations...")
            visualizations = tracer.generate_visualizations(trace_results)
            
            if visualizations:
                print("\nVisualizations ready! Open the HTML files in your browser.")
            else:
                print("Warning: Could not generate visualizations.")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"\nError: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())