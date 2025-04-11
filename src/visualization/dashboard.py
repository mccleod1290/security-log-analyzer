import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta

import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from fastapi import APIRouter, HTTPException
from storage.elasticsearch_client import ElasticsearchClient

logger = logging.getLogger(__name__)
router = APIRouter()

class Dashboard:
    def __init__(self, es_client: ElasticsearchClient, config: Dict[str, Any]):
        self.es_client = es_client
        self.config = config
        self.status = "initialized"

    async def get_time_series_data(self, timeframe: str = "24h") -> Dict[str, Any]:
        """Get time series data for security events."""
        try:
            # Convert timeframe to datetime
            end_time = datetime.utcnow()
            start_time = self._parse_timeframe(timeframe, end_time)
            
            # Query Elasticsearch for time series data
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lt": end_time.isoformat()
                        }
                    }
                },
                "aggs": {
                    "events_over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h"
                        },
                        "aggs": {
                            "by_severity": {
                                "terms": {
                                    "field": "severity"
                                }
                            }
                        }
                    }
                }
            }
            
            results = await self.es_client.search(
                index=f"{self.es_client.index_prefix}-threats",
                body=query
            )
            
            return self._format_time_series(results)
        except Exception as e:
            logger.error(f"Error getting time series data: {str(e)}")
            raise HTTPException(status_code=500, detail="Error retrieving time series data")

    async def get_geolocation_data(self) -> Dict[str, Any]:
        """Get geolocation data for attack sources."""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-24h",
                            "lt": "now"
                        }
                    }
                },
                "aggs": {
                    "locations": {
                        "terms": {
                            "field": "source_ip",
                            "size": 100
                        },
                        "aggs": {
                            "location": {
                                "geo_point": {
                                    "field": "geoip.location"
                                }
                            },
                            "threat_count": {
                                "value_count": {
                                    "field": "_id"
                                }
                            }
                        }
                    }
                }
            }
            
            results = await self.es_client.search(
                index=f"{self.es_client.index_prefix}-threats",
                body=query
            )
            
            return self._format_geolocation(results)
        except Exception as e:
            logger.error(f"Error getting geolocation data: {str(e)}")
            raise HTTPException(status_code=500, detail="Error retrieving geolocation data")

    async def get_attack_distribution(self) -> Dict[str, Any]:
        """Get distribution of attack types and vectors."""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-24h",
                            "lt": "now"
                        }
                    }
                },
                "aggs": {
                    "attack_types": {
                        "terms": {
                            "field": "type",
                            "size": 10
                        }
                    },
                    "severity_distribution": {
                        "terms": {
                            "field": "severity",
                            "size": 5
                        }
                    }
                }
            }
            
            results = await self.es_client.search(
                index=f"{self.es_client.index_prefix}-threats",
                body=query
            )
            
            return self._format_distribution(results)
        except Exception as e:
            logger.error(f"Error getting attack distribution: {str(e)}")
            raise HTTPException(status_code=500, detail="Error retrieving attack distribution")

    def _parse_timeframe(self, timeframe: str, end_time: datetime) -> datetime:
        """Parse timeframe string to datetime."""
        units = {
            "h": "hours",
            "d": "days",
            "w": "weeks"
        }
        
        value = int(timeframe[:-1])
        unit = timeframe[-1]
        
        if unit not in units:
            raise ValueError(f"Invalid timeframe unit: {unit}")
        
        delta = timedelta(**{units[unit]: value})
        return end_time - delta

    def _format_time_series(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format time series data for visualization."""
        buckets = results["aggregations"]["events_over_time"]["buckets"]
        
        timestamps = []
        data_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for bucket in buckets:
            timestamps.append(bucket["key"])
            severity_counts = {
                item["key"]: item["doc_count"]
                for item in bucket["by_severity"]["buckets"]
            }
            
            for severity in data_by_severity.keys():
                data_by_severity[severity].append(
                    severity_counts.get(severity, 0)
                )
        
        return {
            "timestamps": timestamps,
            "series": [
                {
                    "name": severity,
                    "data": values,
                    "color": self._get_severity_color(severity)
                }
                for severity, values in data_by_severity.items()
            ]
        }

    def _format_geolocation(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format geolocation data for visualization."""
        locations = []
        
        for bucket in results["aggregations"]["locations"]["buckets"]:
            location = bucket["location"]
            if location and "lat" in location and "lon" in location:
                locations.append({
                    "ip": bucket["key"],
                    "lat": location["lat"],
                    "lon": location["lon"],
                    "count": bucket["threat_count"]["value"]
                })
        
        return {"locations": locations}

    def _format_distribution(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format attack distribution data for visualization."""
        attack_types = [
            {
                "name": bucket["key"],
                "count": bucket["doc_count"]
            }
            for bucket in results["aggregations"]["attack_types"]["buckets"]
        ]
        
        severity_dist = [
            {
                "severity": bucket["key"],
                "count": bucket["doc_count"],
                "color": self._get_severity_color(bucket["key"])
            }
            for bucket in results["aggregations"]["severity_distribution"]["buckets"]
        ]
        
        return {
            "attack_types": attack_types,
            "severity_distribution": severity_dist
        }

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level."""
        colors = {
            "critical": "#780000",
            "high": "#c1121f",
            "medium": "#f0a500",
            "low": "#92c353"
        }
        return colors.get(severity.lower(), "#808080")

# API Routes
@router.get("/time-series")
async def get_time_series(timeframe: str = "24h"):
    """Get time series data for security events."""
    dashboard = Dashboard(None, {})  # Initialize with proper dependencies
    return await dashboard.get_time_series_data(timeframe)

@router.get("/geolocation")
async def get_geolocation():
    """Get geolocation data for attack sources."""
    dashboard = Dashboard(None, {})
    return await dashboard.get_geolocation_data()

@router.get("/distribution")
async def get_distribution():
    """Get distribution of attack types and vectors."""
    dashboard = Dashboard(None, {})
    return await dashboard.get_attack_distribution() 