import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import re
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest
from storage.elasticsearch_client import ElasticsearchClient
from storage.redis_client import RedisClient

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, es_client: ElasticsearchClient, redis_client: RedisClient, config: Dict[str, Any]):
        self.es_client = es_client
        self.redis_client = redis_client
        self.config = config
        self.running = False
        self.status = "initialized"
        
        # Initialize analyzers
        self.rule_analyzer = RuleBasedAnalyzer(config["rules"])
        self.anomaly_detector = AnomalyDetector(config["anomaly_detection"])
        self.ip_reputation_checker = IPReputationChecker(
            config["ip_reputation"],
            redis_client
        )

    async def start_analysis(self):
        """Start the continuous analysis process."""
        self.running = True
        self.status = "running"
        
        try:
            while self.running:
                # Get recent logs from Elasticsearch
                logs = await self._get_recent_logs()
                
                if logs:
                    # Perform different types of analysis
                    rule_threats = await self.rule_analyzer.analyze(logs)
                    anomalies = await self.anomaly_detector.analyze(logs)
                    ip_threats = await self.ip_reputation_checker.check(logs)
                    
                    # Combine and correlate threats
                    combined_threats = self._correlate_threats(
                        rule_threats,
                        anomalies,
                        ip_threats
                    )
                    
                    if combined_threats:
                        await self._store_threats(combined_threats)
                
                await asyncio.sleep(10)  # Adjust based on load
        except Exception as e:
            logger.error(f"Error in analysis main loop: {str(e)}")
            self.status = "error"
            raise

    async def stop(self):
        """Stop the analysis process."""
        self.running = False
        self.status = "stopped"

    async def _get_recent_logs(self) -> List[Dict[str, Any]]:
        """Retrieve recent logs from Elasticsearch for analysis."""
        try:
            # Query logs from the last analysis interval
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1m",
                            "lt": "now"
                        }
                    }
                },
                "sort": [{"@timestamp": "asc"}]
            }
            
            return await self.es_client.search(
                index=f"{self.es_client.index_prefix}-*",
                body=query
            )
        except Exception as e:
            logger.error(f"Error retrieving logs: {str(e)}")
            return []

    def _correlate_threats(
        self,
        rule_threats: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        ip_threats: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Correlate threats from different analysis methods."""
        # Combine all threats
        all_threats = []
        all_threats.extend(rule_threats)
        all_threats.extend(anomalies)
        all_threats.extend(ip_threats)
        
        # Group threats by source IP
        threats_by_ip = defaultdict(list)
        for threat in all_threats:
            ip = threat.get("source_ip")
            if ip:
                threats_by_ip[ip].append(threat)
        
        # Correlate threats from the same source
        correlated_threats = []
        for ip, threats in threats_by_ip.items():
            if len(threats) > 1:
                # Combine related threats
                combined_threat = {
                    "source_ip": ip,
                    "timestamp": max(t["timestamp"] for t in threats),
                    "severity": max(t.get("severity", "low") for t in threats),
                    "related_threats": threats,
                    "correlation_type": "multiple_detections"
                }
                correlated_threats.append(combined_threat)
            else:
                correlated_threats.extend(threats)
        
        return correlated_threats

    async def _store_threats(self, threats: List[Dict[str, Any]]):
        """Store detected threats in Elasticsearch."""
        try:
            await self.es_client.bulk_index(
                index=f"{self.es_client.index_prefix}-threats",
                documents=threats
            )
        except Exception as e:
            logger.error(f"Error storing threats: {str(e)}")

class RuleBasedAnalyzer:
    def __init__(self, rules_config: List[Dict[str, Any]]):
        self.rules = []
        for rule in rules_config:
            if "pattern" in rule:
                self.rules.append({
                    "name": rule["name"],
                    "pattern": re.compile(rule["pattern"]),
                    "severity": rule["severity"]
                })
            elif "conditions" in rule:
                self.rules.append({
                    "name": rule["name"],
                    "conditions": rule["conditions"],
                    "severity": rule["severity"]
                })

    async def analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze logs using predefined rules."""
        threats = []
        
        for log in logs:
            for rule in self.rules:
                if "pattern" in rule:
                    # Pattern-based detection
                    if rule["pattern"].search(str(log.get("message", ""))):
                        threats.append({
                            "type": "rule_based",
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "timestamp": log.get("@timestamp"),
                            "source_ip": log.get("source_ip"),
                            "details": log
                        })
                elif "conditions" in rule:
                    # Condition-based detection (e.g., frequency-based rules)
                    if self._check_conditions(rule["conditions"], log):
                        threats.append({
                            "type": "rule_based",
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "timestamp": log.get("@timestamp"),
                            "source_ip": log.get("source_ip"),
                            "details": log
                        })
        
        return threats

    def _check_conditions(self, conditions: Dict[str, Any], log: Dict[str, Any]) -> bool:
        """Check if a log entry meets the specified conditions."""
        # Implement condition checking logic here
        return False  # Placeholder

class AnomalyDetector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.baseline_data = None

    async def analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in log patterns."""
        if not logs:
            return []

        # Extract features for anomaly detection
        features = self._extract_features(logs)
        
        # Update baseline if needed
        if self.baseline_data is None:
            self.baseline_data = features
            self.model.fit(features)
        
        # Predict anomalies
        predictions = self.model.predict(features)
        anomalies = []
        
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly detected
                anomalies.append({
                    "type": "anomaly",
                    "severity": "medium",
                    "timestamp": logs[i].get("@timestamp"),
                    "source_ip": logs[i].get("source_ip"),
                    "details": logs[i],
                    "anomaly_score": float(self.model.score_samples([features[i]])[0])
                })
        
        return anomalies

    def _extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Extract numerical features from logs for anomaly detection."""
        # Implement feature extraction logic here
        # This is a placeholder that returns dummy features
        return np.random.rand(len(logs), 5)

class IPReputationChecker:
    def __init__(self, config: Dict[str, Any], redis_client: RedisClient):
        self.config = config
        self.redis_client = redis_client
        self.cache_key_prefix = "ip_reputation:"
        self.cache_ttl = config["update_interval"]

    async def check(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check IP addresses against reputation databases."""
        threats = []
        unique_ips = {log.get("source_ip") for log in logs if log.get("source_ip")}
        
        for ip in unique_ips:
            reputation = await self._get_ip_reputation(ip)
            if reputation and reputation["threat_level"] > 0:
                # Find all logs from this IP
                related_logs = [log for log in logs if log.get("source_ip") == ip]
                
                threats.append({
                    "type": "ip_reputation",
                    "severity": self._threat_level_to_severity(reputation["threat_level"]),
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": ip,
                    "details": {
                        "reputation": reputation,
                        "related_logs": related_logs
                    }
                })
        
        return threats

    async def _get_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get IP reputation from cache or external sources."""
        cache_key = f"{self.cache_key_prefix}{ip}"
        
        # Check cache first
        cached_data = await self.redis_client.get(cache_key)
        if cached_data:
            return cached_data
        
        # Query external sources
        reputation = await self._query_reputation_sources(ip)
        if reputation:
            # Cache the result
            await self.redis_client.set(
                cache_key,
                reputation,
                expire=self.cache_ttl
            )
        
        return reputation

    async def _query_reputation_sources(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query configured reputation sources for IP information."""
        # Implement queries to external reputation databases
        # This is a placeholder that returns dummy data
        return {
            "threat_level": 0,
            "categories": [],
            "last_seen": datetime.utcnow().isoformat(),
            "sources": []
        }

    def _threat_level_to_severity(self, threat_level: int) -> str:
        """Convert numerical threat level to severity string."""
        if threat_level >= 80:
            return "critical"
        elif threat_level >= 60:
            return "high"
        elif threat_level >= 40:
            return "medium"
        return "low" 