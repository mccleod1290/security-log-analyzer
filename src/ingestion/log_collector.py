import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import re
from pathlib import Path

from storage.elasticsearch_client import ElasticsearchClient

logger = logging.getLogger(__name__)

class LogCollector:
    def __init__(self, es_client: ElasticsearchClient, config: Dict[str, Any]):
        self.es_client = es_client
        self.config = config
        self.running = False
        self.status = "initialized"
        self.collectors = {}
        self._setup_collectors()

    def _setup_collectors(self):
        """Initialize collectors for each supported log format."""
        for log_format in self.config["supported_formats"]:
            if log_format["name"] == "syslog":
                self.collectors["syslog"] = SyslogCollector(log_format["pattern"])
            elif log_format["name"] == "windows_event":
                self.collectors["windows_event"] = WindowsEventCollector(log_format.get("hosts", []))
            elif log_format["name"] in ["apache", "nginx"]:
                self.collectors[log_format["name"]] = WebServerLogCollector(
                    log_format["name"],
                    log_format["pattern"]
                )

    async def start_collection(self):
        """Start the log collection process."""
        self.running = True
        self.status = "running"
        
        try:
            while self.running:
                for collector_name, collector in self.collectors.items():
                    try:
                        logs = await collector.collect()
                        if logs:
                            await self._process_logs(collector_name, logs)
                    except Exception as e:
                        logger.error(f"Error collecting logs from {collector_name}: {str(e)}")
                
                await asyncio.sleep(self.config["polling_interval"])
        except Exception as e:
            logger.error(f"Error in log collection main loop: {str(e)}")
            self.status = "error"
            raise
        
    async def stop(self):
        """Stop the log collection process."""
        self.running = False
        self.status = "stopped"
        
        # Clean up collectors
        for collector in self.collectors.values():
            await collector.cleanup()

    async def _process_logs(self, source: str, logs: List[Dict[str, Any]]):
        """Process and store collected logs."""
        if not logs:
            return

        # Add metadata to logs
        enriched_logs = []
        for log in logs:
            log.update({
                "@timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
                "source": source,
                "metadata": {
                    "collector_version": "1.0",
                    "processed_at": datetime.utcnow().isoformat()
                }
            })
            enriched_logs.append(log)

        # Store logs in Elasticsearch
        try:
            await self.es_client.bulk_index(
                index=f"{self.es_client.index_prefix}-{source}",
                documents=enriched_logs
            )
        except Exception as e:
            logger.error(f"Error storing logs in Elasticsearch: {str(e)}")
            # Implement retry logic here

class BaseLogCollector:
    """Base class for log collectors."""
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect logs from the source."""
        raise NotImplementedError
    
    async def cleanup(self):
        """Clean up resources."""
        pass

class SyslogCollector(BaseLogCollector):
    def __init__(self, pattern: str):
        self.pattern = re.compile(pattern)
        self.syslog_path = Path("/var/log/syslog")  # Default syslog path
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect logs from syslog."""
        if not self.syslog_path.exists():
            return []
        
        logs = []
        try:
            with open(self.syslog_path, 'r') as f:
                # Seek to the last read position
                f.seek(0, 2)  # Go to the end of file
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    match = self.pattern.match(line)
                    if match:
                        logs.append(match.groupdict())
        except Exception as e:
            logger.error(f"Error reading syslog: {str(e)}")
        
        return logs

class WindowsEventCollector(BaseLogCollector):
    def __init__(self, hosts: List[str]):
        self.hosts = hosts
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect logs from Windows Event Log."""
        logs = []
        # Implement Windows Event Log collection using pywinrm
        # This is a placeholder for the actual implementation
        return logs

class WebServerLogCollector(BaseLogCollector):
    def __init__(self, server_type: str, pattern: str):
        self.server_type = server_type
        self.pattern = re.compile(pattern)
        self.log_paths = {
            "apache": Path("/var/log/apache2/access.log"),
            "nginx": Path("/var/log/nginx/access.log")
        }
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect logs from web server log files."""
        log_path = self.log_paths.get(self.server_type)
        if not log_path or not log_path.exists():
            return []
        
        logs = []
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    match = self.pattern.match(line)
                    if match:
                        logs.append(match.groupdict())
        except Exception as e:
            logger.error(f"Error reading {self.server_type} logs: {str(e)}")
        
        return logs 