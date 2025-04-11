import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiohttp

from storage.redis_client import RedisClient

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, redis_client: RedisClient, config: Dict[str, Any]):
        self.redis_client = redis_client
        self.config = config
        self.running = False
        self.status = "initialized"
        
        # Initialize notification channels
        self.channels = {
            "email": EmailNotifier(config["channels"]["email"]),
            "slack": SlackNotifier(config["channels"]["slack"]),
            "sms": SMSNotifier(config["channels"]["sms"])
        }
        
        # Alert aggregation settings
        self.aggregation_window = config["aggregation"]["window"]
        self.max_alerts = config["aggregation"]["max_alerts"]

    async def start_monitoring(self):
        """Start the alert monitoring process."""
        self.running = True
        self.status = "running"
        
        try:
            while self.running:
                # Get new threats from Redis queue
                threats = await self._get_new_threats()
                
                if threats:
                    # Process and aggregate alerts
                    alerts = await self._process_alerts(threats)
                    
                    # Send notifications
                    await self._send_notifications(alerts)
                
                await asyncio.sleep(5)  # Check every 5 seconds
        except Exception as e:
            logger.error(f"Error in alert monitoring loop: {str(e)}")
            self.status = "error"
            raise

    async def stop(self):
        """Stop the alert monitoring process."""
        self.running = False
        self.status = "stopped"

    async def _get_new_threats(self) -> List[Dict[str, Any]]:
        """Get new threats from Redis queue."""
        try:
            # Get threats from Redis list
            threats = await self.redis_client.lrange(
                "security_alerts:queue",
                0,
                -1
            )
            
            if threats:
                # Clear the queue after retrieving threats
                await self.redis_client.delete("security_alerts:queue")
            
            return threats
        except Exception as e:
            logger.error(f"Error getting threats from Redis: {str(e)}")
            return []

    async def _process_alerts(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and aggregate alerts."""
        # Group threats by source IP
        threats_by_ip = {}
        for threat in threats:
            ip = threat.get("source_ip")
            if ip:
                if ip not in threats_by_ip:
                    threats_by_ip[ip] = []
                threats_by_ip[ip].append(threat)
        
        # Aggregate alerts
        aggregated_alerts = []
        for ip, ip_threats in threats_by_ip.items():
            if len(ip_threats) > 1:
                # Combine related threats into a single alert
                alert = {
                    "type": "aggregated",
                    "source_ip": ip,
                    "severity": max(t.get("severity", "low") for t in ip_threats),
                    "timestamp": datetime.utcnow().isoformat(),
                    "threat_count": len(ip_threats),
                    "threats": ip_threats
                }
                aggregated_alerts.append(alert)
            else:
                # Single threat becomes a single alert
                aggregated_alerts.append(ip_threats[0])
        
        return aggregated_alerts[:self.max_alerts]

    async def _send_notifications(self, alerts: List[Dict[str, Any]]):
        """Send notifications through configured channels."""
        for alert in alerts:
            severity = alert.get("severity", "low")
            
            # Determine which channels to use based on severity
            channels_to_use = self._get_channels_for_severity(severity)
            
            for channel_name in channels_to_use:
                channel = self.channels.get(channel_name)
                if channel and channel.is_enabled():
                    try:
                        await channel.send_alert(alert)
                    except Exception as e:
                        logger.error(
                            f"Error sending alert through {channel_name}: {str(e)}"
                        )

    def _get_channels_for_severity(self, severity: str) -> List[str]:
        """Determine which notification channels to use based on severity."""
        if severity == "critical":
            return ["email", "slack", "sms"]
        elif severity == "high":
            return ["email", "slack"]
        elif severity == "medium":
            return ["slack"]
        return ["slack"]  # Low severity goes to Slack only

class BaseNotifier:
    """Base class for notification channels."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def is_enabled(self) -> bool:
        """Check if the notification channel is enabled."""
        return self.config.get("enabled", False)
    
    async def send_alert(self, alert: Dict[str, Any]):
        """Send an alert through this channel."""
        raise NotImplementedError

class EmailNotifier(BaseNotifier):
    async def send_alert(self, alert: Dict[str, Any]):
        """Send alert via email."""
        if not self.is_enabled():
            return
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.config["username"]
            msg["To"] = self.config["username"]  # Send to self for now
            msg["Subject"] = f"Security Alert: {alert.get('type')} - {alert.get('severity')}"
            
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, "html"))
            
            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                server.starttls()
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            raise

    def _format_email_body(self, alert: Dict[str, Any]) -> str:
        """Format alert data as HTML email body."""
        template = """
        <html>
            <body>
                <h2>Security Alert</h2>
                <p><strong>Type:</strong> {type}</p>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Source IP:</strong> {source_ip}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                {details}
            </body>
        </html>
        """
        
        details = ""
        if "threats" in alert:
            details = "<h3>Related Threats:</h3><ul>"
            for threat in alert["threats"]:
                details += f"<li>{threat.get('type')} - {threat.get('severity')}</li>"
            details += "</ul>"
        
        return template.format(
            type=alert.get("type", "Unknown"),
            severity=alert.get("severity", "Unknown"),
            source_ip=alert.get("source_ip", "Unknown"),
            timestamp=alert.get("timestamp", "Unknown"),
            details=details
        )

class SlackNotifier(BaseNotifier):
    async def send_alert(self, alert: Dict[str, Any]):
        """Send alert to Slack."""
        if not self.is_enabled():
            return
        
        try:
            webhook_url = self.config["webhook_url"]
            message = self._format_slack_message(alert)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    if response.status not in (200, 201):
                        raise Exception(f"Slack API error: {response.status}")
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
            raise

    def _format_slack_message(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert data as Slack message."""
        color = {
            "critical": "#780000",
            "high": "#c1121f",
            "medium": "#f0a500",
            "low": "#92c353"
        }.get(alert.get("severity", "low"), "#808080")
        
        fields = [
            {
                "title": "Type",
                "value": alert.get("type", "Unknown"),
                "short": True
            },
            {
                "title": "Severity",
                "value": alert.get("severity", "Unknown"),
                "short": True
            },
            {
                "title": "Source IP",
                "value": alert.get("source_ip", "Unknown"),
                "short": True
            }
        ]
        
        if "threats" in alert:
            threat_list = "\n".join(
                f"- {t.get('type')} ({t.get('severity')})"
                for t in alert["threats"]
            )
            fields.append({
                "title": "Related Threats",
                "value": threat_list,
                "short": False
            })
        
        return {
            "attachments": [{
                "color": color,
                "title": "Security Alert",
                "fields": fields,
                "ts": datetime.utcnow().timestamp()
            }]
        }

class SMSNotifier(BaseNotifier):
    async def send_alert(self, alert: Dict[str, Any]):
        """Send alert via SMS (using Twilio)."""
        if not self.is_enabled():
            return
        
        try:
            # This is a placeholder for SMS implementation
            # You would typically use Twilio or another SMS service here
            logger.info(f"SMS alert would be sent for: {alert}")
        except Exception as e:
            logger.error(f"Error sending SMS alert: {str(e)}")
            raise 