import httpx
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger

from app.models.edr.edr_models import EDRConnection


class CrowdstrikeClient:
    """Crowdstrike Falcon API client"""
    
    def __init__(self, connection: EDRConnection):
        self.connection = connection
        self.base_url = connection.api_endpoint.rstrip('/')
        self.api_key = connection.api_key
        self.client_id = connection.client_id
        self.client_secret = connection.client_secret
        self.access_token = None
        self.token_expires = None
    
    async def _get_access_token(self) -> str:
        """Get OAuth2 access token"""
        if self.access_token and self.token_expires and datetime.utcnow() < self.token_expires:
            return self.access_token
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "client_credentials"
                }
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            expires_in = token_data.get("expires_in", 3600)
            self.token_expires = datetime.utcnow() + timedelta(seconds=expires_in - 60)
            
            return self.access_token
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test API connection"""
        try:
            token = await self._get_access_token()
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/sensors/queries/sensors/v1",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 1}
                )
                response.raise_for_status()
                
                return {
                    "success": True,
                    "message": "Connection successful",
                    "platform": "Crowdstrike Falcon"
                }
        except Exception as e:
            logger.error(f"Crowdstrike connection test failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "platform": "Crowdstrike Falcon"
            }
    
    async def extract_indicators(self, extraction_type: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from Crowdstrike"""
        token = await self._get_access_token()
        indicators = []
        
        try:
            if extraction_type == "indicators":
                indicators = await self._extract_detection_indicators(token, filters)
            elif extraction_type == "alerts":
                indicators = await self._extract_alert_indicators(token, filters)
            elif extraction_type == "events":
                indicators = await self._extract_event_indicators(token, filters)
            else:
                raise ValueError(f"Unsupported extraction type: {extraction_type}")
            
            logger.info(f"Extracted {len(indicators)} indicators from Crowdstrike")
            return indicators
            
        except Exception as e:
            logger.error(f"Crowdstrike extraction failed: {e}")
            raise
    
    async def _extract_detection_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from detections"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            # Get detections
            params = {
                "limit": 5000,
                "sort": "timestamp.desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["filter"] = f"timestamp:>='{filters['start_time']}'"
                if "severity" in filters:
                    severity_filter = f"severity:'{filters['severity']}'"
                    if "filter" in params:
                        params["filter"] += f"+{severity_filter}"
                    else:
                        params["filter"] = severity_filter
            
            response = await client.get(
                f"{self.base_url}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            detection_ids = response.json().get("resources", [])
            
            if not detection_ids:
                return indicators
            
            # Get detailed detection information
            response = await client.get(
                f"{self.base_url}/detects/entities/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"ids": ",".join(detection_ids[:100])}  # Limit to 100 detections
            )
            response.raise_for_status()
            
            detections = response.json().get("resources", [])
            
            for detection in detections:
                # Extract indicators from detection
                indicators.extend(self._parse_detection_indicators(detection))
        
        return indicators
    
    async def _extract_alert_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from alerts"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "limit": 5000,
                "sort": "created_timestamp.desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["filter"] = f"created_timestamp:>='{filters['start_time']}'"
            
            response = await client.get(
                f"{self.base_url}/alerts/queries/alerts/v1",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            alert_ids = response.json().get("resources", [])
            
            if not alert_ids:
                return indicators
            
            # Get detailed alert information
            response = await client.get(
                f"{self.base_url}/alerts/entities/alerts/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"ids": ",".join(alert_ids[:100])}
            )
            response.raise_for_status()
            
            alerts = response.json().get("resources", [])
            
            for alert in alerts:
                indicators.extend(self._parse_alert_indicators(alert))
        
        return indicators
    
    async def _extract_event_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from events"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "limit": 5000,
                "sort": "timestamp.desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["filter"] = f"timestamp:>='{filters['start_time']}'"
            
            response = await client.get(
                f"{self.base_url}/events/queries/events/v1",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            event_ids = response.json().get("resources", [])
            
            if not event_ids:
                return indicators
            
            # Get detailed event information
            response = await client.get(
                f"{self.base_url}/events/entities/events/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"ids": ",".join(event_ids[:100])}
            )
            response.raise_for_status()
            
            events = response.json().get("resources", [])
            
            for event in events:
                indicators.extend(self._parse_event_indicators(event))
        
        return indicators
    
    def _parse_detection_indicators(self, detection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from detection data"""
        indicators = []
        
        # Extract file hashes
        if "behaviors" in detection:
            for behavior in detection["behaviors"]:
                if "filepath" in behavior:
                    indicators.append({
                        "indicator_type": "file_path",
                        "indicator_value": behavior["filepath"],
                        "source_event_id": detection.get("detection_id"),
                        "detection_timestamp": detection.get("first_behavior"),
                        "confidence_score": behavior.get("confidence", 0.5),
                        "severity": detection.get("max_severity", "medium"),
                        "context_data": {
                            "behavior_id": behavior.get("behavior_id"),
                            "technique": behavior.get("technique"),
                            "tactic": behavior.get("tactic")
                        }
                    })
                
                if "filepath" in behavior and "sha256" in behavior:
                    indicators.append({
                        "indicator_type": "hash",
                        "indicator_value": behavior["sha256"],
                        "source_event_id": detection.get("detection_id"),
                        "detection_timestamp": detection.get("first_behavior"),
                        "confidence_score": behavior.get("confidence", 0.5),
                        "severity": detection.get("max_severity", "medium"),
                        "context_data": {
                            "behavior_id": behavior.get("behavior_id"),
                            "filepath": behavior.get("filepath"),
                            "technique": behavior.get("technique")
                        }
                    })
        
        # Extract network indicators
        if "behaviors" in detection:
            for behavior in detection["behaviors"]:
                if "ioc_type" in behavior and "ioc_value" in behavior:
                    indicator_type = self._map_crowdstrike_ioc_type(behavior["ioc_type"])
                    if indicator_type:
                        indicators.append({
                            "indicator_type": indicator_type,
                            "indicator_value": behavior["ioc_value"],
                            "source_event_id": detection.get("detection_id"),
                            "detection_timestamp": detection.get("first_behavior"),
                            "confidence_score": behavior.get("confidence", 0.5),
                            "severity": detection.get("max_severity", "medium"),
                            "context_data": {
                                "behavior_id": behavior.get("behavior_id"),
                                "ioc_type": behavior.get("ioc_type"),
                                "technique": behavior.get("technique")
                            }
                        })
        
        return indicators
    
    def _parse_alert_indicators(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from alert data"""
        indicators = []
        
        # Extract indicators from alert
        if "indicators" in alert:
            for indicator in alert["indicators"]:
                indicator_type = self._map_crowdstrike_ioc_type(indicator.get("type"))
                if indicator_type and indicator.get("value"):
                    indicators.append({
                        "indicator_type": indicator_type,
                        "indicator_value": indicator["value"],
                        "source_event_id": alert.get("id"),
                        "detection_timestamp": alert.get("created_timestamp"),
                        "confidence_score": indicator.get("confidence", 0.5),
                        "severity": alert.get("severity", "medium"),
                        "context_data": {
                            "alert_id": alert.get("id"),
                            "indicator_type": indicator.get("type"),
                            "description": alert.get("description")
                        }
                    })
        
        return indicators
    
    def _parse_event_indicators(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from event data"""
        indicators = []
        
        # Extract file indicators
        if "file_ref" in event:
            file_ref = event["file_ref"]
            if "file_name" in file_ref:
                indicators.append({
                    "indicator_type": "file_path",
                    "indicator_value": file_ref["file_name"],
                    "source_event_id": event.get("event_id"),
                    "detection_timestamp": event.get("timestamp"),
                    "confidence_score": 0.5,
                    "severity": "medium",
                    "context_data": {
                        "event_id": event.get("event_id"),
                        "event_type": event.get("event_type"),
                        "file_ref": file_ref
                    }
                })
        
        # Extract network indicators
        if "network_ref" in event:
            network_ref = event["network_ref"]
            if "ipv4" in network_ref:
                indicators.append({
                    "indicator_type": "ip",
                    "indicator_value": network_ref["ipv4"],
                    "source_event_id": event.get("event_id"),
                    "detection_timestamp": event.get("timestamp"),
                    "confidence_score": 0.5,
                    "severity": "medium",
                    "context_data": {
                        "event_id": event.get("event_id"),
                        "event_type": event.get("event_type"),
                        "network_ref": network_ref
                    }
                })
        
        return indicators
    
    def _map_crowdstrike_ioc_type(self, crowdstrike_type: str) -> Optional[str]:
        """Map Crowdstrike IOC type to standard indicator type"""
        mapping = {
            "domain": "domain",
            "ipv4": "ip",
            "ipv6": "ip",
            "url": "url",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "email": "email",
            "file_path": "file_path"
        }
        return mapping.get(crowdstrike_type)
