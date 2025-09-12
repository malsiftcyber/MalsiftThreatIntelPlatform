import httpx
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger

from app.models.edr.edr_models import EDRConnection


class DefenderClient:
    """Microsoft Defender for Endpoint API client"""
    
    def __init__(self, connection: EDRConnection):
        self.connection = connection
        self.base_url = connection.api_endpoint.rstrip('/')
        self.api_key = connection.api_key
        self.tenant_id = connection.tenant_id
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
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://api.securitycenter.microsoft.com/.default",
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
                    f"{self.base_url}/api/machines",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"$top": 1}
                )
                response.raise_for_status()
                
                return {
                    "success": True,
                    "message": "Connection successful",
                    "platform": "Microsoft Defender for Endpoint"
                }
        except Exception as e:
            logger.error(f"Defender connection test failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "platform": "Microsoft Defender for Endpoint"
            }
    
    async def extract_indicators(self, extraction_type: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from Microsoft Defender"""
        token = await self._get_access_token()
        indicators = []
        
        try:
            if extraction_type == "indicators":
                indicators = await self._extract_threat_indicators(token, filters)
            elif extraction_type == "alerts":
                indicators = await self._extract_alert_indicators(token, filters)
            elif extraction_type == "events":
                indicators = await self._extract_event_indicators(token, filters)
            else:
                raise ValueError(f"Unsupported extraction type: {extraction_type}")
            
            logger.info(f"Extracted {len(indicators)} indicators from Microsoft Defender")
            return indicators
            
        except Exception as e:
            logger.error(f"Defender extraction failed: {e}")
            raise
    
    async def _extract_threat_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from threat intelligence"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "$top": 1000,
                "$orderby": "createdDateTime desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["$filter"] = f"createdDateTime ge {filters['start_time']}"
            
            response = await client.get(
                f"{self.base_url}/api/tiIndicators",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            threat_indicators = response.json().get("value", [])
            
            for ti in threat_indicators:
                indicators.extend(self._parse_threat_intelligence_indicators(ti))
        
        return indicators
    
    async def _extract_alert_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from alerts"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "$top": 1000,
                "$orderby": "createdDateTime desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["$filter"] = f"createdDateTime ge {filters['start_time']}"
                if "severity" in filters:
                    severity_filter = f"severity eq '{filters['severity']}'"
                    if "$filter" in params:
                        params["$filter"] += f" and {severity_filter}"
                    else:
                        params["$filter"] = severity_filter
            
            response = await client.get(
                f"{self.base_url}/api/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            alerts = response.json().get("value", [])
            
            for alert in alerts:
                indicators.extend(self._parse_alert_indicators(alert))
        
        return indicators
    
    async def _extract_event_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from events"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "$top": 1000,
                "$orderby": "eventDateTime desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["$filter"] = f"eventDateTime ge {filters['start_time']}"
            
            response = await client.get(
                f"{self.base_url}/api/machineactions",
                headers={"Authorization": f"Bearer {token}"},
                params=params
            )
            response.raise_for_status()
            
            events = response.json().get("value", [])
            
            for event in events:
                indicators.extend(self._parse_event_indicators(event))
        
        return indicators
    
    def _parse_threat_intelligence_indicators(self, ti: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from threat intelligence data"""
        indicators = []
        
        indicator_type = self._map_defender_indicator_type(ti.get("indicatorType"))
        if indicator_type and ti.get("indicatorValue"):
            indicators.append({
                "indicator_type": indicator_type,
                "indicator_value": ti["indicatorValue"],
                "source_event_id": ti.get("id"),
                "detection_timestamp": ti.get("createdDateTime"),
                "confidence_score": self._map_defender_confidence(ti.get("confidence")),
                "severity": ti.get("severity", "medium"),
                "context_data": {
                    "ti_id": ti.get("id"),
                    "indicator_type": ti.get("indicatorType"),
                    "description": ti.get("description"),
                    "tags": ti.get("tags", []),
                    "action": ti.get("action")
                }
            })
        
        return indicators
    
    def _parse_alert_indicators(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from alert data"""
        indicators = []
        
        # Extract indicators from alert
        if "entities" in alert:
            for entity in alert["entities"]:
                if entity.get("type") == "File":
                    file_data = entity.get("file", {})
                    if "sha1" in file_data:
                        indicators.append({
                            "indicator_type": "hash",
                            "indicator_value": file_data["sha1"],
                            "source_event_id": alert.get("id"),
                            "detection_timestamp": alert.get("createdDateTime"),
                            "confidence_score": self._map_defender_severity(alert.get("severity")),
                            "severity": alert.get("severity", "medium"),
                            "context_data": {
                                "alert_id": alert.get("id"),
                                "alert_title": alert.get("title"),
                                "file_name": file_data.get("name"),
                                "file_path": file_data.get("filePath"),
                                "hash_type": "sha1"
                            }
                        })
                    
                    if "sha256" in file_data:
                        indicators.append({
                            "indicator_type": "hash",
                            "indicator_value": file_data["sha256"],
                            "source_event_id": alert.get("id"),
                            "detection_timestamp": alert.get("createdDateTime"),
                            "confidence_score": self._map_defender_severity(alert.get("severity")),
                            "severity": alert.get("severity", "medium"),
                            "context_data": {
                                "alert_id": alert.get("id"),
                                "alert_title": alert.get("title"),
                                "file_name": file_data.get("name"),
                                "file_path": file_data.get("filePath"),
                                "hash_type": "sha256"
                            }
                        })
                    
                    if "filePath" in file_data:
                        indicators.append({
                            "indicator_type": "file_path",
                            "indicator_value": file_data["filePath"],
                            "source_event_id": alert.get("id"),
                            "detection_timestamp": alert.get("createdDateTime"),
                            "confidence_score": self._map_defender_severity(alert.get("severity")),
                            "severity": alert.get("severity", "medium"),
                            "context_data": {
                                "alert_id": alert.get("id"),
                                "alert_title": alert.get("title"),
                                "file_name": file_data.get("name"),
                                "file_sha1": file_data.get("sha1"),
                                "file_sha256": file_data.get("sha256")
                            }
                        })
                
                elif entity.get("type") == "IpAddress":
                    ip_data = entity.get("ipAddress", {})
                    if "address" in ip_data:
                        indicators.append({
                            "indicator_type": "ip",
                            "indicator_value": ip_data["address"],
                            "source_event_id": alert.get("id"),
                            "detection_timestamp": alert.get("createdDateTime"),
                            "confidence_score": self._map_defender_severity(alert.get("severity")),
                            "severity": alert.get("severity", "medium"),
                            "context_data": {
                                "alert_id": alert.get("id"),
                                "alert_title": alert.get("title"),
                                "ip_type": ip_data.get("type"),
                                "location": ip_data.get("location")
                            }
                        })
                
                elif entity.get("type") == "Url":
                    url_data = entity.get("url", {})
                    if "url" in url_data:
                        indicators.append({
                            "indicator_type": "url",
                            "indicator_value": url_data["url"],
                            "source_event_id": alert.get("id"),
                            "detection_timestamp": alert.get("createdDateTime"),
                            "confidence_score": self._map_defender_severity(alert.get("severity")),
                            "severity": alert.get("severity", "medium"),
                            "context_data": {
                                "alert_id": alert.get("id"),
                                "alert_title": alert.get("title"),
                                "url_category": url_data.get("category")
                            }
                        })
        
        return indicators
    
    def _parse_event_indicators(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from event data"""
        indicators = []
        
        # Extract file indicators from machine actions
        if "requestor" in event and "filePath" in event["requestor"]:
            indicators.append({
                "indicator_type": "file_path",
                "indicator_value": event["requestor"]["filePath"],
                "source_event_id": event.get("id"),
                "detection_timestamp": event.get("eventDateTime"),
                "confidence_score": 0.5,
                "severity": "medium",
                "context_data": {
                    "event_id": event.get("id"),
                    "event_type": event.get("type"),
                    "requestor": event.get("requestor")
                }
            })
        
        return indicators
    
    def _map_defender_indicator_type(self, defender_type: str) -> Optional[str]:
        """Map Defender indicator type to standard indicator type"""
        mapping = {
            "DomainName": "domain",
            "IpAddress": "ip",
            "Url": "url",
            "FileMd5": "hash",
            "FileSha1": "hash",
            "FileSha256": "hash",
            "EmailAddress": "email",
            "File": "file_path"
        }
        return mapping.get(defender_type)
    
    def _map_defender_confidence(self, confidence: int) -> float:
        """Map Defender confidence to 0-1 scale"""
        if confidence is None:
            return 0.5
        return confidence / 100.0
    
    def _map_defender_severity(self, severity: str) -> float:
        """Map Defender severity to confidence score"""
        mapping = {
            "Informational": 0.2,
            "Low": 0.4,
            "Medium": 0.6,
            "High": 0.8,
            "Critical": 0.9
        }
        return mapping.get(severity, 0.5)
