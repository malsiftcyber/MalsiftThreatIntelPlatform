import httpx
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger

from app.models.edr.edr_models import EDRConnection


class SentinelOneClient:
    """SentinelOne API client"""
    
    def __init__(self, connection: EDRConnection):
        self.connection = connection
        self.base_url = connection.api_endpoint.rstrip('/')
        self.api_key = connection.api_key
        self.access_token = None
        self.token_expires = None
    
    async def _get_access_token(self) -> str:
        """Get API access token"""
        if self.access_token and self.token_expires and datetime.utcnow() < self.token_expires:
            return self.access_token
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/web/api/v2.1/users/login",
                json={
                    "username": self.connection.client_id,
                    "password": self.connection.client_secret
                }
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["data"]["token"]
            # SentinelOne tokens typically expire in 24 hours
            self.token_expires = datetime.utcnow() + timedelta(hours=23)
            
            return self.access_token
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test API connection"""
        try:
            token = await self._get_access_token()
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/web/api/v2.1/system/info",
                    headers={"Authorization": f"ApiToken {token}"}
                )
                response.raise_for_status()
                
                return {
                    "success": True,
                    "message": "Connection successful",
                    "platform": "SentinelOne"
                }
        except Exception as e:
            logger.error(f"SentinelOne connection test failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "platform": "SentinelOne"
            }
    
    async def extract_indicators(self, extraction_type: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from SentinelOne"""
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
            
            logger.info(f"Extracted {len(indicators)} indicators from SentinelOne")
            return indicators
            
        except Exception as e:
            logger.error(f"SentinelOne extraction failed: {e}")
            raise
    
    async def _extract_threat_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from threats"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "limit": 1000,
                "sortBy": "createdAt",
                "sortOrder": "desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["createdAt__gte"] = filters["start_time"]
                if "severity" in filters:
                    params["threatLevel"] = filters["severity"]
            
            response = await client.get(
                f"{self.base_url}/web/api/v2.1/threats",
                headers={"Authorization": f"ApiToken {token}"},
                params=params
            )
            response.raise_for_status()
            
            threats = response.json().get("data", [])
            
            for threat in threats:
                indicators.extend(self._parse_threat_indicators(threat))
        
        return indicators
    
    async def _extract_alert_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from alerts"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "limit": 1000,
                "sortBy": "createdAt",
                "sortOrder": "desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["createdAt__gte"] = filters["start_time"]
            
            response = await client.get(
                f"{self.base_url}/web/api/v2.1/activities",
                headers={"Authorization": f"ApiToken {token}"},
                params=params
            )
            response.raise_for_status()
            
            activities = response.json().get("data", [])
            
            for activity in activities:
                indicators.extend(self._parse_activity_indicators(activity))
        
        return indicators
    
    async def _extract_event_indicators(self, token: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Extract indicators from events"""
        indicators = []
        
        async with httpx.AsyncClient() as client:
            params = {
                "limit": 1000,
                "sortBy": "createdAt",
                "sortOrder": "desc"
            }
            
            if filters:
                if "start_time" in filters:
                    params["createdAt__gte"] = filters["start_time"]
            
            response = await client.get(
                f"{self.base_url}/web/api/v2.1/events",
                headers={"Authorization": f"ApiToken {token}"},
                params=params
            )
            response.raise_for_status()
            
            events = response.json().get("data", [])
            
            for event in events:
                indicators.extend(self._parse_event_indicators(event))
        
        return indicators
    
    def _parse_threat_indicators(self, threat: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from threat data"""
        indicators = []
        
        # Extract file indicators
        if "filePath" in threat:
            indicators.append({
                "indicator_type": "file_path",
                "indicator_value": threat["filePath"],
                "source_event_id": threat.get("id"),
                "detection_timestamp": threat.get("createdAt"),
                "confidence_score": self._map_threat_level(threat.get("threatLevel")),
                "severity": threat.get("threatLevel", "medium"),
                "context_data": {
                    "threat_id": threat.get("id"),
                    "threat_name": threat.get("threatName"),
                    "classification": threat.get("classification"),
                    "file_sha1": threat.get("fileSha1"),
                    "file_sha256": threat.get("fileSha256")
                }
            })
        
        # Extract file hashes
        if "fileSha1" in threat:
            indicators.append({
                "indicator_type": "hash",
                "indicator_value": threat["fileSha1"],
                "source_event_id": threat.get("id"),
                "detection_timestamp": threat.get("createdAt"),
                "confidence_score": self._map_threat_level(threat.get("threatLevel")),
                "severity": threat.get("threatLevel", "medium"),
                "context_data": {
                    "threat_id": threat.get("id"),
                    "threat_name": threat.get("threatName"),
                    "file_path": threat.get("filePath"),
                    "hash_type": "sha1"
                }
            })
        
        if "fileSha256" in threat:
            indicators.append({
                "indicator_type": "hash",
                "indicator_value": threat["fileSha256"],
                "source_event_id": threat.get("id"),
                "detection_timestamp": threat.get("createdAt"),
                "confidence_score": self._map_threat_level(threat.get("threatLevel")),
                "severity": threat.get("threatLevel", "medium"),
                "context_data": {
                    "threat_id": threat.get("id"),
                    "threat_name": threat.get("threatName"),
                    "file_path": threat.get("filePath"),
                    "hash_type": "sha256"
                }
            })
        
        # Extract network indicators
        if "networkQuarantine" in threat and threat["networkQuarantine"]:
            network_data = threat["networkQuarantine"]
            if "url" in network_data:
                indicators.append({
                    "indicator_type": "url",
                    "indicator_value": network_data["url"],
                    "source_event_id": threat.get("id"),
                    "detection_timestamp": threat.get("createdAt"),
                    "confidence_score": self._map_threat_level(threat.get("threatLevel")),
                    "severity": threat.get("threatLevel", "medium"),
                    "context_data": {
                        "threat_id": threat.get("id"),
                        "threat_name": threat.get("threatName"),
                        "network_quarantine": network_data
                    }
                })
        
        return indicators
    
    def _parse_activity_indicators(self, activity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from activity data"""
        indicators = []
        
        # Extract file indicators
        if "filePath" in activity:
            indicators.append({
                "indicator_type": "file_path",
                "indicator_value": activity["filePath"],
                "source_event_id": activity.get("id"),
                "detection_timestamp": activity.get("createdAt"),
                "confidence_score": 0.5,
                "severity": "medium",
                "context_data": {
                    "activity_id": activity.get("id"),
                    "activity_type": activity.get("activityType"),
                    "description": activity.get("description")
                }
            })
        
        # Extract network indicators
        if "networkQuarantine" in activity and activity["networkQuarantine"]:
            network_data = activity["networkQuarantine"]
            if "url" in network_data:
                indicators.append({
                    "indicator_type": "url",
                    "indicator_value": network_data["url"],
                    "source_event_id": activity.get("id"),
                    "detection_timestamp": activity.get("createdAt"),
                    "confidence_score": 0.5,
                    "severity": "medium",
                    "context_data": {
                        "activity_id": activity.get("id"),
                        "activity_type": activity.get("activityType"),
                        "network_quarantine": network_data
                    }
                })
        
        return indicators
    
    def _parse_event_indicators(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse indicators from event data"""
        indicators = []
        
        # Extract file indicators
        if "filePath" in event:
            indicators.append({
                "indicator_type": "file_path",
                "indicator_value": event["filePath"],
                "source_event_id": event.get("id"),
                "detection_timestamp": event.get("createdAt"),
                "confidence_score": 0.5,
                "severity": "medium",
                "context_data": {
                    "event_id": event.get("id"),
                    "event_type": event.get("eventType"),
                    "description": event.get("description")
                }
            })
        
        # Extract network indicators
        if "networkQuarantine" in event and event["networkQuarantine"]:
            network_data = event["networkQuarantine"]
            if "url" in network_data:
                indicators.append({
                    "indicator_type": "url",
                    "indicator_value": network_data["url"],
                    "source_event_id": event.get("id"),
                    "detection_timestamp": event.get("createdAt"),
                    "confidence_score": 0.5,
                    "severity": "medium",
                    "context_data": {
                        "event_id": event.get("id"),
                        "event_type": event.get("eventType"),
                        "network_quarantine": network_data
                    }
                })
        
        return indicators
    
    def _map_threat_level(self, threat_level: str) -> float:
        """Map SentinelOne threat level to confidence score"""
        mapping = {
            "critical": 0.9,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4,
            "info": 0.2
        }
        return mapping.get(threat_level, 0.5)
