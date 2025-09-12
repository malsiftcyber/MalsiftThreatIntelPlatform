import httpx
import json
import time
from typing import Dict, Any, Optional
from datetime import datetime
from loguru import logger

from app.models.edr.edr_models import EDRIndicator, LLMConfiguration


class LLMService:
    """LLM service for indicator analysis"""
    
    def __init__(self, db):
        self.db = db
    
    async def analyze_indicator(self, indicator: EDRIndicator, llm_config: LLMConfiguration) -> Dict[str, Any]:
        """Analyze indicator with LLM"""
        start_time = time.time()
        
        try:
            # Prepare analysis prompt
            prompt = self._create_analysis_prompt(indicator)
            
            # Call LLM API
            if llm_config.provider == "openai":
                response = await self._call_openai_api(prompt, llm_config)
            elif llm_config.provider == "anthropic":
                response = await self._call_anthropic_api(prompt, llm_config)
            else:
                raise ValueError(f"Unsupported LLM provider: {llm_config.provider}")
            
            # Parse response
            analysis_result = self._parse_llm_response(response, indicator)
            
            # Calculate processing time and cost
            processing_time = time.time() - start_time
            cost = self._calculate_cost(response, llm_config)
            
            return {
                "llm_provider": llm_config.provider,
                "llm_model": llm_config.default_model,
                "analysis_prompt": prompt,
                "analysis_response": response,
                "malicious_probability": analysis_result.get("malicious_probability"),
                "analysis_confidence": analysis_result.get("confidence"),
                "reasoning": analysis_result.get("reasoning"),
                "recommended_actions": analysis_result.get("recommended_actions"),
                "processing_time": processing_time,
                "cost": cost
            }
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise
    
    def _create_analysis_prompt(self, indicator: EDRIndicator) -> str:
        """Create analysis prompt for LLM"""
        context_info = ""
        if indicator.context_data:
            context_info = f"\nAdditional Context: {json.dumps(indicator.context_data, indent=2)}"
        
        prompt = f"""
You are a cybersecurity expert analyzing a potential threat indicator. Please analyze the following indicator and provide your assessment:

Indicator Type: {indicator.indicator_type}
Indicator Value: {indicator.indicator_value}
Detection Timestamp: {indicator.detection_timestamp}
Confidence Score: {indicator.confidence_score}
Severity: {indicator.severity}{context_info}

Please provide your analysis in the following JSON format:
{{
    "malicious_probability": 0.0-1.0,
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of your analysis",
    "recommended_actions": ["action1", "action2", "action3"],
    "threat_category": "malware/phishing/botnet/etc",
    "risk_level": "low/medium/high/critical"
}}

Consider the following factors:
1. Indicator type and value patterns
2. Context from the EDR platform
3. Known attack patterns and techniques
4. Severity and confidence scores
5. Temporal factors (recent detection)

Provide a thorough analysis focusing on the likelihood that this indicator represents malicious activity.
"""
        return prompt.strip()
    
    async def _call_openai_api(self, prompt: str, llm_config: LLMConfiguration) -> str:
        """Call OpenAI API"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {llm_config.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": llm_config.default_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert specializing in threat analysis. Always respond with valid JSON."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": llm_config.max_tokens,
                    "temperature": llm_config.temperature
                },
                timeout=30.0
            )
            response.raise_for_status()
            
            result = response.json()
            return result["choices"][0]["message"]["content"]
    
    async def _call_anthropic_api(self, prompt: str, llm_config: LLMConfiguration) -> str:
        """Call Anthropic API"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": llm_config.api_key,
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01"
                },
                json={
                    "model": llm_config.default_model,
                    "max_tokens": llm_config.max_tokens,
                    "temperature": llm_config.temperature,
                    "system": "You are a cybersecurity expert specializing in threat analysis. Always respond with valid JSON.",
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                },
                timeout=30.0
            )
            response.raise_for_status()
            
            result = response.json()
            return result["content"][0]["text"]
    
    def _parse_llm_response(self, response: str, indicator: EDRIndicator) -> Dict[str, Any]:
        """Parse LLM response"""
        try:
            # Try to extract JSON from response
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_str = response[json_start:json_end].strip()
            elif "{" in response and "}" in response:
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_str = response[json_start:json_end]
            else:
                # Fallback parsing
                return self._fallback_parse(response)
            
            analysis = json.loads(json_str)
            
            # Validate and normalize response
            return {
                "malicious_probability": float(analysis.get("malicious_probability", 0.5)),
                "confidence": float(analysis.get("confidence", 0.5)),
                "reasoning": analysis.get("reasoning", "Analysis completed"),
                "recommended_actions": analysis.get("recommended_actions", []),
                "threat_category": analysis.get("threat_category", "unknown"),
                "risk_level": analysis.get("risk_level", "medium")
            }
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return self._fallback_parse(response)
    
    def _fallback_parse(self, response: str) -> Dict[str, Any]:
        """Fallback parsing when JSON parsing fails"""
        # Simple keyword-based analysis
        malicious_keywords = ["malicious", "malware", "threat", "attack", "suspicious", "dangerous"]
        benign_keywords = ["legitimate", "safe", "normal", "clean", "benign"]
        
        response_lower = response.lower()
        malicious_score = sum(1 for keyword in malicious_keywords if keyword in response_lower)
        benign_score = sum(1 for keyword in benign_keywords if keyword in response_lower)
        
        if malicious_score > benign_score:
            malicious_probability = min(0.8, 0.5 + (malicious_score * 0.1))
        elif benign_score > malicious_score:
            malicious_probability = max(0.2, 0.5 - (benign_score * 0.1))
        else:
            malicious_probability = 0.5
        
        return {
            "malicious_probability": malicious_probability,
            "confidence": 0.3,  # Lower confidence for fallback
            "reasoning": f"Fallback analysis based on keyword detection. Response: {response[:200]}...",
            "recommended_actions": ["Manual review recommended"],
            "threat_category": "unknown",
            "risk_level": "medium"
        }
    
    def _calculate_cost(self, response: str, llm_config: LLMConfiguration) -> float:
        """Calculate API cost"""
        if not llm_config.cost_per_token:
            return 0.0
        
        # Rough token estimation (4 characters per token)
        estimated_tokens = len(response) / 4
        
        # Add input tokens (rough estimate)
        input_tokens = 1000  # Approximate for the prompt
        
        total_tokens = estimated_tokens + input_tokens
        return total_tokens * llm_config.cost_per_token
    
    async def test_llm_connection(self, llm_config: LLMConfiguration) -> Dict[str, Any]:
        """Test LLM API connection"""
        try:
            test_prompt = "Respond with: {'status': 'connected', 'model': 'working'}"
            
            if llm_config.provider == "openai":
                response = await self._call_openai_api(test_prompt, llm_config)
            elif llm_config.provider == "anthropic":
                response = await self._call_anthropic_api(test_prompt, llm_config)
            else:
                return {"success": False, "error": "Unsupported provider"}
            
            return {
                "success": True,
                "message": "LLM connection successful",
                "provider": llm_config.provider,
                "model": llm_config.default_model,
                "response": response[:100]
            }
            
        except Exception as e:
            logger.error(f"LLM connection test failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "provider": llm_config.provider
            }
