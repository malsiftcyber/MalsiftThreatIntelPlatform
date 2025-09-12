import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from loguru import logger
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import json
from dataclasses import dataclass
import hashlib
import re

from app.core.config import settings
from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.schemas.threat_intelligence import ThreatLevel, IndicatorType


@dataclass
class ThreatFeatures:
    """Features used for threat scoring"""
    # Source credibility
    source_reputation: float
    source_type_weight: float
    
    # Temporal features
    days_since_first_seen: int
    days_since_last_seen: int
    frequency_score: float
    
    # Indicator characteristics
    indicator_type_weight: float
    value_length: int
    value_complexity: float
    
    # Threat context
    tag_count: int
    threat_keywords: int
    malware_family_mentions: int
    
    # External validation
    external_validation_score: float
    community_confidence: float
    
    # Network features (for IP/Domain indicators)
    asn_reputation: float
    geolocation_risk: float
    tld_risk: float
    
    # Behavioral features
    attack_pattern_score: float
    campaign_association: float


class MLThreatScoring:
    """Machine Learning-based threat scoring and prioritization"""
    
    def __init__(self):
        self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Feature weights for manual scoring
        self.feature_weights = {
            'source_reputation': 0.15,
            'temporal_freshness': 0.10,
            'indicator_type': 0.12,
            'threat_context': 0.18,
            'external_validation': 0.20,
            'network_reputation': 0.10,
            'behavioral_patterns': 0.15
        }
        
        # Model paths
        self.model_dir = "models"
        self.classifier_path = os.path.join(self.model_dir, "threat_classifier.joblib")
        self.scaler_path = os.path.join(self.model_dir, "feature_scaler.joblib")
        self.vectorizer_path = os.path.join(self.model_dir, "text_vectorizer.joblib")
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load pre-trained models if they exist
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models"""
        try:
            if os.path.exists(self.classifier_path):
                self.rf_classifier = joblib.load(self.classifier_path)
                logger.info("Loaded pre-trained threat classifier")
            
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                logger.info("Loaded feature scaler")
            
            if os.path.exists(self.vectorizer_path):
                self.tfidf_vectorizer = joblib.load(self.vectorizer_path)
                logger.info("Loaded text vectorizer")
                
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    def _save_models(self):
        """Save trained models"""
        try:
            joblib.dump(self.rf_classifier, self.classifier_path)
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.tfidf_vectorizer, self.vectorizer_path)
            logger.info("Saved trained models")
        except Exception as e:
            logger.error(f"Could not save models: {e}")
    
    def extract_features(self, indicator: ThreatIndicator, source: ThreatSource) -> ThreatFeatures:
        """Extract features from threat indicator for ML scoring"""
        
        # Source credibility
        source_reputation = self._calculate_source_reputation(source)
        source_type_weight = self._get_source_type_weight(source.source_type)
        
        # Temporal features
        days_since_first_seen = (datetime.now() - indicator.first_seen).days
        days_since_last_seen = (datetime.now() - indicator.last_seen).days
        frequency_score = self._calculate_frequency_score(indicator)
        
        # Indicator characteristics
        indicator_type_weight = self._get_indicator_type_weight(indicator.indicator_type)
        value_length = len(indicator.value)
        value_complexity = self._calculate_complexity(indicator.value)
        
        # Threat context
        tag_count = len(indicator.tags) if indicator.tags else 0
        threat_keywords = self._count_threat_keywords(indicator.description or "")
        malware_family_mentions = self._count_malware_families(indicator.description or "")
        
        # External validation
        external_validation_score = self._calculate_external_validation(indicator)
        community_confidence = self._calculate_community_confidence(indicator)
        
        # Network features
        asn_reputation = self._get_asn_reputation(indicator)
        geolocation_risk = self._get_geolocation_risk(indicator)
        tld_risk = self._get_tld_risk(indicator)
        
        # Behavioral features
        attack_pattern_score = self._detect_attack_patterns(indicator)
        campaign_association = self._calculate_campaign_association(indicator)
        
        return ThreatFeatures(
            source_reputation=source_reputation,
            source_type_weight=source_type_weight,
            days_since_first_seen=days_since_first_seen,
            days_since_last_seen=days_since_last_seen,
            frequency_score=frequency_score,
            indicator_type_weight=indicator_type_weight,
            value_length=value_length,
            value_complexity=value_complexity,
            tag_count=tag_count,
            threat_keywords=threat_keywords,
            malware_family_mentions=malware_family_mentions,
            external_validation_score=external_validation_score,
            community_confidence=community_confidence,
            asn_reputation=asn_reputation,
            geolocation_risk=geolocation_risk,
            tld_risk=tld_risk,
            attack_pattern_score=attack_pattern_score,
            campaign_association=campaign_association
        )
    
    def _calculate_source_reputation(self, source: ThreatSource) -> float:
        """Calculate source reputation score"""
        reputation_scores = {
            'government': 0.95,
            'commercial': 0.85,
            'opensource': 0.70,
            'community': 0.60
        }
        return reputation_scores.get(source.source_type.lower(), 0.50)
    
    def _get_source_type_weight(self, source_type: str) -> float:
        """Get weight for source type"""
        weights = {
            'government': 1.0,
            'commercial': 0.9,
            'opensource': 0.7,
            'community': 0.5
        }
        return weights.get(source_type.lower(), 0.5)
    
    def _calculate_frequency_score(self, indicator: ThreatIndicator) -> float:
        """Calculate frequency score based on how often indicator appears"""
        # This would be calculated from historical data
        # For now, return a default score
        return 0.5
    
    def _get_indicator_type_weight(self, indicator_type: IndicatorType) -> float:
        """Get weight for indicator type"""
        weights = {
            IndicatorType.IP_ADDRESS: 0.8,
            IndicatorType.DOMAIN: 0.7,
            IndicatorType.URL: 0.9,
            IndicatorType.HASH: 0.85,
            IndicatorType.EMAIL: 0.6,
            IndicatorType.MALWARE: 0.95,
            IndicatorType.REGISTRY_KEY: 0.75
        }
        return weights.get(indicator_type, 0.5)
    
    def _calculate_complexity(self, value: str) -> float:
        """Calculate complexity score of indicator value"""
        # Simple complexity calculation
        complexity = 0.0
        
        # Length factor
        complexity += min(len(value) / 100.0, 0.3)
        
        # Special characters
        special_chars = len(re.findall(r'[^a-zA-Z0-9]', value))
        complexity += min(special_chars / len(value), 0.3)
        
        # Entropy
        if len(value) > 0:
            char_freq = {}
            for char in value:
                char_freq[char] = char_freq.get(char, 0) + 1
            
            entropy = 0
            for freq in char_freq.values():
                p = freq / len(value)
                if p > 0:
                    entropy -= p * np.log2(p)
            
            complexity += min(entropy / 8.0, 0.4)  # Normalize to 0-0.4
        
        return min(complexity, 1.0)
    
    def _count_threat_keywords(self, text: str) -> int:
        """Count threat-related keywords in text"""
        threat_keywords = [
            'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'spam',
            'botnet', 'ddos', 'exploit', 'vulnerability', 'attack', 'threat',
            'compromise', 'breach', 'hack', 'intrusion', 'backdoor', 'keylogger',
            'spyware', 'adware', 'rootkit', 'worm', 'spyware'
        ]
        
        text_lower = text.lower()
        count = sum(1 for keyword in threat_keywords if keyword in text_lower)
        return count
    
    def _count_malware_families(self, text: str) -> int:
        """Count malware family mentions"""
        malware_families = [
            'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit', 'revil',
            'wannacry', 'notpetya', 'cryptolocker', 'zeus', 'citadel',
            'dridex', 'ursnif', 'qbot', 'icedid', 'bazar', 'suncrypt'
        ]
        
        text_lower = text.lower()
        count = sum(1 for family in malware_families if family in text_lower)
        return count
    
    def _calculate_external_validation(self, indicator: ThreatIndicator) -> float:
        """Calculate external validation score"""
        # This would check against external reputation services
        # For now, return a default score
        return 0.5
    
    def _calculate_community_confidence(self, indicator: ThreatIndicator) -> float:
        """Calculate community confidence score"""
        # This would be based on community voting/feedback
        # For now, return a default score
        return 0.5
    
    def _get_asn_reputation(self, indicator: ThreatIndicator) -> float:
        """Get ASN reputation score"""
        # This would query ASN reputation databases
        # For now, return a default score
        return 0.5
    
    def _get_geolocation_risk(self, indicator: ThreatIndicator) -> float:
        """Get geolocation risk score"""
        # This would check against known malicious geolocations
        # For now, return a default score
        return 0.5
    
    def _get_tld_risk(self, indicator: ThreatIndicator) -> float:
        """Get TLD risk score"""
        high_risk_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        if indicator.indicator_type in [IndicatorType.DOMAIN, IndicatorType.URL]:
            for tld in high_risk_tlds:
                if indicator.value.endswith(tld):
                    return 0.8
        return 0.3
    
    def _detect_attack_patterns(self, indicator: ThreatIndicator) -> float:
        """Detect attack patterns in indicator"""
        patterns = {
            'sql_injection': r'(union|select|insert|update|delete|drop|create|alter)',
            'xss': r'(<script|javascript:|onload=|onerror=)',
            'command_injection': r'(cmd|powershell|bash|sh|exec|system)',
            'file_inclusion': r'(\.\./|\.\.\\|include|require)',
            'directory_traversal': r'(\.\./|\.\.\\)',
            'phishing': r'(login|signin|verify|secure|update|confirm)'
        }
        
        text = f"{indicator.value} {indicator.description or ''}"
        text_lower = text.lower()
        
        pattern_matches = 0
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                pattern_matches += 1
        
        return min(pattern_matches / len(patterns), 1.0)
    
    def _calculate_campaign_association(self, indicator: ThreatIndicator) -> float:
        """Calculate campaign association score"""
        # This would check if indicator is part of known campaigns
        # For now, return a default score
        return 0.5
    
    def features_to_vector(self, features: ThreatFeatures) -> np.ndarray:
        """Convert features to feature vector"""
        feature_vector = [
            features.source_reputation,
            features.source_type_weight,
            features.days_since_first_seen,
            features.days_since_last_seen,
            features.frequency_score,
            features.indicator_type_weight,
            features.value_length,
            features.value_complexity,
            features.tag_count,
            features.threat_keywords,
            features.malware_family_mentions,
            features.external_validation_score,
            features.community_confidence,
            features.asn_reputation,
            features.geolocation_risk,
            features.tld_risk,
            features.attack_pattern_score,
            features.campaign_association
        ]
        
        return np.array(feature_vector).reshape(1, -1)
    
    def calculate_manual_score(self, features: ThreatFeatures) -> float:
        """Calculate manual threat score using weighted features"""
        score = 0.0
        
        # Source reputation
        score += features.source_reputation * self.feature_weights['source_reputation']
        
        # Temporal freshness (newer = higher score)
        temporal_freshness = max(0, 30 - features.days_since_first_seen) / 30
        score += temporal_freshness * self.feature_weights['temporal_freshness']
        
        # Indicator type
        score += features.indicator_type_weight * self.feature_weights['indicator_type']
        
        # Threat context
        threat_context = min(features.threat_keywords / 5.0, 1.0) + min(features.malware_family_mentions / 3.0, 1.0)
        score += threat_context * self.feature_weights['threat_context']
        
        # External validation
        score += features.external_validation_score * self.feature_weights['external_validation']
        
        # Network reputation
        network_score = (features.asn_reputation + features.geolocation_risk + features.tld_risk) / 3
        score += network_score * self.feature_weights['network_reputation']
        
        # Behavioral patterns
        behavioral_score = (features.attack_pattern_score + features.campaign_association) / 2
        score += behavioral_score * self.feature_weights['behavioral_patterns']
        
        return min(score, 1.0)
    
    def predict_threat_level(self, indicator: ThreatIndicator, source: ThreatSource) -> Tuple[ThreatLevel, float]:
        """Predict threat level using ML model"""
        try:
            # Extract features
            features = self.extract_features(indicator, source)
            feature_vector = self.features_to_vector(features)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Predict using Random Forest
            prediction = self.rf_classifier.predict(feature_vector_scaled)[0]
            probabilities = self.rf_classifier.predict_proba(feature_vector_scaled)[0]
            
            # Get confidence score
            confidence = max(probabilities)
            
            # Map prediction to ThreatLevel
            threat_level_mapping = {
                0: ThreatLevel.LOW,
                1: ThreatLevel.MEDIUM,
                2: ThreatLevel.HIGH,
                3: ThreatLevel.CRITICAL
            }
            
            threat_level = threat_level_mapping.get(prediction, ThreatLevel.MEDIUM)
            
            return threat_level, confidence
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            # Fallback to manual scoring
            return self._fallback_scoring(indicator, source)
    
    def _fallback_scoring(self, indicator: ThreatIndicator, source: ThreatSource) -> Tuple[ThreatLevel, float]:
        """Fallback scoring when ML model fails"""
        features = self.extract_features(indicator, source)
        manual_score = self.calculate_manual_score(features)
        
        # Map score to threat level
        if manual_score >= 0.8:
            threat_level = ThreatLevel.CRITICAL
        elif manual_score >= 0.6:
            threat_level = ThreatLevel.HIGH
        elif manual_score >= 0.4:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        return threat_level, manual_score
    
    def train_model(self, indicators: List[ThreatIndicator], sources: List[ThreatSource]) -> Dict[str, float]:
        """Train the ML model with historical data"""
        try:
            # Prepare training data
            X = []
            y = []
            
            for indicator in indicators:
                source = next((s for s in sources if s.id == indicator.source_id), None)
                if source:
                    features = self.extract_features(indicator, source)
                    feature_vector = self.features_to_vector(features).flatten()
                    X.append(feature_vector)
                    
                    # Convert threat level to numeric
                    level_mapping = {
                        ThreatLevel.LOW: 0,
                        ThreatLevel.MEDIUM: 1,
                        ThreatLevel.HIGH: 2,
                        ThreatLevel.CRITICAL: 3
                    }
                    y.append(level_mapping.get(indicator.threat_level, 1))
            
            if len(X) < 10:
                logger.warning("Insufficient training data")
                return {"accuracy": 0.0, "samples": len(X)}
            
            X = np.array(X)
            y = np.array(y)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Random Forest
            self.rf_classifier.fit(X_scaled, y)
            
            # Calculate accuracy
            y_pred = self.rf_classifier.predict(X_scaled)
            accuracy = np.mean(y_pred == y)
            
            # Save models
            self._save_models()
            
            logger.info(f"Trained ML model with {len(X)} samples, accuracy: {accuracy:.3f}")
            
            return {
                "accuracy": accuracy,
                "samples": len(X),
                "feature_importance": dict(zip(
                    ['source_reputation', 'source_type_weight', 'days_since_first_seen', 
                     'days_since_last_seen', 'frequency_score', 'indicator_type_weight',
                     'value_length', 'value_complexity', 'tag_count', 'threat_keywords',
                     'malware_family_mentions', 'external_validation_score', 'community_confidence',
                     'asn_reputation', 'geolocation_risk', 'tld_risk', 'attack_pattern_score',
                     'campaign_association'],
                    self.rf_classifier.feature_importances_
                ))
            }
            
        except Exception as e:
            logger.error(f"Error training ML model: {e}")
            return {"accuracy": 0.0, "error": str(e)}
    
    def detect_anomalies(self, indicators: List[ThreatIndicator], sources: List[ThreatSource]) -> List[Dict[str, Any]]:
        """Detect anomalous indicators using Isolation Forest"""
        try:
            # Prepare data
            X = []
            indicator_ids = []
            
            for indicator in indicators:
                source = next((s for s in sources if s.id == indicator.source_id), None)
                if source:
                    features = self.extract_features(indicator, source)
                    feature_vector = self.features_to_vector(features).flatten()
                    X.append(feature_vector)
                    indicator_ids.append(indicator.id)
            
            if len(X) < 5:
                return []
            
            X = np.array(X)
            
            # Fit and predict anomalies
            self.isolation_forest.fit(X)
            anomaly_scores = self.isolation_forest.decision_function(X)
            predictions = self.isolation_forest.predict(X)
            
            # Find anomalies (predictions == -1)
            anomalies = []
            for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
                if pred == -1:  # Anomaly detected
                    anomalies.append({
                        "indicator_id": indicator_ids[i],
                        "anomaly_score": float(score),
                        "severity": "high" if score < -0.5 else "medium"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model"""
        try:
            feature_names = [
                'source_reputation', 'source_type_weight', 'days_since_first_seen', 
                'days_since_last_seen', 'frequency_score', 'indicator_type_weight',
                'value_length', 'value_complexity', 'tag_count', 'threat_keywords',
                'malware_family_mentions', 'external_validation_score', 'community_confidence',
                'asn_reputation', 'geolocation_risk', 'tld_risk', 'attack_pattern_score',
                'campaign_association'
            ]
            
            importance_dict = dict(zip(feature_names, self.rf_classifier.feature_importances_))
            return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return {}
