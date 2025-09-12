from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from loguru import logger

from app.core.database import get_db
from app.services.ml_threat_scoring import MLThreatScoring
from app.services.threat_intelligence import ThreatIntelligenceService
from app.schemas.threat_intelligence import ThreatLevel

router = APIRouter()


@router.post("/train")
async def train_ml_model(
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Train the machine learning model with historical data"""
    try:
        ml_scoring = MLThreatScoring()
        
        # Get historical indicators and sources
        indicators = threat_service.get_all_indicators(db)
        sources = threat_service.get_all_sources(db)
        
        # Train the model
        training_results = ml_scoring.train_model(indicators, sources)
        
        return {
            "message": "ML model training completed",
            "results": training_results
        }
    
    except Exception as e:
        logger.error(f"Error training ML model: {e}")
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.post("/score/{indicator_id}")
async def score_indicator(
    indicator_id: int,
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Score a specific indicator using ML"""
    try:
        ml_scoring = MLThreatScoring()
        
        # Get indicator and source
        indicator = threat_service.get_indicator_by_id(db, indicator_id)
        if not indicator:
            raise HTTPException(status_code=404, detail="Indicator not found")
        
        source = threat_service.get_source_by_id(db, indicator.source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        # Predict threat level
        predicted_level, confidence = ml_scoring.predict_threat_level(indicator, source)
        
        # Extract features for analysis
        features = ml_scoring.extract_features(indicator, source)
        manual_score = ml_scoring.calculate_manual_score(features)
        
        return {
            "indicator_id": indicator_id,
            "current_threat_level": indicator.threat_level,
            "predicted_threat_level": predicted_level,
            "confidence": confidence,
            "manual_score": manual_score,
            "features": {
                "source_reputation": features.source_reputation,
                "indicator_type_weight": features.indicator_type_weight,
                "threat_keywords": features.threat_keywords,
                "malware_family_mentions": features.malware_family_mentions,
                "attack_pattern_score": features.attack_pattern_score,
                "tld_risk": features.tld_risk
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scoring indicator: {e}")
        raise HTTPException(status_code=500, detail=f"Scoring failed: {str(e)}")


@router.get("/anomalies")
async def detect_anomalies(
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends(),
    limit: int = Query(100, description="Maximum number of anomalies to return")
):
    """Detect anomalous indicators using Isolation Forest"""
    try:
        ml_scoring = MLThreatScoring()
        
        # Get recent indicators and sources
        indicators = threat_service.get_recent_indicators(db, limit=1000)
        sources = threat_service.get_all_sources(db)
        
        # Detect anomalies
        anomalies = ml_scoring.detect_anomalies(indicators, sources)
        
        # Limit results
        anomalies = anomalies[:limit]
        
        return {
            "anomalies": anomalies,
            "total_detected": len(anomalies)
        }
    
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")


@router.get("/feature-importance")
async def get_feature_importance():
    """Get feature importance from the trained model"""
    try:
        ml_scoring = MLThreatScoring()
        importance = ml_scoring.get_feature_importance()
        
        return {
            "feature_importance": importance
        }
    
    except Exception as e:
        logger.error(f"Error getting feature importance: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get feature importance: {str(e)}")


@router.post("/bulk-score")
async def bulk_score_indicators(
    indicator_ids: List[int],
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Score multiple indicators using ML"""
    try:
        ml_scoring = MLThreatScoring()
        results = []
        
        for indicator_id in indicator_ids:
            try:
                # Get indicator and source
                indicator = threat_service.get_indicator_by_id(db, indicator_id)
                if not indicator:
                    continue
                
                source = threat_service.get_source_by_id(db, indicator.source_id)
                if not source:
                    continue
                
                # Predict threat level
                predicted_level, confidence = ml_scoring.predict_threat_level(indicator, source)
                
                results.append({
                    "indicator_id": indicator_id,
                    "current_threat_level": indicator.threat_level,
                    "predicted_threat_level": predicted_level,
                    "confidence": confidence
                })
            
            except Exception as e:
                logger.error(f"Error scoring indicator {indicator_id}: {e}")
                results.append({
                    "indicator_id": indicator_id,
                    "error": str(e)
                })
        
        return {
            "results": results,
            "total_processed": len(results)
        }
    
    except Exception as e:
        logger.error(f"Error in bulk scoring: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk scoring failed: {str(e)}")


@router.get("/model-status")
async def get_model_status():
    """Get the status of the ML model"""
    try:
        ml_scoring = MLThreatScoring()
        
        # Check if models are loaded
        import os
        model_dir = "models"
        classifier_exists = os.path.exists(os.path.join(model_dir, "threat_classifier.joblib"))
        scaler_exists = os.path.exists(os.path.join(model_dir, "feature_scaler.joblib"))
        
        return {
            "model_loaded": classifier_exists and scaler_exists,
            "classifier_exists": classifier_exists,
            "scaler_exists": scaler_exists,
            "feature_weights": ml_scoring.feature_weights
        }
    
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model status: {str(e)}")


@router.post("/update-threat-levels")
async def update_threat_levels_with_ml(
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends(),
    confidence_threshold: float = Query(0.7, description="Minimum confidence for updates"),
    limit: int = Query(1000, description="Maximum indicators to process")
):
    """Update threat levels using ML predictions"""
    try:
        ml_scoring = MLThreatScoring()
        
        # Get indicators that need updating
        indicators = threat_service.get_indicators_for_ml_update(db, limit=limit)
        sources = threat_service.get_all_sources(db)
        
        updated_count = 0
        skipped_count = 0
        
        for indicator in indicators:
            try:
                source = next((s for s in sources if s.id == indicator.source_id), None)
                if not source:
                    continue
                
                # Predict threat level
                predicted_level, confidence = ml_scoring.predict_threat_level(indicator, source)
                
                # Only update if confidence is high enough
                if confidence >= confidence_threshold:
                    # Update the indicator
                    threat_service.update_indicator_threat_level(
                        db, indicator.id, predicted_level
                    )
                    updated_count += 1
                else:
                    skipped_count += 1
            
            except Exception as e:
                logger.error(f"Error updating indicator {indicator.id}: {e}")
                skipped_count += 1
        
        return {
            "message": "Threat level updates completed",
            "updated_count": updated_count,
            "skipped_count": skipped_count,
            "confidence_threshold": confidence_threshold
        }
    
    except Exception as e:
        logger.error(f"Error updating threat levels: {e}")
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")
