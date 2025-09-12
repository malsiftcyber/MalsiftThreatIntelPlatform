from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from loguru import logger
import json
import yaml
from pathlib import Path

from app.core.database import get_db
from app.services.custom_feed_parsers import CustomFeedParserManager
from app.services.threat_intelligence import ThreatIntelligenceService
from app.schemas.threat_intelligence import ThreatSourceCreate, ThreatSource

router = APIRouter()


@router.get("/available")
async def get_available_parsers():
    """Get list of available parser types"""
    try:
        parser_manager = CustomFeedParserManager()
        return {
            "builtin_parsers": ["json", "csv", "xml"],
            "custom_parsers": list(parser_manager.loaded_parsers.keys()),
            "all_parsers": parser_manager.get_available_parsers()
        }
    except Exception as e:
        logger.error(f"Error getting available parsers: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get parsers: {str(e)}")


@router.post("/validate-config")
async def validate_parser_config(config: Dict[str, Any]):
    """Validate a parser configuration"""
    try:
        parser_manager = CustomFeedParserManager()
        validated_config = parser_manager.validate_config(config)
        
        return {
            "valid": True,
            "config": validated_config
        }
    except ValueError as e:
        return {
            "valid": False,
            "errors": str(e)
        }
    except Exception as e:
        logger.error(f"Error validating config: {e}")
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.post("/test")
async def test_parser_config(
    config: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Test a parser configuration with a sample source"""
    try:
        parser_manager = CustomFeedParserManager()
        
        # Validate config first
        validated_config = parser_manager.validate_config(config)
        
        # Create a temporary source for testing
        test_source = ThreatSource(
            id=0,
            name="test_source",
            description="Temporary source for testing",
            url="",
            api_key="",
            is_active=True,
            source_type="custom",
            metadata={"custom_parser_config": json.dumps(config)}
        )
        
        # Create parser and test
        parser = parser_manager.create_parser(test_source, validated_config)
        
        async with parser:
            indicators = await parser.fetch_indicators()
        
        return {
            "success": True,
            "indicators_found": len(indicators),
            "sample_indicators": indicators[:5] if indicators else [],
            "config": validated_config
        }
    
    except Exception as e:
        logger.error(f"Error testing parser: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/create-source")
async def create_custom_source(
    source_data: ThreatSourceCreate,
    parser_config: Dict[str, Any],
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Create a new threat source with custom parser configuration"""
    try:
        # Validate parser config
        parser_manager = CustomFeedParserManager()
        validated_config = parser_manager.validate_config(parser_config)
        
        # Add parser config to metadata
        source_data.metadata = source_data.metadata or {}
        source_data.metadata["custom_parser_config"] = json.dumps(validated_config)
        source_data.metadata["parser_type"] = "custom"
        
        # Create the source
        source = threat_service.create_source(db, source_data)
        
        return {
            "message": "Custom source created successfully",
            "source_id": source.id,
            "config": validated_config
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating custom source: {e}")
        raise HTTPException(status_code=500, detail=f"Creation failed: {str(e)}")


@router.get("/templates")
async def get_parser_templates():
    """Get parser configuration templates"""
    templates = {
        "json": {
            "parser_type": "json",
            "url": "https://api.example.com/threats",
            "headers": {
                "Authorization": "Bearer YOUR_API_KEY",
                "Accept": "application/json"
            },
            "indicator_path": "data.threats",
            "value_field": "indicator",
            "type_field": "type",
            "description_field": "description",
            "tags_field": "tags",
            "threat_level_field": "severity"
        },
        "csv": {
            "parser_type": "csv",
            "url": "https://example.com/threats.csv",
            "delimiter": ",",
            "has_header": True,
            "value_column": 0,
            "type_column": 1,
            "description_column": 2,
            "tags_column": 3,
            "threat_level_column": 4
        },
        "xml": {
            "parser_type": "xml",
            "url": "https://example.com/threats.xml",
            "indicator_xpath": ".//threat",
            "value_xpath": "./indicator",
            "type_xpath": "./type",
            "description_xpath": "./description",
            "tags_xpath": "./tags",
            "threat_level_xpath": "./severity"
        }
    }
    
    return {
        "templates": templates,
        "usage": {
            "json": "For JSON APIs with nested indicator arrays",
            "csv": "For CSV files with tabular threat data",
            "xml": "For XML feeds with structured threat information"
        }
    }


@router.post("/upload-custom-parser")
async def upload_custom_parser(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload a custom parser Python file"""
    try:
        # Validate file type
        if not file.filename.endswith('.py'):
            raise HTTPException(status_code=400, detail="Only Python files (.py) are allowed")
        
        # Read file content
        content = await file.read()
        content_str = content.decode('utf-8')
        
        # Validate Python syntax
        try:
            compile(content_str, file.filename, 'exec')
        except SyntaxError as e:
            raise HTTPException(status_code=400, detail=f"Invalid Python syntax: {str(e)}")
        
        # Save to custom_parsers directory
        parser_manager = CustomFeedParserManager()
        parser_file = parser_manager.parsers_dir / file.filename
        
        with open(parser_file, 'w') as f:
            f.write(content_str)
        
        # Reload parsers
        parser_manager._load_custom_parsers()
        
        return {
            "message": "Custom parser uploaded successfully",
            "filename": file.filename,
            "available_parsers": list(parser_manager.loaded_parsers.keys())
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading custom parser: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/custom-parsers")
async def list_custom_parsers():
    """List all custom parser files"""
    try:
        parser_manager = CustomFeedParserManager()
        parser_files = []
        
        for parser_file in parser_manager.parsers_dir.glob("*.py"):
            if parser_file.name != "__init__.py":
                parser_files.append({
                    "filename": parser_file.name,
                    "size": parser_file.stat().st_size,
                    "modified": parser_file.stat().st_mtime
                })
        
        return {
            "custom_parsers": parser_files,
            "loaded_parsers": list(parser_manager.loaded_parsers.keys())
        }
    
    except Exception as e:
        logger.error(f"Error listing custom parsers: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list parsers: {str(e)}")


@router.delete("/custom-parser/{filename}")
async def delete_custom_parser(filename: str):
    """Delete a custom parser file"""
    try:
        parser_manager = CustomFeedParserManager()
        parser_file = parser_manager.parsers_dir / filename
        
        if not parser_file.exists():
            raise HTTPException(status_code=404, detail="Parser file not found")
        
        # Remove from loaded parsers
        if filename.replace('.py', '') in parser_manager.loaded_parsers:
            del parser_manager.loaded_parsers[filename.replace('.py', '')]
        
        # Delete file
        parser_file.unlink()
        
        return {
            "message": "Custom parser deleted successfully",
            "filename": filename
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting custom parser: {e}")
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")


@router.get("/parser-config/{source_id}")
async def get_parser_config(
    source_id: int,
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Get parser configuration for a specific source"""
    try:
        source = threat_service.get_source_by_id(db, source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        config_str = source.metadata.get('custom_parser_config', '{}')
        try:
            config = json.loads(config_str)
        except json.JSONDecodeError:
            config = {}
        
        return {
            "source_id": source_id,
            "source_name": source.name,
            "parser_config": config,
            "parser_type": source.metadata.get('parser_type', 'unknown')
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting parser config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get config: {str(e)}")


@router.put("/parser-config/{source_id}")
async def update_parser_config(
    source_id: int,
    config: Dict[str, Any],
    db: Session = Depends(get_db),
    threat_service: ThreatIntelligenceService = Depends()
):
    """Update parser configuration for a specific source"""
    try:
        # Validate config
        parser_manager = CustomFeedParserManager()
        validated_config = parser_manager.validate_config(config)
        
        # Update source metadata
        source = threat_service.get_source_by_id(db, source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        source.metadata = source.metadata or {}
        source.metadata["custom_parser_config"] = json.dumps(validated_config)
        source.metadata["parser_type"] = "custom"
        
        # Save updated source
        threat_service.update_source(db, source_id, source)
        
        return {
            "message": "Parser configuration updated successfully",
            "source_id": source_id,
            "config": validated_config
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating parser config: {e}")
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")
