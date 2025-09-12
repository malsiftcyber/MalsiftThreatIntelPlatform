from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.schemas.threat_intelligence import FetchJob
from app.models.threat_intelligence import FetchJob as FetchJobModel

router = APIRouter()


@router.get("/", response_model=List[FetchJob])
async def get_jobs(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Get recent fetch jobs"""
    jobs = db.query(FetchJobModel).order_by(
        FetchJobModel.created_at.desc()
    ).limit(limit).all()
    
    return jobs


@router.get("/{job_id}", response_model=FetchJob)
async def get_job(
    job_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific fetch job"""
    job = db.query(FetchJobModel).filter(FetchJobModel.id == job_id).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Fetch job not found")
    
    return job


@router.delete("/{job_id}")
async def delete_job(
    job_id: int,
    db: Session = Depends(get_db)
):
    """Delete a fetch job"""
    job = db.query(FetchJobModel).filter(FetchJobModel.id == job_id).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Fetch job not found")
    
    db.delete(job)
    db.commit()
    
    return {"message": "Fetch job deleted successfully"}
