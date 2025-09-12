#!/usr/bin/env python3
"""
Script to create admin user for Malsift
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.auth import User, Role, Base
from app.services.auth_service import AuthService
from passlib.context import CryptContext

# Create tables
Base.metadata.create_all(bind=engine)

def create_admin_user():
    """Create admin user and roles"""
    db = SessionLocal()
    auth_service = AuthService(db)
    
    try:
        # Create admin role if it doesn't exist
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if not admin_role:
            admin_role = Role(
                name="admin",
                description="Administrator role with full permissions",
                permissions='["*"]'  # All permissions
            )
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
            print("✅ Admin role created")
        else:
            print("✅ Admin role already exists")
        
        # Create user role if it doesn't exist
        user_role = db.query(Role).filter(Role.name == "user").first()
        if not user_role:
            user_role = Role(
                name="user",
                description="Default user role",
                permissions='["read:indicators", "read:feeds", "read:sources"]'
            )
            db.add(user_role)
            db.commit()
            db.refresh(user_role)
            print("✅ User role created")
        else:
            print("✅ User role already exists")
        
        # Check if admin user exists
        admin_user = db.query(User).filter(User.username == "admin").first()
        if admin_user:
            print("✅ Admin user already exists")
            return
        
        # Create admin user
        from app.schemas.auth import UserCreate
        
        admin_data = UserCreate(
            username="admin",
            email="admin@malsift.local",
            password="admin123",
            is_active=True,
            is_superuser=True
        )
        
        admin_user = auth_service.create_user(admin_data)
        admin_user.role_id = admin_role.id
        db.commit()
        
        print("✅ Admin user created successfully!")
        print(f"   Username: {admin_user.username}")
        print(f"   Email: {admin_user.email}")
        print(f"   Password: admin123")
        print("   ⚠️  IMPORTANT: Change the password immediately after first login!")
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin_user()
