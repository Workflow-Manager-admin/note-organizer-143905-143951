"""
notes_database: All database interaction and schema for the Notes Organizer application.

- Uses SQLite by default for ease of local development.
- Reads database URL etc. from environment variables for flexible deployment.
- Provides SQLAlchemy engine/session/mapping for Users, Notes, Categories.
- Handles DB initialization/migration if not already setup.

PUBLIC INTERFACES:
    - get_db(): Dependency for FastAPI routes to provide a sql session.
    - User, Note, Category: ORM models.
"""

import os
from typing import Generator
from sqlalchemy import create_engine, Boolean, Column, ForeignKey, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.sql import func

from dotenv import load_dotenv

# Load env vars from .env at project root (if present)
load_dotenv()

# PUBLIC_INTERFACE
def get_database_url():
    """
    Uses env var NOTES_DATABASE_URL or falls back to a default SQLite url.
    """
    return os.environ.get("NOTES_DATABASE_URL", "sqlite:///./notes.db")

DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- ORM MODELS ---

# PUBLIC_INTERFACE
class User(Base):
    """User accounts for authentication."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    # Optionally: created/last_login...

    notes = relationship("Note", back_populates="owner", cascade="all,delete")
    categories = relationship("Category", back_populates="owner", cascade="all,delete")

# PUBLIC_INTERFACE
class Category(Base):
    """Categories for organizing notes."""
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Optionally: unique constraint (owner_id, name)
    owner = relationship("User", back_populates="categories")
    notes = relationship("Note", back_populates="category", cascade="all,delete")

# PUBLIC_INTERFACE
class Note(Base):
    """Notes created by users, optionally linked to a category."""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    owner_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)

    owner = relationship("User", back_populates="notes")
    category = relationship("Category", back_populates="notes")


# PUBLIC_INTERFACE
def get_db() -> Generator:
    """Yields a SQLAlchemy db session for use as a FastAPI dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PUBLIC_INTERFACE
def init_db():
    """Creates all tables. Run at startup or via migration system."""
    Base.metadata.create_all(bind=engine)
