from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./log_analyzer.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_source = Column(String)
    rule_name = Column(String)
    severity = Column(String)
    category = Column(String)
    message = Column(Text)
    remote_ip = Column(String, nullable=True)
    raw_log = Column(Text)
    hostname = Column(String, nullable=True)
    count = Column(Integer, default=1)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="user")

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_key = Column(String, unique=True, index=True)
    pattern = Column(String)
    severity = Column(String)
    category = Column(String)
    description = Column(Text)
    is_active = Column(Boolean, default=True)

class SystemMetadata(Base):
    __tablename__ = "metadata"
    key = Column(String, primary_key=True)
    value = Column(String)

class ReportHistory(Base):
    __tablename__ = "report_history"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
