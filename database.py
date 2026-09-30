from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# استخدام متغيرات البيئة لتحديد مسار قاعدة البيانات بأمان تام مع الاحتفاظ بالافتراضي
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./tickets.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class TicketDB(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    client_name = Column(String, index=True)
    department = Column(String)
    extension_number = Column(String)
    company_name = Column(String)
    category = Column(String)  # جهاز/نظام تشغيل، Microsoft 365، Odoo
    priority = Column(String, default="عادي") # حرج/عاجل، متوسط، عادي
    restarted = Column(String)  # نعم / لا
    issue_description = Column(Text)
    status = Column(String, default="جديد")  # جديد، قيد العمل، مغلق
    progress = Column(Integer, default=0)    # نسبة الإنجاز من 0 إلى 100
    ai_summary = Column(Text, nullable=True)
    technician_name = Column(String, nullable=True)
    technician_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow) # إضافة وقت إنشاء التذكرة لتنظيم السجلات

Base.metadata.create_all(bind=engine)