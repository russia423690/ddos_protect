import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config import (
    DATABASE_URL, PG_HOST, PG_USER, PG_PASSWORD, PG_PORT, PG_DATABASE,
    PG_POOL_SIZE, PG_MAX_OVERFLOW, PG_POOL_RECYCLE, SQLITE_DB_PATH
)

logger = logging.getLogger(__name__)

use_sqlite = False
db_url = DATABASE_URL

if not db_url:
    db_url = f"postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}"

try:
    temp_engine = create_engine(db_url, connect_args={"connect_timeout": 5})
    with temp_engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    logger.info("Успешное подключение к PostgreSQL")
except Exception as e:
    logger.warning(f"Не удалось подключиться к PostgreSQL: {e}")
    logger.info("Используем SQLite для локальной разработки")
    use_sqlite = True
    
    os.makedirs(os.path.dirname(SQLITE_DB_PATH), exist_ok=True)
    db_url = f"sqlite:///{SQLITE_DB_PATH}"

if use_sqlite:
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False}
    )
    logger.info(f"Инициализирован движок SQLite: {db_url}")
else:
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        pool_recycle=PG_POOL_RECYCLE,
        pool_size=PG_POOL_SIZE,
        max_overflow=PG_MAX_OVERFLOW
    )
    logger.info(f"Инициализирован движок PostgreSQL")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
