import os
import logging
from typing import List

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Настройки базы данных
DATABASE_URL = os.environ.get("DATABASE_URL")

# Настройки PostgreSQL
PG_HOST = os.environ.get("PGHOST", "localhost")
PG_USER = os.environ.get("PGUSER", "postgres")
PG_PASSWORD = os.environ.get("PGPASSWORD", "postgres")
PG_PORT = os.environ.get("PGPORT", "5432")
PG_DATABASE = os.environ.get("PGDATABASE", "postgres")
PG_POOL_SIZE = 5
PG_MAX_OVERFLOW = 10
PG_POOL_RECYCLE = 300

# SQLite настройки (для локальной разработки)
SQLITE_DB_PATH = os.path.join("data", "local_storage.db")

# Настройки безопасности
SECRET_KEY = os.environ.get("SECRET_KEY", "this-is-a-very-long-and-secure-secret-key-that-should-be-changed")
COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "cookie-1298hd129hdisabfp1b80123ed")
COOKIE_MAX_AGE = 60 * 60 * 24 * 3  # 3 дня в секундах
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30  # 30 минут
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 минут

# Настройки веб-сервера
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 5000))
DEBUG = True
API_PREFIX = "/api"

# Настройки защиты от DDoS
RATE_LIMIT_ANONYMOUS = 120  # запросов в минуту для анонимных пользователей
RATE_LIMIT_AUTHENTICATED = 300  # запросов в минуту для аутентифицированных пользователей
RATE_LIMIT_WINDOW = 60  # размер окна в секундах (1 минута)
BLOCK_THRESHOLD = 15  # Количество превышений лимита для блокировки
BLOCK_DURATION = 1800  # Время блокировки в секундах (30 минут)

# Белый список IP адресов
WHITELIST_IPS: List[str] = [
    "127.0.0.1",       # localhost
    "::1",             # localhost IPv6
]

# API эндпоинты, которые должны быть доступны всегда
ALWAYS_ALLOWED_ENDPOINTS: List[str] = [
    "/api/stats",  # эндпоинт статистики
    "/health",     # эндпоинт проверки состояния
    "/browser-check", # страница проверки браузера
    "/verify-browser" # подтверждение проверки браузера
]

# Пути, которые исключены из проверки безопасностного куки
COOKIE_EXEMPT_PATHS: List[str] = [
    "/browser-check",
    "/verify-browser",
    "/static",
    "/favicon.ico",
    "/api/stats",  # Статистика доступна всем без проверки
    "/health",     # Health check доступен всем
]

# Подозрительные User-Agent
SUSPICIOUS_USER_AGENTS: List[str] = [
    "masscan", "zgrab", "gobuster", "nikto", "nmap", "sqlmap", "dirbuster", 
    "wpscan", "hydra", "appscan", "acunetix", "burpsuite", "metasploit",
    "python-requests", "Go-http-client", "curl", "wget", "Baiduspider", "SemrushBot",
    "AhrefsBot", "MJ12bot", "YandexBot", "Googlebot", "MegaIndex"
]

# Настройки CORS
CORS_ORIGINS = ["*"]  # Разрешенные источники для CORS
CORS_METHODS = ["*"]  # Разрешенные методы для CORS
CORS_HEADERS = ["*"]  # Разрешенные заголовки для CORS

# Заголовки безопасности
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self' cdn.replit.com cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.replit.com cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' cdn.replit.com cdnjs.cloudflare.com",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache"
}

# Настройки для локального хранилища при отсутствии Redis
LOCAL_STORAGE_DB_PATH = "data/local_storage.db"

# Функция для проверки расположения файлов и папок для хранения
def ensure_data_directories():
    data_dirs = ["data", "logs"]
    for directory in data_dirs:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")
