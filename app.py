import os
import logging
import random
import uuid
import time
from datetime import datetime
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Depends, HTTPException, Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
from starlette.exceptions import HTTPException as StarletteHTTPException

from database import engine, get_db
import models
from routers import users, auth
from middleware.ddos_protection import DDoSProtectionMiddleware
from middleware.rate_limiter import RateLimiterMiddleware
from utils.local_storage import local_storage
from utils.security_utils import generate_secure_token, verify_secure_token
from config import (
    COOKIE_MAX_AGE, HOST, PORT, SUSPICIOUS_USER_AGENTS, 
    SECURITY_HEADERS, CORS_ORIGINS, CORS_METHODS, CORS_HEADERS
)

logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FastAPI Application with DDoS Protection",
    description="A migrated application from Flask to FastAPI with intelligent DDoS protection",
    version="1.0.0",
    docs_url=None,
    redoc_url=None
)

templates = Jinja2Templates(directory="templates")

def generate_blocked_ip_response(request: Request, message: str = None):
    client_ip = request.client.host if request.client else "unknown"
    timestamp = datetime.utcnow().isoformat()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    
    default_message = "У вас нет прав для доступа к этому ресурсу. Ваш IP был заблокирован системой защиты."
    block_message = message or default_message
    
    # Для API запросов возвращаем JSON
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=HTTP_403_FORBIDDEN,
            content={
                "error": "access_denied",
                "detail": block_message,
                "request_id": request_id,
                "timestamp": timestamp
            }
        )
    # Для обычных запросов возвращаем HTML
    else:
        context = {
            "request": request,
            "status_code": HTTP_403_FORBIDDEN,
            "client_ip": client_ip,
            "timestamp": timestamp,
            "event_id": request_id,
            "request_id": request_id,
            "show_security_info": True,
            "title": "Доступ запрещен",
            "message": block_message
        }
        
        return templates.TemplateResponse("error.html", context, status_code=HTTP_403_FORBIDDEN)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=CORS_METHODS,
    allow_headers=CORS_HEADERS,
)

from middleware.cookie_check import SecurityCheckMiddleware

app.add_middleware(DDoSProtectionMiddleware)
app.add_middleware(RateLimiterMiddleware)
app.add_middleware(SecurityCheckMiddleware)

app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])

blocked_attacks = 0
total_requests = 0
blocked_ips = 0
avg_response_time = 50

def is_suspicious_request(request: Request) -> bool:
    user_agent = request.headers.get("user-agent", "").lower()
    if any(bot in user_agent.lower() for bot in SUSPICIOUS_USER_AGENTS):
        return True
    
    has_browser_headers = ("accept" in request.headers and 
                         "accept-language" in request.headers and
                         "accept-encoding" in request.headers)
    if not has_browser_headers:
        return True
    
    referer = request.headers.get("referer", "")
    if referer:
        try:
            parsed = urlparse(referer)
            if not parsed.netloc or not parsed.scheme:
                return True
        except:
            return True
    
    return False

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    global total_requests, avg_response_time
    
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    start_time = time.time()
    total_requests += 1
    
    response = await call_next(request)
    
    request_time = int((time.time() - start_time) * 1000)
    avg_response_time = int((avg_response_time * 0.95) + (request_time * 0.05))
    
    response.headers["X-Request-ID"] = request_id
    
    for header_name, header_value in SECURITY_HEADERS.items():
        response.headers[header_name] = header_value
    
    return response

@app.get("/", response_class=HTMLResponse)
async def root(request: Request, security_token: str = Cookie(None)):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    from utils.cookie_storage import cookie_storage
    
    # Проверяем токен как в памяти, так и в базе данных
    has_valid_cookie = False
    if security_token:
        memory_check = verify_secure_token(security_token, client_ip, user_agent)
        db_check = cookie_storage.verify_token(security_token, client_ip, user_agent)
        has_valid_cookie = memory_check or db_check
        
        logger.debug(f"Cookie verification result for {client_ip}: {has_valid_cookie} (memory: {memory_check}, db: {db_check})")
        
        # Если токен валиден в памяти, но не в БД, сохраняем его в БД
        if memory_check and not db_check:
            cookie_storage.store_token(client_ip, user_agent, security_token, COOKIE_MAX_AGE)
            logger.debug(f"Saved valid token to database for IP {client_ip}")
    
    # Если невалидный токен и подозрительный запрос - отправляем на проверку браузера
    if not has_valid_cookie and is_suspicious_request(request):
        logger.warning(f"Suspicious request detected from {client_ip}")
        return RedirectResponse(url="/browser-check")
    
    # Статистика для отображения
    stats = {
        "total_requests": total_requests,
        "blocked_attacks": blocked_attacks,
        "blocked_ips": blocked_ips,
        "avg_response_time": avg_response_time
    }
    
    # Создаем ответ
    response = templates.TemplateResponse(
        "index.html", 
        {"request": request, **stats}
    )
    
    # Если токен невалидный, генерируем новый и сохраняем в БД
    if not has_valid_cookie:
        token = generate_secure_token(client_ip, user_agent)
        
        # Сохраняем в базе данных
        cookie_storage.store_token(client_ip, user_agent, token, COOKIE_MAX_AGE)
        
        # Устанавливаем куку
        response.set_cookie(
            key="security_token", 
            value=token, 
            max_age=COOKIE_MAX_AGE, 
            httponly=True, 
            samesite="lax",  # Изменено с "strict" на "lax" для лучшей работы при редиректах
            secure=True
        )
        logger.info(f"Set new security cookie for {client_ip} and saved to database")
    
    return response

@app.get("/browser-check", response_class=HTMLResponse)
async def browser_check(request: Request, security_token: str = Cookie(None)):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    from utils.cookie_storage import cookie_storage
    
    # Проверяем токен как в памяти, так и в базе данных
    has_valid_cookie = False
    if security_token:
        memory_check = verify_secure_token(security_token, client_ip, user_agent)
        db_check = cookie_storage.verify_token(security_token, client_ip, user_agent)
        has_valid_cookie = memory_check or db_check
        
        logger.debug(f"Browser check cookie verification: {has_valid_cookie} (memory: {memory_check}, db: {db_check})")
    
    # Если у пользователя уже есть валидный токен, перенаправляем его на главную
    if has_valid_cookie and security_token:
        logger.info(f"Browser check passed with existing cookie for {client_ip}")
        redirect_response = RedirectResponse(url="/", status_code=303)
        
        # Восстанавливаем куку в redirect, чтобы она не потерялась при переходе
        redirect_response.set_cookie(
            key="security_token", 
            value=security_token, 
            max_age=COOKIE_MAX_AGE, 
            httponly=True, 
            samesite="lax",  # Изменено для лучшей работы редиректов
            secure=True
        )
        
        # Дополнительная проверка на случай неинициализированных переменных
        if 'db_check' in locals() and 'memory_check' in locals():
            # Если токен валиден только в памяти, сохраняем его также в БД
            if not db_check and memory_check:
                cookie_storage.store_token(client_ip, user_agent, security_token, COOKIE_MAX_AGE)
                logger.debug(f"Stored memory-valid token to database for {client_ip}")
        
        return redirect_response
    
    # Если блокировка IP есть в БД, но этот запрос дошел до проверки браузера, 
    # скорее всего это должен быть разблокирован
    if cookie_storage.is_ip_blocked(client_ip):
        cookie_storage.unblock_ip(client_ip)
        logger.info(f"IP {client_ip} разблокирован во время проверки браузера")
    
    # Если нет валидной куки, показываем форму проверки браузера
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    
    return templates.TemplateResponse(
        "browser_check.html",
        {
            "request": request,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "request_id": request_id
        }
    )

@app.post("/verify-browser", response_class=HTMLResponse)
async def verify_browser(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Сбрасываем счетчик редиректов, так как проверка браузера пройдена
    redirect_count_key = f"redirect_count:{client_ip}"
    local_storage.delete(redirect_count_key)
    
    # Разблокируем IP, если он был заблокирован
    from utils.cookie_storage import cookie_storage
    if cookie_storage.is_ip_blocked(client_ip):
        cookie_storage.unblock_ip(client_ip)
        logger.info(f"IP {client_ip} разблокирован после успешной проверки браузера")
    
    # Генерируем новый токен безопасности
    token = generate_secure_token(client_ip, user_agent)
    
    # Сохраняем токен в базе данных SQLite
    cookie_storage.store_token(client_ip, user_agent, token, COOKIE_MAX_AGE)
    
    # Сохраняем флаг верификации локально - дополнительная защита от редирект-цикла
    verified_key = f"browser_verified:{client_ip}"
    local_storage.setex(verified_key, COOKIE_MAX_AGE, "1")
    
    logger.info(f"Browser verification passed for {client_ip}, security cookie set and stored in database")
    
    # Создаем редирект на главную страницу
    redirect_response = RedirectResponse(url="/", status_code=303)
    
    # Устанавливаем куку безопасности в ответ
    redirect_response.set_cookie(
        key="security_token", 
        value=token, 
        max_age=COOKIE_MAX_AGE, 
        httponly=True, 
        samesite="lax",      # Изменено с strict на lax для лучшей совместимости с редиректами
        secure=True
    )
    
    # Используем HTTP заголовок для дополнительной проверки (для внутреннего использования)
    redirect_response.headers["X-Browser-Verified"] = "1"
    
    return redirect_response

@app.get("/api/test-ddos")
async def test_ddos(request: Request):
    global blocked_attacks, blocked_ips
    
    if random.random() < 0.3:
        blocked_attacks += 1
        logger.warning(f"Симуляция блокировки DDoS-атаки, всего блокировок: {blocked_attacks}")
        
        if random.random() < 0.2:
            blocked_ips += 1
        
        raise HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Simulated DDoS protection triggered."
        )
    
    return {"status": "ok", "message": "No anomalies detected in this request."}

@app.get("/api/stats")
async def get_stats():
    return {
        "total_requests": total_requests,
        "blocked_attacks": blocked_attacks,
        "blocked_ips": blocked_ips,
        "avg_response_time": avg_response_time,
        "uptime": "99.98%",
        "timestamp": datetime.utcnow().isoformat()
    }
    
@app.get("/api/security/tokens")
async def get_tokens(request: Request):
    """Получение списка активных токенов безопасности"""
    from utils.cookie_storage import cookie_storage
    
    tokens = cookie_storage.get_all_tokens()
    
    # Для безопасности не возвращаем сами значения токенов
    safe_tokens = []
    for token in tokens:
        safe_token = token.copy()
        if "token" in safe_token:
            safe_token["token"] = safe_token["token"][:10] + "..." # Показываем только начало токена
        safe_tokens.append(safe_token)
    
    return {
        "total": len(safe_tokens),
        "tokens": safe_tokens,
        "timestamp": datetime.utcnow().isoformat()
    }
    
@app.get("/api/security/blocks")
async def get_blocks(request: Request):
    """Получение списка заблокированных IP-адресов"""
    from utils.cookie_storage import cookie_storage
    
    blocks = cookie_storage.get_all_blocks()
    
    return {
        "total": len(blocks),
        "blocks": blocks,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/debug/unblock/{ip_address}")
async def debug_unblock_ip(ip_address: str):
    """
    Отладочный эндпоинт для разблокировки IP-адреса (доступен без авторизации)
    Важно: В продакшене этот эндпоинт следует удалить или защитить!
    """
    logger.warning(f"Вызван отладочный метод разблокировки для IP: {ip_address}")
    
    from utils.cookie_storage import cookie_storage
    
    # Проверяем, заблокирован ли IP
    is_blocked = cookie_storage.is_ip_blocked(ip_address)
    
    # Если заблокирован, разблокируем
    if is_blocked:
        cookie_storage.unblock_ip(ip_address)
        return {
            "status": "success",
            "message": f"IP {ip_address} успешно разблокирован",
            "timestamp": datetime.utcnow().isoformat()
        }
    else:
        return {
            "status": "info",
            "message": f"IP {ip_address} не был заблокирован",
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        logger.error(f"Database health check failed: {e}")
    
    try:
        local_storage.ping()
        storage_status = "healthy"
    except Exception as e:
        storage_status = f"unhealthy: {str(e)}"
        logger.error(f"Local storage health check failed: {e}")
    
    # Проверяем статус хранилища куки
    cookie_db_status = "not_available"
    try:
        from utils.cookie_storage import cookie_storage
        tokens = cookie_storage.get_all_tokens()
        blocks = cookie_storage.get_all_blocks()
        cookie_db_status = f"healthy (tokens: {len(tokens)}, blocks: {len(blocks)})"
    except Exception as e:
        cookie_db_status = f"unhealthy: {str(e)}"
        logger.error(f"Cookie storage health check failed: {e}")
        
    return {
        "status": "running",
        "database": db_status,
        "local_storage": storage_status,
        "cookie_storage": cookie_db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    client_ip = request.client.host if request.client else "unknown"
    timestamp = datetime.utcnow().isoformat()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    
    context = {
        "request": request,
        "status_code": exc.status_code,
        "client_ip": client_ip,
        "timestamp": timestamp,
        "event_id": request_id,
        "request_id": request_id,
        "show_security_info": True
    }
    
    if exc.status_code == HTTP_404_NOT_FOUND:
        context["title"] = "Страница не найдена"
        context["message"] = "Запрошенный ресурс не существует на сервере."
    elif exc.status_code == HTTP_403_FORBIDDEN:
        context["title"] = "Доступ запрещен"
        context["message"] = "У вас нет прав для доступа к этому ресурсу. Ваш IP был заблокирован системой защиты."
    elif exc.status_code == HTTP_429_TOO_MANY_REQUESTS:
        context["title"] = "Слишком много запросов"
        context["message"] = "Вы превысили допустимое количество запросов. Пожалуйста, повторите попытку позже."
        context["retry_after"] = 60
        
        if hasattr(exc, 'headers') and exc.headers and "retry-after" in exc.headers:
            context["retry_after"] = exc.headers["retry-after"]
    else:
        context["title"] = "Произошла ошибка"
        context["message"] = str(exc.detail) if hasattr(exc, 'detail') else "Извините, произошла неожиданная ошибка."
    
    return templates.TemplateResponse("error.html", context, status_code=exc.status_code)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    client_ip = request.client.host if request.client else "unknown"
    timestamp = datetime.utcnow().isoformat()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    
    return templates.TemplateResponse("error.html", {
        "request": request,
        "status_code": 500,
        "title": "Внутренняя ошибка сервера",
        "message": "Извините, на сервере произошла непредвиденная ошибка. Наши специалисты уже работают над ее устранением.",
        "client_ip": client_ip,
        "timestamp": timestamp,
        "event_id": request_id,
        "request_id": request_id,
        "show_security_info": False
    }, status_code=500)
