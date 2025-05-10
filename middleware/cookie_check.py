import logging
import time
from typing import Optional, List
from fastapi import Request, Cookie
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, RedirectResponse
from utils.local_storage import local_storage
from utils.cookie_storage import cookie_storage
from utils.security_utils import verify_secure_token, generate_secure_token
from config import COOKIE_EXEMPT_PATHS, COOKIE_MAX_AGE, WHITELIST_IPS

logger = logging.getLogger(__name__)

class SecurityCheckMiddleware(BaseHTTPMiddleware):
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        for exempt_path in COOKIE_EXEMPT_PATHS:
            if path.startswith(exempt_path):
                return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        if cookie_storage.is_ip_blocked(client_ip):
            reason = cookie_storage.get_block_reason(client_ip) or "Подозрительная активность"
            logger.warning(f"Попытка доступа с заблокированного IP: {client_ip} (причина: {reason})")
            
            from app import generate_blocked_ip_response
            return generate_blocked_ip_response(request, f"Ваш IP заблокирован. Причина: {reason}")
        
        if client_ip in WHITELIST_IPS and "/browser-check" not in path:
            token = generate_secure_token(client_ip, user_agent)
            
            if not cookie_storage.verify_token(token, client_ip, user_agent):
                cookie_storage.store_token(client_ip, user_agent, token, COOKIE_MAX_AGE)
                logger.info(f"Автоматическая генерация токена безопасности для белого IP {client_ip}")
            
            response = await call_next(request)
            
            response.set_cookie(
                key="security_token", 
                value=token, 
                max_age=COOKIE_MAX_AGE, 
                httponly=True, 
                samesite="strict",
                secure=True
            )
            
            return response
        
        security_token = None
        for cookie in request.cookies:
            if cookie == "security_token":
                security_token = request.cookies[cookie]
                break
        
        has_valid_cookie = False
        if security_token:
            memory_check = verify_secure_token(security_token, client_ip, user_agent)
            
            db_check = cookie_storage.verify_token(security_token, client_ip, user_agent)
            
            has_valid_cookie = memory_check or db_check
            
            if memory_check and not db_check:
                cookie_storage.store_token(client_ip, user_agent, security_token, COOKIE_MAX_AGE)
                logger.debug(f"Токен сохранен в БД для IP {client_ip}")
            
            logger.debug(f"Cookie verification result for {client_ip} on {path}: {has_valid_cookie} (memory: {memory_check}, db: {db_check})")
        
        if not has_valid_cookie:
            redirect_count_key = f"redirect_count:{client_ip}"
            redirect_count = local_storage.get(redirect_count_key)
            redirect_count = int(redirect_count) if redirect_count else 0
            
            if redirect_count > 5:
                logger.warning(f"Слишком много редиректов для {client_ip}, пропускаем проверку")
                local_storage.setex(redirect_count_key, 60, "0")  # Сбрасываем счетчик через минуту
                
                token = generate_secure_token(client_ip, user_agent)
                cookie_storage.store_token(client_ip, user_agent, token, COOKIE_MAX_AGE)
                
                response = await call_next(request)
                response.set_cookie(
                    key="security_token", 
                    value=token, 
                    max_age=COOKIE_MAX_AGE, 
                    httponly=True, 
                    samesite="strict",
                    secure=True
                )
                
                return response
            
            local_storage.setex(redirect_count_key, 60, str(redirect_count + 1))
            
            if path.startswith("/api"):
                logger.info(f"API request without valid security cookie from {client_ip}: {path}")
                return RedirectResponse(url="/browser-check", status_code=303)
            else:
                logger.info(f"Redirecting {client_ip} to browser check for {path}")
                return RedirectResponse(url="/browser-check", status_code=303)
        
        redirect_count_key = f"redirect_count:{client_ip}"
        local_storage.delete(redirect_count_key)
        
        return await call_next(request)
