import time
import logging
import subprocess
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_403_FORBIDDEN
from sqlalchemy.orm import Session

from database import SessionLocal
from security import record_security_event
from utils.local_storage import local_storage
from config import (
    WHITELIST_IPS, ALWAYS_ALLOWED_ENDPOINTS, 
    RATE_LIMIT_ANONYMOUS, RATE_LIMIT_AUTHENTICATED, RATE_LIMIT_WINDOW,
    BLOCK_THRESHOLD, BLOCK_DURATION
)

logger = logging.getLogger(__name__)

class RateLimiterMiddleware(BaseHTTPMiddleware):
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        client_ip = request.client.host if request.client else "127.0.0.1"
        
        if client_ip in WHITELIST_IPS:
            return await call_next(request)
        
        path = request.url.path
        
        is_api_request = path.startswith("/api")
        
        if not is_api_request:
            return await call_next(request)
        
        auth_header = request.headers.get("Authorization")
        api_key = request.query_params.get("api_key") or request.headers.get("X-API-Key")
        
        is_authenticated = auth_header is not None or api_key is not None
        
        rate_limit = RATE_LIMIT_AUTHENTICATED if is_authenticated else RATE_LIMIT_ANONYMOUS
        
        rate_limit_key = f"rate_limit:{client_ip}"
        violations_key = f"violations:{client_ip}"
        
        block_key = f"block:{client_ip}"
        if local_storage.get(block_key):
            from app import generate_blocked_ip_response
            return generate_blocked_ip_response(
                request,
                "Ваш IP-адрес заблокирован из-за превышения лимита запросов."
            )
        
        exceeded = False
        retry_after = 0
        
        current_count = local_storage.get(rate_limit_key)
        
        if current_count is None:
            local_storage.setex(rate_limit_key, RATE_LIMIT_WINDOW, "1")
        else:
            current_count = int(current_count)
            
            if current_count >= rate_limit:
                exceeded = True
                
                violations = local_storage.get(violations_key)
                if violations is None:
                    violations = 1
                else:
                    violations = int(violations) + 1
                
                local_storage.setex(violations_key, 86400, str(violations))
                
                if violations >= BLOCK_THRESHOLD:
                    try:
                        local_storage.setex(block_key, BLOCK_DURATION, "1")
                        
                        subprocess.Popen(
                            ["./scripts/block_ip.sh", client_ip, str(BLOCK_DURATION)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        
                        logger.warning(f"Blocked IP {client_ip} for {BLOCK_DURATION} seconds due to excessive rate limit violations")
                        
                        db = SessionLocal()
                        try:
                            record_security_event(
                                db=db,
                                event_type="ip_blocked",
                                ip_address=client_ip,
                                details=f"IP blocked for {BLOCK_DURATION} seconds after {violations} rate limit violations",
                                severity="high"
                            )
                        finally:
                            db.close()
                        
                        from app import generate_blocked_ip_response
                        return generate_blocked_ip_response(
                            request,
                            f"Ваш IP-адрес заблокирован на {BLOCK_DURATION} секунд из-за многократного превышения лимита запросов ({violations} нарушений)."
                        )
                        
                    except Exception as e:
                        logger.error(f"Failed to block IP {client_ip}: {str(e)}")
                
                ttl = local_storage.ttl(rate_limit_key)
                retry_after = max(1, ttl) if ttl > 0 else RATE_LIMIT_WINDOW
            else:
                local_storage.incr(rate_limit_key)
        
        if exceeded:
            db = SessionLocal()
            try:
                record_security_event(
                    db=db,
                    event_type="rate_limit_exceeded",
                    ip_address=client_ip,
                    details=f"Rate limit of {rate_limit} requests per {RATE_LIMIT_WINDOW} seconds exceeded",
                    severity="medium"
                )
            finally:
                db.close()
            
            from starlette.exceptions import HTTPException as StarletteHTTPException
            headers = {"Retry-After": str(retry_after)}
            raise StarletteHTTPException(
                status_code=HTTP_429_TOO_MANY_REQUESTS, 
                detail=f"Превышен лимит запросов. Повторите попытку через {retry_after} секунд.",
                headers=headers
            )
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        
        current = local_storage.get(rate_limit_key)
        ttl = local_storage.ttl(rate_limit_key)
        
        if current is not None and ttl > 0:
            response.headers["X-RateLimit-Limit"] = str(rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, rate_limit - int(current)))
            response.headers["X-RateLimit-Reset"] = str(int(time.time() + ttl))
        
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
