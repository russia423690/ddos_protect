import time
import logging
import subprocess
from fastapi import Request, Cookie
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse, RedirectResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_403_FORBIDDEN
from sqlalchemy.orm import Session

from database import SessionLocal
from security import (
    is_ip_blacklisted, blacklist_ip, track_request_pattern,
    record_security_event
)
from middleware.anomaly_detection import detect_anomalies
from utils.local_storage import local_storage
from config import WHITELIST_IPS, BLOCK_DURATION

logger = logging.getLogger(__name__)

class DDoSProtectionMiddleware(BaseHTTPMiddleware):
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        client_ip = request.client.host if request.client else "127.0.0.1"
        
        if client_ip in WHITELIST_IPS:
            return await call_next(request)
        
        block_key = f"block:{client_ip}"
        if local_storage.get(block_key):
            logger.warning(f"Blocked request from locally blocked IP: {client_ip}")
            from app import generate_blocked_ip_response
            return generate_blocked_ip_response(
                request, 
                "Ваш IP-адрес заблокирован из-за подозрительной активности."
            )
        
        db = SessionLocal()
        try:
            if is_ip_blacklisted(client_ip, db):
                logger.warning(f"Blocked request from blacklisted IP (DB): {client_ip}")
                
                if not local_storage.get(block_key):
                    local_storage.setex(block_key, BLOCK_DURATION, "1")
                    
                    try:
                        subprocess.Popen(
                            ["./scripts/block_ip.sh", client_ip, str(BLOCK_DURATION)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        logger.info(f"Blocked IP {client_ip} via iptables for {BLOCK_DURATION} seconds")
                    except Exception as e:
                        logger.error(f"Failed to block IP via iptables: {str(e)}")
                
                from app import generate_blocked_ip_response
                return generate_blocked_ip_response(
                    request, 
                    "Ваш IP-адрес заблокирован системой защиты. Обратитесь к администратору для разблокировки."
                )
            
            request_stats = track_request_pattern(request, local_storage)
            
            anomalies = detect_anomalies(request, request_stats)
            
            critical_counter_key = f"critical_anomalies:{client_ip}"
            critical_counter = local_storage.get(critical_counter_key)
            critical_counter = int(critical_counter) if critical_counter else 0
            
            if anomalies and any(a["severity"] == "critical" for a in anomalies):
                critical_counter += 1
                local_storage.setex(critical_counter_key, 3600, str(critical_counter))
                
                if critical_counter >= 3:
                    critical_anomalies = [a for a in anomalies if a["severity"] == "critical"]
                    
                    reason = f"Critical anomalies detected: {', '.join(a['type'] for a in critical_anomalies)}"
                    blacklist_ip(client_ip, reason, db, duration=BLOCK_DURATION)
                    
                    local_storage.setex(block_key, BLOCK_DURATION, "1")
                    
                    try:
                        subprocess.Popen(
                            ["./scripts/block_ip.sh", client_ip, str(BLOCK_DURATION)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        logger.warning(f"IP {client_ip} blocked via iptables due to anomalies: {reason}")
                    except Exception as e:
                        logger.error(f"Failed to block IP via iptables: {str(e)}")
                    
                    record_security_event(
                        db=db,
                        event_type="ddos_protection_triggered",
                        ip_address=client_ip,
                        details=reason,
                        severity="critical"
                    )
                    
                    local_storage.setex(critical_counter_key, 3600, "0")
                    
                    from app import generate_blocked_ip_response
                    return generate_blocked_ip_response(
                        request, 
                        f"Доступ заблокирован из-за подозрительной активности: {reason}"
                    )
            else:
                if critical_counter > 0:
                    local_storage.setex(critical_counter_key, 3600, "0")
            
            if anomalies:
                for anomaly in anomalies:
                    record_security_event(
                        db=db,
                        event_type=f"anomaly_detected_{anomaly['type']}",
                        ip_address=client_ip,
                        details=anomaly["detail"],
                        severity=anomaly["severity"]
                    )
            
            response = await call_next(request)
            
            process_time = time.time() - start_time
            
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Security-Check"] = "Passed"
            
            return response
            
        except Exception as e:
            logger.error(f"Error in DDoS protection middleware: {str(e)}", exc_info=True)
            return await call_next(request)
        finally:
            db.close()
