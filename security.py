import os
import secrets
import hashlib
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import Request, HTTPException, status

from models import SecurityEvent, BlacklistedIP
from utils.local_storage import local_storage
import schemas

logger = logging.getLogger(__name__)

MAX_FAILED_LOGIN_ATTEMPTS = 5
FAILED_LOGIN_WINDOW = 3600
IP_BLACKLIST_DURATION = 86400
REQUEST_TRACKING_WINDOW = 600
BLOCK_DURATION = 3600

def is_ip_blacklisted(ip_address: str, db: Session) -> bool:
    block_key = f"blacklist:{ip_address}"
    if local_storage.get(block_key):
        return True
    
    from sqlalchemy import or_
    blacklisted_ip = db.query(BlacklistedIP).filter(
        BlacklistedIP.ip_address == ip_address,
        or_(
            BlacklistedIP.expires_at > datetime.utcnow(),
            BlacklistedIP.expires_at.is_(None)
        )
    ).first()
    
    if blacklisted_ip:
        if blacklisted_ip.expires_at:
            ttl = int((blacklisted_ip.expires_at - datetime.utcnow()).total_seconds())
            local_storage.setex(block_key, ttl, "1")
        else:
            local_storage.setex(block_key, IP_BLACKLIST_DURATION, "1")
        return True
    
    return False

def blacklist_ip(ip_address: str, reason: str, db: Session, duration: Optional[int] = None) -> BlacklistedIP:
    expires_at = None
    if duration:
        expires_at = datetime.utcnow() + timedelta(seconds=duration)
    else:
        duration = IP_BLACKLIST_DURATION
    
    blacklisted_ip = BlacklistedIP(
        ip_address=ip_address,
        reason=reason,
        expires_at=expires_at
    )
    db.add(blacklisted_ip)
    db.commit()
    db.refresh(blacklisted_ip)
    
    block_key = f"blacklist:{ip_address}"
    local_storage.setex(block_key, duration, "1")
    
    try:
        subprocess.Popen(
            ["./scripts/block_ip.sh", ip_address, str(duration)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.warning(f"IP {ip_address} blocked via iptables for {duration} seconds: {reason}")
    except Exception as e:
        logger.error(f"Failed to block IP via iptables: {str(e)}")
    
    logger.warning(f"IP {ip_address} blacklisted: {reason}")
    return blacklisted_ip

def record_failed_login(ip_address: str, username: str) -> int:
    key = f"failed_login:{ip_address}:{username}"
    
    count = local_storage.incr(key)
    
    if count == 1:
        local_storage.expire(key, FAILED_LOGIN_WINDOW)
    
    return count

def check_failed_logins(ip_address: str, username: str) -> int:
    key = f"failed_login:{ip_address}:{username}"
    count = local_storage.get(key)
    
    return int(count) if count else 0

def reset_failed_logins(ip_address: str, username: str) -> None:
    key = f"failed_login:{ip_address}:{username}"
    local_storage.delete(key)

def record_security_event(
    db: Session,
    event_type: str,
    ip_address: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None,
    severity: str = "medium"
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=event_type,
        ip_address=ip_address,
        user_id=user_id,
        details=details,
        severity=severity
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    
    log_message = f"Security event: {event_type} from {ip_address}"
    if user_id:
        log_message += f" (user: {user_id})"
    if details:
        log_message += f" - {details}"
    
    if severity in ("high", "critical"):
        logger.warning(log_message)
    else:
        logger.info(log_message)
    
    if severity == "critical" and event_type not in ["ip_blocked", "ddos_protection_triggered"]:
        block_key = f"block:{ip_address}"
        if not local_storage.get(block_key):
            logger.warning(f"Critical security event detected, blocking IP {ip_address}")
            blacklist_ip(db=db, ip_address=ip_address, reason=f"Critical security event: {event_type}", duration=BLOCK_DURATION)
    
    return event

def track_request_pattern(request: Request, storage=None) -> Dict[str, Any]:
    if storage is None:
        storage = local_storage
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    endpoint = f"{request.method}:{request.url.path}"
    
    requests_key = f"requests:{client_ip}"
    
    timestamp = datetime.utcnow().timestamp()
    
    request_data = {
        "endpoint": endpoint,
        "timestamp": timestamp,
        "method": request.method,
        "query_params": str(request.query_params),
        "path": request.url.path
    }
    
    storage.lpush(requests_key, json.dumps(request_data))
    storage.ltrim(requests_key, 0, 99)
    storage.expire(requests_key, REQUEST_TRACKING_WINDOW)
    
    requests_count = storage.llen(requests_key)
    
    all_requests = storage.lrange(requests_key, 0, -1)
    endpoints = set()
    for req in all_requests:
        try:
            req_data = json.loads(req)
            endpoints.add(req_data["endpoint"])
        except (json.JSONDecodeError, KeyError):
            pass
    
    unique_endpoints = len(endpoints)
    
    if requests_count >= 2:
        try:
            oldest_request = json.loads(all_requests[-1])
            oldest_timestamp = oldest_request["timestamp"]
            time_span = timestamp - oldest_timestamp
            requests_per_second = requests_count / max(time_span, 1)
        except (json.JSONDecodeError, KeyError, ZeroDivisionError):
            requests_per_second = 0
    else:
        requests_per_second = 0
    
    return {
        "requests_count": requests_count,
        "unique_endpoints": unique_endpoints,
        "requests_per_second": requests_per_second
    }

def generate_api_key() -> str:
    token = secrets.token_bytes(32)
    key = hashlib.sha256(token).hexdigest()
    return key
