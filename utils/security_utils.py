import logging
import hmac
import base64
import hashlib
import time
from datetime import datetime, timedelta
from config import COOKIE_SECRET, COOKIE_MAX_AGE

logger = logging.getLogger(__name__)

def generate_secure_token(client_ip: str, user_agent: str = "") -> str:
    now = datetime.utcnow()
    expires = now + timedelta(seconds=COOKIE_MAX_AGE)
    expires_ts = int(expires.timestamp())
    
    base_str = f"{client_ip}|{user_agent}|{expires_ts}"
    
    signature = hmac.new(
        COOKIE_SECRET.encode('utf-8'),
        base_str.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    data_b64 = base64.urlsafe_b64encode(base_str.encode('utf-8')).decode('utf-8')
    sig_b64 = base64.urlsafe_b64encode(signature).decode('utf-8')
    
    return f"{data_b64}.{sig_b64}"

def verify_secure_token(token: str, client_ip: str, user_agent: str = "") -> bool:
    try:
        data_b64, sig_b64 = token.split(".")
        
        data = base64.urlsafe_b64decode(data_b64).decode('utf-8')
        signature = base64.urlsafe_b64decode(sig_b64)
        
        parts = data.split("|")
        if len(parts) != 3:
            return False
        
        token_ip, token_ua, expires_ts = parts
        
        if int(expires_ts) < int(time.time()):
            logger.debug(f"Token expired for IP {client_ip}, expires_ts: {expires_ts}, now: {int(time.time())}")
            return False
        
        if token_ip != client_ip:
            logger.debug(f"IP mismatch: token IP {token_ip}, client IP {client_ip}")
            return False
        
        expected_signature = hmac.new(
            COOKIE_SECRET.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        is_valid = hmac.compare_digest(signature, expected_signature)
        if not is_valid:
            logger.debug(f"Invalid signature for IP {client_ip}")
        return is_valid
        
    except Exception as e:
        logger.error(f"Error verifying security token: {str(e)}")
        return False