import os
import redis
import logging
from typing import Optional, Any, Dict, List, Union

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

class RedisClient:

    
    def __init__(self):
        self.redis = None
        self.connected = False
        
        try:
            self.redis = redis.from_url(REDIS_URL)
            self.redis.ping()
            self.connected = True
            logger.info("Successfully connected to Redis")
        except redis.ConnectionError as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self.connected = False
    
    def is_connected(self) -> bool:
        """Check if Redis is connected"""
        if not self.connected or not self.redis:
            return False
            
        try:
            self.redis.ping()
            return True
        except redis.ConnectionError:
            self.connected = False
            return False
    
    def set(self, key: str, value: Any, expiry: Optional[int] = None) -> bool:
        """Set a key with optional expiry (in seconds)"""
        if not self.is_connected():
            return False
            
        try:
            if expiry:
                return self.redis.setex(key, expiry, value)
            else:
                return self.redis.set(key, value)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    def get(self, key: str) -> Optional[str]:
        """Get a value from Redis"""
        if not self.is_connected():
            return None
            
        try:
            return self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    def increment(self, key: str, amount: int = 1, expiry: Optional[int] = None) -> Optional[int]:
        if not self.is_connected():
            return None
            
        try:
            result = self.redis.incr(key, amount)
            
            if result == amount and expiry:
                self.redis.expire(key, expiry)
                
            return result
        except Exception as e:
            logger.error(f"Redis increment error: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete a key from Redis"""
        if not self.is_connected():
            return False
            
        try:
            return bool(self.redis.delete(key))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists in Redis"""
        if not self.is_connected():
            return False
            
        try:
            return bool(self.redis.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False
    
    def set_rate_limit(self, key_prefix: str, identifier: str, limit: int, window: int) -> Dict[str, int]:
        if not self.is_connected():
            return {"count": 0, "limit": limit, "remaining": limit, "reset": window}
            
        key = f"{key_prefix}:{identifier}"
        
        try:
            count = self.redis.get(key)
            
            if count is None:
                self.redis.setex(key, window, 1)
                count = 1
            else:
                count = int(count)
                self.redis.incr(key)
                count += 1
            
            ttl = self.redis.ttl(key)
            reset = max(0, ttl)
            
            return {
                "count": count,
                "limit": limit,
                "remaining": max(0, limit - count),
                "reset": reset
            }
        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            return {"count": 0, "limit": limit, "remaining": limit, "reset": window}
    
    def add_to_ip_blacklist(self, ip_address: str, reason: str, duration: int) -> bool:
        if not self.is_connected():
            return False
            
        try:
            key = f"blacklist:{ip_address}"
            return self.redis.setex(key, duration, reason)
        except Exception as e:
            logger.error(f"Redis blacklist error: {e}")
            return False
    
    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Check if an IP is blacklisted"""
        if not self.is_connected():
            return False
            
        try:
            key = f"blacklist:{ip_address}"
            return bool(self.redis.exists(key))
        except Exception as e:
            logger.error(f"Redis blacklist check error: {e}")
            return False
    
    def get_blacklist_reason(self, ip_address: str) -> Optional[str]:
        """Get the reason an IP was blacklisted"""
        if not self.is_connected():
            return None
            
        try:
            key = f"blacklist:{ip_address}"
            return self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis blacklist reason error: {e}")
            return None

redis_client = RedisClient()
