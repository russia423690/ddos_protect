import time
import threading
import json
import logging
import sqlite3
from typing import Dict, Any, Optional, List, Union
import os

logger = logging.getLogger(__name__)

os.makedirs("data", exist_ok=True)

class LocalStorage:
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LocalStorage, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        self.db_path = "data/local_storage.db"
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_keys, daemon=True)
        self._cleanup_thread.start()
        logger.info("LocalStorage initialized")
    
    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS key_value (
            key TEXT PRIMARY KEY,
            value TEXT,
            expiry INTEGER
        )
        ''')
        self.conn.commit()
    
    def _cleanup_expired_keys(self):
        while True:
            try:
                current_time = int(time.time())
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM key_value WHERE expiry > 0 AND expiry < ?", (current_time,))
                self.conn.commit()
            except Exception as e:
                logger.error(f"Error cleaning up expired keys: {str(e)}")
            time.sleep(10)
    
    def get(self, key: str) -> Optional[str]:
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "SELECT value, expiry FROM key_value WHERE key = ?", 
                    (key,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                if row['expiry'] > 0 and row['expiry'] < int(time.time()):
                    self.delete(key)
                    return None
                
                return row['value']
        except Exception as e:
            logger.error(f"Error getting key {key}: {str(e)}")
            return None
    
    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        try:
            with self._lock:
                expiry = 0
                if ex:
                    expiry = int(time.time()) + ex
                
                cursor = self.conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO key_value (key, value, expiry) VALUES (?, ?, ?)",
                    (key, value, expiry)
                )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error setting key {key}: {str(e)}")
            return False
    
    def setex(self, key: str, seconds: int, value: str) -> bool:
        return self.set(key, value, ex=seconds)
    
    def delete(self, key: str) -> bool:
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM key_value WHERE key = ?", (key,))
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error deleting key {key}: {str(e)}")
            return False
    
    def incr(self, key: str) -> int:
        try:
            with self._lock:
                value = self.get(key)
                if value is None:
                    new_value = 1
                else:
                    try:
                        new_value = int(value) + 1
                    except ValueError:
                        new_value = 1
                
                self.set(key, str(new_value))
                return new_value
        except Exception as e:
            logger.error(f"Error incrementing key {key}: {str(e)}")
            return 0
    
    def expire(self, key: str, seconds: int) -> bool:
        try:
            with self._lock:
                value = self.get(key)
                if value is None:
                    return False
                
                expiry = int(time.time()) + seconds
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE key_value SET expiry = ? WHERE key = ?",
                    (expiry, key)
                )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error setting expiry for key {key}: {str(e)}")
            return False
    
    def ttl(self, key: str) -> int:
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT expiry FROM key_value WHERE key = ?", (key,))
                row = cursor.fetchone()
                
                if not row:
                    return -2
                
                expiry = row['expiry']
                if expiry == 0:
                    return -1
                
                remaining = expiry - int(time.time())
                return max(0, remaining)
        except Exception as e:
            logger.error(f"Error getting TTL for key {key}: {str(e)}")
            return -2
    
    def lpush(self, key: str, value: str) -> int:
        try:
            with self._lock:
                current_list = self._get_list(key)
                current_list.insert(0, value)
                self._save_list(key, current_list)
                return len(current_list)
        except Exception as e:
            logger.error(f"Error pushing to list {key}: {str(e)}")
            return 0
    
    def lrange(self, key: str, start: int, stop: int) -> List[str]:
        try:
            with self._lock:
                current_list = self._get_list(key)
                
                if stop < 0:
                    stop = len(current_list) + stop + 1
                
                return current_list[start:stop]
        except Exception as e:
            logger.error(f"Error getting range from list {key}: {str(e)}")
            return []
    
    def ltrim(self, key: str, start: int, stop: int) -> bool:
        try:
            with self._lock:
                current_list = self._get_list(key)
                
                if stop < 0:
                    stop = len(current_list) + stop + 1
                
                trimmed_list = current_list[start:stop]
                self._save_list(key, trimmed_list)
                return True
        except Exception as e:
            logger.error(f"Error trimming list {key}: {str(e)}")
            return False
    
    def llen(self, key: str) -> int:
        try:
            with self._lock:
                return len(self._get_list(key))
        except Exception as e:
            logger.error(f"Error getting length of list {key}: {str(e)}")
            return 0
    
    def _get_list(self, key: str) -> List[str]:
        value = self.get(key)
        if value is None:
            return []
        
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return [value]
    
    def _save_list(self, key: str, value_list: List[str]):
        self.set(key, json.dumps(value_list))
    
    def ping(self) -> bool:
        return True

local_storage = LocalStorage()