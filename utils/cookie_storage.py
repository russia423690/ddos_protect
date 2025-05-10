import os
import sqlite3
import threading
import time
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timedelta

from config import ensure_data_directories

DB_PATH = os.path.join("data", "security_cookies.db")

class CookieStorage:
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(CookieStorage, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        """Инициализация хранилища при первом создании"""
        ensure_data_directories()
        
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        self._create_tables()
        
        cleanup_thread = threading.Thread(target=self._cleanup_expired_tokens, daemon=True)
        cleanup_thread.start()
    
    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_token ON security_tokens(token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON security_tokens(client_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_expires_at ON security_tokens(expires_at)')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT NOT NULL,
            block_count INTEGER DEFAULT 1,
            created_at INTEGER NOT NULL,
            expires_at INTEGER
        )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_blocks(ip_address)')
        self.conn.commit()
    
    def _cleanup_expired_tokens(self):
        while True:
            try:
                cursor = self.conn.cursor()
                now = int(time.time())
                
                cursor.execute('DELETE FROM security_tokens WHERE expires_at < ?', (now,))
                
                cursor.execute('DELETE FROM ip_blocks WHERE expires_at IS NOT NULL AND expires_at < ?', (now,))
                
                self.conn.commit()
                
                time.sleep(600)
            except Exception as e:
                print(f"Ошибка при очистке просроченных токенов: {e}")
                time.sleep(60)
    
    def store_token(self, client_ip: str, user_agent: str, token: str, expires_in: int = 86400) -> bool:
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            expires_at = now + expires_in
            
            cursor.execute('DELETE FROM security_tokens WHERE client_ip = ?', (client_ip,))
            
            cursor.execute(
                'INSERT INTO security_tokens (client_ip, user_agent, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                (client_ip, user_agent, token, now, expires_at)
            )
            
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при сохранении токена: {e}")
            return False
    
    def verify_token(self, token: str, client_ip: str, user_agent: str) -> bool:
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            cursor.execute(
                'SELECT * FROM security_tokens WHERE token = ? AND client_ip = ? AND expires_at > ?',
                (token, client_ip, now)
            )
            
            result = cursor.fetchone()
            return result is not None
        except Exception as e:
            print(f"Ошибка при проверке токена: {e}")
            return False
    
    def delete_token(self, client_ip: str) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM security_tokens WHERE client_ip = ?', (client_ip,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при удалении токена: {e}")
            return False
    
    def block_ip(self, ip_address: str, reason: str, duration: Optional[int] = None) -> bool:
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            expires_at = now + duration if duration else None
            
            cursor.execute('SELECT * FROM ip_blocks WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute(
                    'UPDATE ip_blocks SET reason = ?, block_count = block_count + 1, created_at = ?, expires_at = ? WHERE ip_address = ?',
                    (reason, now, expires_at, ip_address)
                )
            else:
                cursor.execute(
                    'INSERT INTO ip_blocks (ip_address, reason, created_at, expires_at) VALUES (?, ?, ?, ?)',
                    (ip_address, reason, now, expires_at)
                )
            
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при блокировке IP: {e}")
            return False
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            cursor.execute(
                'SELECT * FROM ip_blocks WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)',
                (ip_address, now)
            )
            
            result = cursor.fetchone()
            return result is not None
        except Exception as e:
            print(f"Ошибка при проверке блокировки IP: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM ip_blocks WHERE ip_address = ?', (ip_address,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при разблокировке IP: {e}")
            return False
    
    def get_block_reason(self, ip_address: str) -> Optional[str]:

        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            cursor.execute(
                'SELECT reason FROM ip_blocks WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)',
                (ip_address, now)
            )
            
            result = cursor.fetchone()
            return result['reason'] if result else None
        except Exception as e:
            print(f"Ошибка при получении причины блокировки IP: {e}")
            return None
    
    def get_all_tokens(self) -> List[Dict[str, Any]]:

        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            cursor.execute('SELECT * FROM security_tokens WHERE expires_at > ?', (now,))
            
            result = []
            for row in cursor.fetchall():
                result.append(dict(row))
            
            return result
        except Exception as e:
            print(f"Ошибка при получении списка токенов: {e}")
            return []
    
    def get_all_blocks(self) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            cursor.execute('SELECT * FROM ip_blocks WHERE expires_at IS NULL OR expires_at > ?', (now,))
            
            result = []
            for row in cursor.fetchall():
                result.append(dict(row))
            
            return result
        except Exception as e:
            print(f"Ошибка при получении списка блокировок: {e}")
            return []

cookie_storage = CookieStorage()
