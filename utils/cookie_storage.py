import os
import sqlite3
import threading
import time
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timedelta

from config import ensure_data_directories

# Путь к файлу базы данных
DB_PATH = os.path.join("data", "security_cookies.db")

class CookieStorage:
    """
    Хранилище для токенов безопасности, основанное на SQLite
    """
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
        # Убедимся, что директория существует
        ensure_data_directories()
        
        # Создаем соединение с базой данных
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        # Создаем таблицы, если их нет
        self._create_tables()
        
        # Регулярная очистка просроченных токенов
        cleanup_thread = threading.Thread(target=self._cleanup_expired_tokens, daemon=True)
        cleanup_thread.start()
    
    def _create_tables(self):
        """Создаем таблицы в базе данных, если их нет"""
        cursor = self.conn.cursor()
        
        # Таблица для токенов безопасности
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
        
        # Создаем индексы для быстрого поиска
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_token ON security_tokens(token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON security_tokens(client_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_expires_at ON security_tokens(expires_at)')
        
        # Таблица для учета заблокированных IP
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
        
        # Индекс для быстрого поиска заблокированных IP
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_blocks(ip_address)')
        
        self.conn.commit()
    
    def _cleanup_expired_tokens(self):
        """Периодически удаляет просроченные токены"""
        while True:
            try:
                cursor = self.conn.cursor()
                now = int(time.time())
                
                # Удаляем просроченные токены
                cursor.execute('DELETE FROM security_tokens WHERE expires_at < ?', (now,))
                
                # Удаляем просроченные блокировки IP
                cursor.execute('DELETE FROM ip_blocks WHERE expires_at IS NOT NULL AND expires_at < ?', (now,))
                
                self.conn.commit()
                
                # Проверяем каждые 10 минут
                time.sleep(600)
            except Exception as e:
                print(f"Ошибка при очистке просроченных токенов: {e}")
                time.sleep(60)
    
    def store_token(self, client_ip: str, user_agent: str, token: str, expires_in: int = 86400) -> bool:
        """
        Сохраняет токен безопасности в базе данных
        
        Args:
            client_ip: IP-адрес клиента
            user_agent: User-Agent клиента
            token: Токен безопасности
            expires_in: Время жизни токена в секундах (по умолчанию 24 часа)
            
        Returns:
            bool: True, если токен успешно сохранен
        """
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            expires_at = now + expires_in
            
            # Удаляем предыдущие токены для этого IP, если они есть
            cursor.execute('DELETE FROM security_tokens WHERE client_ip = ?', (client_ip,))
            
            # Вставляем новый токен
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
        """
        Проверяет валидность токена безопасности
        
        Args:
            token: Токен безопасности
            client_ip: IP-адрес клиента
            user_agent: User-Agent клиента
            
        Returns:
            bool: True, если токен валидный
        """
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            # Ищем токен в базе
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
        """
        Удаляет все токены для указанного IP-адреса
        
        Args:
            client_ip: IP-адрес клиента
            
        Returns:
            bool: True, если токены удалены
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM security_tokens WHERE client_ip = ?', (client_ip,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при удалении токена: {e}")
            return False
    
    def block_ip(self, ip_address: str, reason: str, duration: Optional[int] = None) -> bool:
        """
        Добавляет IP-адрес в список заблокированных
        
        Args:
            ip_address: IP-адрес для блокировки
            reason: Причина блокировки
            duration: Длительность блокировки в секундах (None - навсегда)
            
        Returns:
            bool: True, если IP успешно заблокирован
        """
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            expires_at = now + duration if duration else None
            
            # Проверяем, есть ли уже такой IP в списке
            cursor.execute('SELECT * FROM ip_blocks WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Обновляем существующую запись
                cursor.execute(
                    'UPDATE ip_blocks SET reason = ?, block_count = block_count + 1, created_at = ?, expires_at = ? WHERE ip_address = ?',
                    (reason, now, expires_at, ip_address)
                )
            else:
                # Добавляем новую запись
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
        """
        Проверяет, заблокирован ли IP-адрес
        
        Args:
            ip_address: IP-адрес для проверки
            
        Returns:
            bool: True, если IP заблокирован
        """
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            # Ищем IP в списке заблокированных
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
        """
        Удаляет IP-адрес из списка заблокированных
        
        Args:
            ip_address: IP-адрес для разблокировки
            
        Returns:
            bool: True, если IP успешно разблокирован
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM ip_blocks WHERE ip_address = ?', (ip_address,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка при разблокировке IP: {e}")
            return False
    
    def get_block_reason(self, ip_address: str) -> Optional[str]:
        """
        Возвращает причину блокировки IP-адреса
        
        Args:
            ip_address: IP-адрес для проверки
            
        Returns:
            str: Причина блокировки или None, если IP не заблокирован
        """
        try:
            cursor = self.conn.cursor()
            now = int(time.time())
            
            # Ищем IP в списке заблокированных
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
        """
        Возвращает список всех активных токенов
        
        Returns:
            List[Dict]: Список словарей с информацией о токенах
        """
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
        """
        Возвращает список всех активных блокировок IP
        
        Returns:
            List[Dict]: Список словарей с информацией о блокировках
        """
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

# Создаем глобальный экземпляр хранилища
cookie_storage = CookieStorage()