import time
import uuid
import hmac
import base64
import hashlib
from datetime import datetime, timedelta

from config import COOKIE_SECRET, COOKIE_MAX_AGE

def debug_cookie_values():
    """Проверяет правильность создания и проверки куки безопасности"""
    print("=== Отладка механизма куки безопасности ===")
    
    # Тестовые данные
    client_ip = "172.31.128.77"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Генерация токена
    token = generate_test_token(client_ip, user_agent)
    print(f"Сгенерированный токен: {token}")
    
    # Проверка токена
    is_valid = verify_test_token(token, client_ip, user_agent)
    print(f"Результат проверки токена: {is_valid}")
    
    # Проверка с другим IP
    is_valid_wrong_ip = verify_test_token(token, "1.2.3.4", user_agent)
    print(f"Проверка с неверным IP: {is_valid_wrong_ip} (должно быть False)")
    
    # Проверка с другим User-Agent
    is_valid_wrong_ua = verify_test_token(token, client_ip, "Different User Agent")
    print(f"Проверка с неверным User-Agent: {is_valid_wrong_ua} (должно быть False)")

def generate_test_token(client_ip: str, user_agent: str = "") -> str:
    """Тестовая функция для генерации токена безопасности"""
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

def verify_test_token(token: str, client_ip: str, user_agent: str = "") -> bool:
    """Тестовая функция для проверки токена безопасности"""
    try:
        data_b64, sig_b64 = token.split(".")
        
        data = base64.urlsafe_b64decode(data_b64).decode('utf-8')
        signature = base64.urlsafe_b64decode(sig_b64)
        
        parts = data.split("|")
        if len(parts) != 3:
            print(f"Неверное количество частей в данных: {len(parts)}")
            return False
        
        token_ip, token_ua, expires_ts = parts
        
        if int(expires_ts) < int(time.time()):
            print(f"Токен истек: {expires_ts} < {int(time.time())}")
            return False
        
        if token_ip != client_ip:
            print(f"Несоответствие IP: {token_ip} != {client_ip}")
            return False
        
        expected_signature = hmac.new(
            COOKIE_SECRET.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        is_valid = hmac.compare_digest(signature, expected_signature)
        if not is_valid:
            print("Неверная подпись")
        return is_valid
        
    except Exception as e:
        print(f"Ошибка при проверке токена: {str(e)}")
        return False

if __name__ == "__main__":
    debug_cookie_values()