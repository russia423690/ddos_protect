import os
import sys
from utils.local_storage import LocalStorage

def reset_blocked_ip(ip_address):
    storage = LocalStorage()
    block_key = f"block:{ip_address}"
    storage.delete(block_key)
    critical_counter_key = f"critical_anomalies:{ip_address}"
    storage.delete(critical_counter_key)
    rate_limit_key = f"ratelimit:{ip_address}"
    storage.delete(rate_limit_key)
    print(f"Блокировка IP-адреса {ip_address} сброшена")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python reset_blocks.py <ip_address>")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    reset_blocked_ip(ip_address)
