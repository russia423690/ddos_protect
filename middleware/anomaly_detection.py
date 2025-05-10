import logging
from typing import Dict, Any, List, Optional
from fastapi import Request
import time
import statistics

from middleware.rate_limiter import WHITELIST_IPS

logger = logging.getLogger(__name__)

THRESHOLD_REQUEST_RATE = 25
THRESHOLD_UNIQUE_ENDPOINTS_RATIO = 0.2
THRESHOLD_BURST_RATE = 40
THRESHOLD_SEQUENTIAL_ERRORS = 10

client_state = {}

def detect_anomalies(request: Request, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies = []
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    if client_ip in WHITELIST_IPS:
        return []
    
    if request.url.path.startswith("/api/stats") or request.url.path.startswith("/health"):
        return []
    
    if client_ip not in client_state:
        client_state[client_ip] = {
            "last_request_time": time.time(),
            "sequential_errors": 0,
            "burst_counter": 0,
            "burst_start_time": time.time(),
            "request_history": []
        }
    
    state = client_state[client_ip]
    
    current_time = time.time()
    time_since_last_request = current_time - state["last_request_time"]
    state["last_request_time"] = current_time
    
    state["request_history"].append({
        "time": current_time,
        "path": request.url.path,
        "method": request.method
    })
    if len(state["request_history"]) > 20:
        state["request_history"] = state["request_history"][-20:]
    
    if "requests_per_second" in stats and stats["requests_per_second"] > THRESHOLD_REQUEST_RATE:
        anomalies.append({
            "type": "high_request_rate",
            "detail": f"Request rate of {stats['requests_per_second']:.2f} req/sec exceeds threshold of {THRESHOLD_REQUEST_RATE} req/sec",
            "severity": "high" if stats["requests_per_second"] > THRESHOLD_REQUEST_RATE * 2 else "medium"
        })
    
    if "unique_endpoints" in stats and "requests_count" in stats and stats["requests_count"] > 10:
        unique_ratio = stats["unique_endpoints"] / stats["requests_count"]
        if unique_ratio < THRESHOLD_UNIQUE_ENDPOINTS_RATIO:
            anomalies.append({
                "type": "endpoint_hammering",
                "detail": f"Client is repeatedly hitting {stats['unique_endpoints']} endpoints over {stats['requests_count']} requests",
                "severity": "medium"
            })
    
    if time_since_last_request < 0.1:
        state["burst_counter"] += 1
        
        if state["burst_counter"] == 1:
            state["burst_start_time"] = current_time
        
        if state["burst_counter"] >= THRESHOLD_BURST_RATE:
            burst_duration = current_time - state["burst_start_time"]
            burst_rate = state["burst_counter"] / max(burst_duration, 0.001)
            
            anomalies.append({
                "type": "request_burst",
                "detail": f"Burst of {state['burst_counter']} requests in {burst_duration:.2f} seconds ({burst_rate:.2f} req/sec)",
                "severity": "critical" if burst_rate > THRESHOLD_BURST_RATE * 2 else "high"
            })
            
            state["burst_counter"] = 0
    else:
        state["burst_counter"] = 0
    
    if len(state["request_history"]) >= 5:
        paths = [req["path"] for req in state["request_history"]]
        methods = [req["method"] for req in state["request_history"]]
        
        if is_sequential_pattern(paths):
            anomalies.append({
                "type": "sequential_access",
                "detail": "Sequential access pattern detected, possible scanning activity",
                "severity": "medium"
            })
        
        if has_method_variation(paths, methods):
            anomalies.append({
                "type": "method_variation",
                "detail": "Multiple HTTP methods used on same endpoints, possible API testing",
                "severity": "medium"
            })
    
    if anomalies:
        logger.warning(f"Anomalies detected for IP {client_ip}: {[a['type'] for a in anomalies]}")
    
    return anomalies

def is_sequential_pattern(paths: List[str]) -> bool:
    numeric_sequences = []
    
    for path in paths:
        components = path.split('/')
        for component in components:
            if component.isdigit():
                numeric_sequences.append(int(component))
    
    if len(numeric_sequences) >= 3:
        differences = [numeric_sequences[i+1] - numeric_sequences[i] 
                      for i in range(len(numeric_sequences)-1)]
        
        if len(set(differences)) == 1:
            return True
        
        if all(differences[i] == 1 for i in range(len(differences))):
            return True
    
    return False

def has_method_variation(paths: List[str], methods: List[str]) -> bool:
    path_methods = {}
    
    for i in range(len(paths)):
        path = paths[i]
        method = methods[i]
        
        if path not in path_methods:
            path_methods[path] = set()
        
        path_methods[path].add(method)
    
    for path, methods_used in path_methods.items():
        if len(methods_used) >= 3:
            return True
    
    return False
