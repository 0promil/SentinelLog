import time
from datetime import datetime, timedelta
from database import SessionLocal, Event
from utils import get_hostname

class CorrelationManager:
    def __init__(self):
        self.ip_states = {} 
        self.brute_force_threshold = 5
        self.brute_force_window = 60 
        self.hostname = get_hostname()

    def process_event(self, rule_name, severity, category, message, raw_log, remote_ip=None):
        if not remote_ip:
            return None 
        db = SessionLocal()
        now = time.time()
        
        if remote_ip not in self.ip_states:
            self.ip_states[remote_ip] = []
        
        self.ip_states[remote_ip].append((now, rule_name))
        
        self.ip_states[remote_ip] = [
            (ts, r) for ts, r in self.ip_states[remote_ip] 
            if now - ts < self.brute_force_window
        ]
        alerts = []
        failed_count = sum(1 for ts, r in self.ip_states[remote_ip] if r == 'failed_password')
        if failed_count >= self.brute_force_threshold:
            if (now, 'BRUTE_FORCE') not in self.ip_states[remote_ip]:
                alerts.append({
                    "rule_name": "brute_force_detected",
                    "severity": "CRITICAL",
                    "category": "attack",
                    "message": f"Brute Force Detected from {remote_ip}: {failed_count} failed attempts."
                })
                self.ip_states[remote_ip].append((now, 'BRUTE_FORCE'))
        if len(self.ip_states[remote_ip]) >= 2:
            last_two = [r for ts, r in self.ip_states[remote_ip][-2:]]
            if last_two == ['failed_password', 'ssh_root_login']:
                alerts.append({
                    "rule_name": "suspicious_root_access",
                    "severity": "CRITICAL",
                    "category": "privilege",
                    "message": f"CRITICAL: Failed login follow by root success from {remote_ip}!"
                })
        block_count = sum(1 for ts, r in self.ip_states[remote_ip] if r == 'ufw_block')
        if block_count >= 10:
             if (now, 'SCANNING') not in self.ip_states[remote_ip]:
                alerts.append({
                    "rule_name": "network_scanning",
                    "severity": "HIGH",
                    "category": "recon",
                    "message": f"Network scanning detected from {remote_ip}: {block_count} blocks."
                })
                self.ip_states[remote_ip].append((now, 'SCANNING'))

        for alert in alerts:
            new_event = Event(
                log_source="CorrelationEngine",
                rule_name=alert['rule_name'],
                severity=alert['severity'],
                category=alert['category'],
                message=alert['message'],
                remote_ip=remote_ip,
                raw_log=raw_log,
                hostname=self.hostname,
                count=1
            )
            db.add(new_event)
        
        db.commit()
        db.close()
        return alerts

correlation_engine = CorrelationManager()
