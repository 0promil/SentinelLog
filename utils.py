import json
import os
import socket
from database import SessionLocal, Rule, SystemMetadata

# CLI Renk Sabitleri 
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"
COLOR_CYAN = "\033[96m"

def load_config(file_path='config.json'):
    """Genel sistem konfigürasyonunu yükler."""
    if not os.path.exists(file_path):
        return {
            "log_files": ["/var/log/auth.log", "/var/log/syslog"],
            "reports_dir": "reports",
            "alert_threshold": 5
        }
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

class RuleManager:
    _instance = None
    _rules_cache = {}
    _version = "0"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RuleManager, cls).__new__(cls)
        return cls._instance

    def get_rules(self, force_reload=False):
        db = SessionLocal()
        try:
            # Check version
            meta = db.query(SystemMetadata).filter(SystemMetadata.key == "rules_version").first()
            current_version = meta.value if meta else "1"

            if force_reload or current_version != self._version or not self._rules_cache:
                print(f"{COLOR_CYAN}[SISTEM] Kurallar DB'den yukleniyor... (Versiyon: {current_version}){COLOR_RESET}")
                db_rules = db.query(Rule).filter(Rule.is_active == True).all()
                self._rules_cache = {
                    r.rule_key: {
                        "pattern": r.pattern,
                        "severity": r.severity,
                        "category": r.category,
                        "description": r.description
                    } for r in db_rules
                }
                self._version = current_version
        except Exception as e:
            print(f"{COLOR_RED}Kural yukleme hatası: {e}{COLOR_RESET}")
        finally:
            db.close()
        return self._rules_cache

def load_rules():
    """Geriye donuk uyumluluk icin kural yukleme fonksiyonu."""
    return RuleManager().get_rules()

def check_file_exists(file_path):
    """Dosyanın varlığını kontrol eder."""
    if not os.path.exists(file_path):
        print(f"{COLOR_YELLOW}Uyarı: '{file_path}' dosyası sistemde bulunamadı.{COLOR_RESET}")
        return False
    return True

def color_print(text, color):
    """Renkli terminal çıktısı verir."""
    print(f"{color}{text}{COLOR_RESET}")

def get_hostname():
    return socket.gethostname()

import re
def extract_ip(text):
    """Log satırından IP adresi ayıklar."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None

