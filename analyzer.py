from utils import load_rules, load_config, color_print, COLOR_CYAN, COLOR_RED, COLOR_YELLOW, COLOR_RESET, get_hostname, extract_ip
from database import SessionLocal, Event
from correlation import correlation_engine
from datetime import datetime

def save_event(rule_name, severity, category, message, raw_log, log_source, remote_ip=None):
    db = SessionLocal()
    hostname = get_hostname()
    

    now = datetime.utcnow()

    last_event = db.query(Event).filter(
        Event.rule_name == rule_name,
        Event.remote_ip == remote_ip,
        Event.log_source == log_source
    ).order_by(Event.timestamp.desc()).first()
    
    if last_event and (datetime.utcnow() - last_event.timestamp).total_seconds() < 300:
        last_event.count += 1
        last_event.message = message 
        db.commit()
    else:
        new_event = Event(
            log_source=log_source,
            rule_name=rule_name,
            severity=severity,
            category=category,
            message=message,
            remote_ip=remote_ip,
            raw_log=raw_log,
            hostname=hostname,
            count=1
        )
        db.add(new_event)
        db.commit()
    
    db.close()
    

    try:
        import requests
        requests.post("http://localhost:8000/api/events/internal", json={
            "rule_name": rule_name,
            "severity": severity,
            "category": category,
            "message": message,
            "remote_ip": remote_ip,
            "timestamp": datetime.utcnow().isoformat()
        }, timeout=0.5)
    except:
        pass



    correlation_engine.process_event(rule_name, severity, category, message, raw_log, remote_ip)

def analyze_log(file_path):
    """Belirtilen log dosyasını statik olarak analiz eder ve özet üretir."""
    rules = load_rules()
    config = load_config()
    results = {name: 0 for name in rules}
    total_lines = 0
    match_count = 0
    
    color_print(f"\n[ANALIZ] {file_path} isleniyor...", COLOR_CYAN)
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                total_lines += 1
                line_lower = line.lower()
                for rule_name, rule_details in rules.items():
                    if rule_details['pattern'].lower() in line_lower:
                        results[rule_name] += 1
                        match_count += 1
                        

                        remote_ip = extract_ip(line)
                        save_event(
                            rule_name, 
                            rule_details['severity'], 
                            rule_details.get('category', 'n/a'),
                            rule_details.get('description', ''),
                            line.strip(),
                            file_path,
                            remote_ip
                        )
    except PermissionError:
        color_print(f"Hata: {file_path} okuma yetkisi yok.", COLOR_RED)
        return None
    except Exception as e:
        color_print(f"Bilinmeyen hata: {e}", COLOR_RED)
        return None

    print(f"Toplam okunan satır: {total_lines}")
    print("Analiz Sonuclari:")
    
    threshold = config.get('alert_threshold', 5)
    
    for rule, count in results.items():
        if count == 0: continue
        
        percent = (count / match_count * 100) if match_count > 0 else 0
        rule_info = rules.get(rule, {})
        if not rule_info: continue
        
        severity = rule_info['severity'].upper()
        category = rule_info.get('category', 'n/a').upper()
        description = rule_info.get('description', '')
        

        color = COLOR_RESET
        if severity == 'CRITICAL': color = COLOR_RED
        elif severity == 'HIGH': color = COLOR_RED
        elif severity == 'MEDIUM': color = COLOR_YELLOW
        
        display_text = f"- [{severity}] [{category}] {rule}: {count} ({percent:.1f}%)"
        color_print(display_text, color)
        color_print(f"  Açıklama: {description}", color)
        

        if count >= threshold:
            color_print(f"  [KRITIK DURUM] '{rule}' eslesmesi esik degeri ({threshold}) uzerinde!", COLOR_RED)
    
    return results
