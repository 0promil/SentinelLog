import time
import os
from utils import load_rules, color_print, COLOR_RED, COLOR_YELLOW, COLOR_CYAN, extract_ip
from analyzer import save_event

def start_tail(file_path):


    rules = load_rules()
    print(f"\n[CANLI] {file_path} izleniyor...", flush=True)
    
    last_rule_check = time.time()
    
    while True:
        try:
            if not os.path.exists(file_path):
                print(f"[HATA] Dosya bulunamadi (tekrar deneniyor): {file_path}", flush=True)
                time.sleep(5)
                continue

            with open(file_path, 'r', errors='ignore') as f:
                f.seek(0, os.SEEK_END)
                while True:

                    now = time.time()
                    if now - last_rule_check > 10:
                        rules = load_rules()
                        last_rule_check = now

                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        if not os.path.exists(file_path): break
                        continue
                    
                    line_lower = line.strip().lower()
                    if not line_lower: continue

                    for rule_name, rule_details in rules.items():
                        if rule_details['pattern'].lower() in line_lower:
                            severity = rule_details['severity'].upper()
                            description = rule_details.get('description', '')
                            
                            print(f"[TESPIT] {rule_name} -> {line_lower[:50]}...", flush=True)


                            remote_ip = extract_ip(line)
                            save_event(
                                rule_name,
                                severity,
                                rule_details.get('category', 'n/a'),
                                description,
                                line.strip(),
                                file_path,
                                remote_ip
                            )
                            
        except Exception as e:
            print(f"[HATA] {file_path} izlenirken hata: {e}", flush=True)
            time.sleep(5)

