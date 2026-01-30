import threading
import time
import os
from tailer import start_tail
from utils import load_config, color_print, COLOR_CYAN

def run_daemon():
    config = load_config()
    log_files = config.get('log_files', [])
    
    threads = []
    
    color_print("--- Log Sentinel Daemon Baslatiliyor ---", COLOR_CYAN)
    
    for log_file in log_files:
        if os.path.exists(log_file):
            t = threading.Thread(target=start_tail, args=(log_file,), daemon=True)
            t.start()
            threads.append(t)
            print(f"Started monitoring: {log_file}")
        else:
            print(f"Log file not found (skipping): {log_file}")
            
    if not threads:
        print("No log files found to monitor!")
        
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping daemon...")

if __name__ == "__main__":
    run_daemon()
