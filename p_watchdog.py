import time
import json
import logging
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil  

# Security logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOG_FILE = "detailed_event_log.json"
HONEYFILE_NAME = "Password_hf.txt"

# === Kill Switch Function ===
def kill_suspicious_process():
    logging.warning("[!] ALERT: Ransomware behavior or critical asset tampering detected! Triggering Kill Switch...")
    current_pid = psutil.Process().pid
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['pid'] != current_pid and "python" in proc.info['name'].lower():
                proc.kill()
                logging.info(f"[✓] Successfully terminated suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def log_detailed_event(event_type, src_path, file_size=None, dest_path=None):
    """Log extended event details for security analysis"""
    event_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "source_path": src_path,
        "destination_path": dest_path,
        "file_size_bytes": file_size,
        "file_extension": os.path.splitext(src_path)[1] if src_path else None
    }
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event_data) + "\n")
    except Exception as e:
        logging.error(f"Failed to write log: {e}")

class DetailedRansomwareEventCollector(FileSystemEventHandler):
    
    def check_critical_assets(self, path):
        """Check if the modified/accessed file is the honeyfile or a .pkl model"""
        if path and (HONEYFILE_NAME in path or ".pkl" in path):
            logging.critical(f"[!!!] CRITICAL SECURITY BREACH: Tampering detected on protected asset -> {path}")
            kill_suspicious_process()

    def on_modified(self, event):
        if not event.is_directory:
            self.check_critical_assets(event.src_path)
            file_size = None
            try:
                if os.path.exists(event.src_path):
                    file_size = os.path.getsize(event.src_path)
            except Exception:
                pass
            
            logging.warning(f"[Modified] File: {event.src_path} | Current Size: {file_size} bytes")
            log_detailed_event("MODIFIED", event.src_path, file_size=file_size)

    def on_created(self, event):
        if not event.is_directory:
            self.check_critical_assets(event.src_path)
            file_size = None
            try:
                if os.path.exists(event.src_path):
                    file_size = os.path.getsize(event.src_path)
            except Exception:
                pass
            
            logging.warning(f"[Created] New file: {event.src_path} | Size: {file_size} bytes")
            log_detailed_event("CREATED", event.src_path, file_size=file_size)

    def on_deleted(self, event):
        if not event.is_directory:
            self.check_critical_assets(event.src_path)
            logging.warning(f"[Deleted] File removed (potential encryption or deletion): {event.src_path}")
            log_detailed_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.check_critical_assets(event.src_path)
            logging.warning(f"[Moved/Renamed] From {event.src_path} to {event.dest_path}")
            log_detailed_event("MOVED", event.src_path, dest_path=event.dest_path)

if __name__ == "__main__":
    path_to_watch = "monitoring"
    
    event_handler = DetailedRansomwareEventCollector()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    
    logging.info(f"Starting detailed monitoring on path: {path_to_watch}")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping monitoring system.")
    
    observer.join()