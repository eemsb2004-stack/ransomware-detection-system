import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Define the path of the decoy file (Honeyfile) using relative path
HONEYFILE_PATH = os.path.join("monitoring", "Password_hf.txt")

class HoneyfileHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        # Print every event happening in the folder for debugging
        print(f"[*] Event detected -> Type: {event.event_type} | Path: {event.src_path}")

    def on_modified(self, event):
        # Check if the event occurred exclusively on the honeyfile
        if os.path.abspath(event.src_path) == os.path.abspath(HONEYFILE_PATH):
            print("\n[!] Critical Security Alert: Unauthorized modification or encryption detected on the honeyfile!")
            print(f"[*] Target Path: {event.src_path}")

if __name__ == "__main__":
    if not os.path.exists(HONEYFILE_PATH):
        print(f"[!] Warning: The file {HONEYFILE_PATH} does not exist. Please create it first.")
    else:
        event_handler = HoneyfileHandler()
        observer = Observer()
        
        # Monitor the current monitoring directory
        observer.schedule(event_handler, path="monitoring", recursive=False)
        observer.start()
        
        print(f"[*] Honeyfile monitoring system is now running... Monitoring: {HONEYFILE_PATH}")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\n[*] Monitoring system stopped manually.")
            
        observer.join()