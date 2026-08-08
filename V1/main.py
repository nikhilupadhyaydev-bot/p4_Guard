import sqlite3
import time
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_PATH = "guard.db"
WATCH_DIR = "/path/to/monitor"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

class GuardHandler(FileSystemEventHandler):
    def __init__(self, conn):
        self.conn = conn

    def _log(self, event_type, path):
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO changes (path, event_type, timestamp) VALUES (?, ?, ?)",
            (path, event_type, ts)
        )
        self.conn.commit()
        print(f"[{ts}] {event_type}: {path}")

    def on_created(self, event):
        self._log("created", event.src_path)

    def on_modified(self, event):
        self._log("modified", event.src_path)

    def on_deleted(self, event):
        self._log("deleted", event.src_path)

    def on_moved(self, event):
        self._log(f"moved -> {event.dest_path}", event.src_path)

def main():
    conn = init_db()
    handler = GuardHandler(conn)
    observer = Observer()
    observer.schedule(handler, WATCH_DIR, recursive=True)
    observer.start()
    print(f"Guard watching: {WATCH_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    conn.close()

if __name__ == "__main__":
    main()