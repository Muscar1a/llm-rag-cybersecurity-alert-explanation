import json
import time
import os
import logging
import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [suricata-watcher] %(levelname)s %(message)s",
)
log = logging.getLogger("suricata-watcher")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_PATH = os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
QUEUE = "suricata:alerts:raw"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def wait_for_file(path: str, poll: float = 1.0):
    log.info(f"Waiting for {path}...")
    while not os.path.exists(path):
        time.sleep(poll)
    log.info(f"Found {path}, starting tail.")


def tail(path: str, poll: float = 0.3):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                try:
                    if f.tell() > os.fstat(f.fileno()).st_size:
                        log.warning("Log rotation detected, seeking to start.")
                        f.seek(0)
                except OSError:
                    pass
                time.sleep(poll)
                continue

            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            r.rpush(QUEUE, json.dumps(event))
            sig = event.get("alert", {}).get("signature", "?")
            log.info(f"Alert: {event.get('dest_ip')}:{event.get('dest_port')} | {sig}")


if __name__ == "__main__":
    wait_for_file(LOG_PATH)
    tail(LOG_PATH)
