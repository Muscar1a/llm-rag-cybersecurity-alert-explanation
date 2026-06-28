import json
import time
import os
import logging
import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [zeek-watcher] %(levelname)s %(message)s",
)
log = logging.getLogger("zeek-watcher")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_PATH = os.getenv("ZEEK_CONN_LOG", "/opt/zeek/logs/current/conn.log")
FLOW_TTL = int(os.getenv("FLOW_TTL", 300))
TAIL_FROM_START = os.getenv("TAIL_FROM_START", "0") == "1"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def flow_key(row: dict) -> str:
    proto = str(row.get("proto", "tcp")).lower()
    src = row.get("id.orig_h", "")
    sp = row.get("id.orig_p", 0)
    dst = row.get("id.resp_h", "")
    dp = row.get("id.resp_p", 0)
    return f"zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}"


def wait_for_file(path: str, poll: float = 1.0):
    log.info(f"Waiting for {path}...")
    while not os.path.exists(path):
        time.sleep(poll)
    log.info(f"Found {path}, starting tail.")


def tail(path: str, poll: float = 0.3):
    with open(path, "r") as f:
        if not TAIL_FROM_START:
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

            if line.startswith("#"):
                continue

            try:
                row = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            key = flow_key(row)
            r.set(key, json.dumps(row), ex=FLOW_TTL)


if __name__ == "__main__":
    wait_for_file(LOG_PATH)
    tail(LOG_PATH)
