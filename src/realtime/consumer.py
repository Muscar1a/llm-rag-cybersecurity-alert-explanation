import json
import os
import logging
import redis
import requests

from src.realtime.alert_builder import build_combined_alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [consumer] %(levelname)s %(message)s",
)
log = logging.getLogger("consumer")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
API_URL = os.getenv("API_URL", "http://host.docker.internal:8000/analyze")
API_TIMEOUT = int(os.getenv("API_TIMEOUT", 60))

SURICATA_QUEUE = "suricata:alerts:raw"
RESULT_QUEUE = "alerts:results"
MAX_RESULTS = 200
CONSUMER_PROVIDER = os.getenv("CONSUMER_PROVIDER", "vllm")
CONSUMER_MODEL = os.getenv("CONSUMER_MODEL") or None

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def _get_provider_config() -> tuple[str, str | None]:
    try:
        p = r.get("config:consumer:provider")
        m = r.get("config:consumer:model")
        provider = p.decode() if p else CONSUMER_PROVIDER
        model = m.decode() if m else (CONSUMER_MODEL or "")
        return provider, model or None
    except Exception:
        return CONSUMER_PROVIDER, CONSUMER_MODEL


def _flow_key(event: dict) -> str:
    proto = str(event.get("proto", "TCP")).lower()
    src = event.get("src_ip", "")
    sp = event.get("src_port", 0)
    dst = event.get("dest_ip", "")
    dp = event.get("dest_port", 0)
    return f"zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}"


def consume():
    log.info("Consumer started, waiting for Suricata alerts...")

    while True:
        _, raw = r.blpop(SURICATA_QUEUE)
        event = json.loads(raw)

        sig = event.get("alert", {}).get("signature", "?")
        dst = f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
        log.info(f"Processing: {dst} | {sig}")

        key = _flow_key(event)
        flow_raw = r.get(key)
        zeek_flow = json.loads(flow_raw) if flow_raw else None

        if zeek_flow:
            log.info(f"  Zeek flow found: {key}")
        else:
            log.info(f"  No Zeek flow, using Suricata-only info.")

        alert_text = build_combined_alert(event, zeek_flow)

        provider, model = _get_provider_config()
        log.info(f"  Using provider: {provider}" + (f" / {model}" if model else ""))
        payload = {
            "alert_text": alert_text,
            "k": 5,
            "provider": provider,
            "model": model,
            "metadata": {
                "src_ip":    event.get("src_ip", ""),
                "dest_ip":   event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", 0),
                "proto":     event.get("proto", ""),
                "signature": sig,
                "severity":  event.get("alert", {}).get("severity", 0),
            },
        }

        try:
            resp = requests.post(API_URL, json=payload, timeout=API_TIMEOUT)
            resp.raise_for_status()
            result = resp.json()
            result["_meta"] = payload["metadata"]
            result["_alert_text"] = alert_text

            r.rpush(RESULT_QUEUE, json.dumps(result))
            r.ltrim(RESULT_QUEUE, -MAX_RESULTS, -1)

            severity = result.get("severity", "?")
            desc = result.get("threat_description", "")[:80]
            log.info(f"  → {severity} | {desc}")

        except requests.exceptions.Timeout:
            log.warning(f"API timeout for {dst}, skipping.")
        except Exception as e:
            log.error(f"API error: {e}")


if __name__ == "__main__":
    consume()
