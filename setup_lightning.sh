#!/bin/bash
set -e

QDRANT_STORAGE="/tmp/qdrant_data"

echo "=== [1/3] Installing Qdrant ==="
QDRANT_VERSION=$(curl -s https://api.github.com/repos/qdrant/qdrant/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
# GitHub API is rate-limited per IP on shared cloud runners; fall back to a pinned version
QDRANT_VERSION=${QDRANT_VERSION:-v1.15.1}
echo "Qdrant version: $QDRANT_VERSION"
curl -LO "https://github.com/qdrant/qdrant/releases/download/${QDRANT_VERSION}/qdrant-x86_64-unknown-linux-gnu.tar.gz"
tar -xzf qdrant-x86_64-unknown-linux-gnu.tar.gz
rm qdrant-x86_64-unknown-linux-gnu.tar.gz
chmod +x qdrant

# Run with storage on /tmp to avoid cross-device rename errors on network mounts
mkdir -p "$QDRANT_STORAGE"
QDRANT__STORAGE__STORAGE_PATH="$QDRANT_STORAGE" ./qdrant &
QDRANT_PID=$!
echo "Qdrant started (PID $QDRANT_PID, storage: $QDRANT_STORAGE)"
sleep 3

echo ""
echo "=== [2/3] Installing Python dependencies ==="
pip install -r requirements.txt

# Load environment variables from .env if it exists (strip CR in case the file
# was written on Windows — a trailing \r in exported values breaks API keys/URLs)
if [ -f .env ]; then
    set -a; source <(tr -d '\r' < .env); set +a
fi

echo ""
echo "=== [3/3] Ingesting Knowledge Base to Qdrant ==="
PYTHONPATH=. python src/data_process/ingest_kb.py

echo ""
echo "=== Setup Complete ==="
echo "Qdrant PID: $QDRANT_PID"
echo ""
echo "Run benchmark with cloud model:"
echo "  PYTHONPATH=. python scripts/run_benchmark.py --provider openai --version v1"
echo ""
echo "Run benchmark with local vLLM (run setup_vllm.sh first):"
echo "  PYTHONPATH=. python scripts/run_benchmark.py --provider vllm --version v1"
echo ""
echo "When done:"
echo "  kill $QDRANT_PID"