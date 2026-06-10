#!/bin/bash
set -e

OLLAMA_MODEL="qwen2.5:7b-instruct-q4_K_M"
QDRANT_STORAGE="/tmp/qdrant_data"

echo "=== [1/4] Installing Qdrant ==="
QDRANT_VERSION=$(curl -s https://api.github.com/repos/qdrant/qdrant/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
echo "Latest Qdrant: $QDRANT_VERSION"
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
echo "=== [2/4] Installing Ollama ==="
curl -fsSL https://ollama.ai/install.sh | sh

ollama serve &
OLLAMA_PID=$!
echo "Ollama started (PID $OLLAMA_PID)"
sleep 5

echo ""
echo "=== [3/4] Pulling model: $OLLAMA_MODEL ==="
ollama pull "$OLLAMA_MODEL"

echo ""
echo "=== [4/4] Installing Python dependencies ==="
pip install -r requirements.txt

echo ""
echo "=== Setup complete ==="
echo "Qdrant : http://localhost:6333"
echo "Ollama : http://localhost:11434"
echo ""
echo "Next steps:"
echo "  1. Create .env with DEEPSEEK_API_KEY and HF_TOKEN"
echo "  2. Ingest KB v2:  python src/data_process/ingest_kb.py"
echo "  3. Run benchmark: python scripts/run_benchmark.py --samples 131 --templates basic --version v1"
echo ""
echo "To stop services:"
echo "  kill $QDRANT_PID $OLLAMA_PID"
