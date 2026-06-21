#!/bin/bash
set -e

VLLM_MODEL="deepseek-ai/DeepSeek-R1-Distill-Qwen-14B"
VLLM_PORT=8001
QDRANT_STORAGE="/tmp/qdrant_data"

echo "=== [1/5] Installing Qdrant ==="
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
echo "=== [2/5] Installing Python dependencies ==="
pip install -r requirements.txt

echo ""
echo "=== [3/5] Starting vLLM server: $VLLM_MODEL ==="
# Load environment variables from .env if it exists so vLLM can read HF_TOKEN
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Note: Using bitsandbytes 8-bit quantization so the 14B model fits on 24GB L4 GPU
vllm serve "$VLLM_MODEL" \
    --port "$VLLM_PORT" \
    --max-model-len 10240 \
    --quantization bitsandbytes \
    --load-format bitsandbytes \
    --gpu-memory-utilization 0.9 &
VLLM_PID=$!
echo "vLLM started (PID $VLLM_PID)"

# Wait for vLLM to be ready
echo "Waiting for vLLM to initialize (this may take a few minutes)..."
while ! curl -s "http://localhost:${VLLM_PORT}/v1/models" > /dev/null; do
    sleep 5
done
echo "vLLM is ready!"

echo ""
echo "=== [4/4] Ingesting Knowledge Base to Qdrant ==="
PYTHONPATH=. python src/data_process/ingest_kb.py

echo ""
echo "=== Setup Complete ==="
echo "Qdrant PID: $QDRANT_PID | vLLM PID: $VLLM_PID"
echo ""
echo "Run benchmark manually:"
echo "  PYTHONPATH=. python scripts/run_benchmark.py --samples 135 --templates basic --version v1"
echo ""
echo "When done:"
echo "  kill $QDRANT_PID $VLLM_PID"

