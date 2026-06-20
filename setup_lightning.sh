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
# Note: Using bitsandbytes 8-bit quantization so the 14B model fits on 24GB L4 GPU
vllm serve "$VLLM_MODEL" \
    --port "$VLLM_PORT" \
    --max-model-len 5120 \
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
echo "=== [4/5] Ingesting Knowledge Base to Qdrant ==="
python src/data_process/ingest_kb.py

echo ""
echo "=== [5/5] Running Benchmark ==="
# You can customize the sample size and templates here
python scripts/run_benchmark.py --samples 173 --templates basic --version v1

echo ""
echo "=== Benchmark Complete ==="
echo "Cleaning up background processes..."
kill $QDRANT_PID $VLLM_PID
echo "All done."

