#!/bin/bash
set -e

VLLM_MODEL="Qwen/Qwen2.5-14B-Instruct"
VLLM_PORT=8001

# Load environment variables from .env if it exists so vLLM can read HF_TOKEN
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

echo "=== Starting vLLM server: $VLLM_MODEL ==="
# Using bitsandbytes 8-bit quantization so the 14B model fits on 24GB L4 GPU
vllm serve "$VLLM_MODEL" \
    --port "$VLLM_PORT" \
    --max-model-len 8192 \
    --quantization bitsandbytes \
    --load-format bitsandbytes \
    --gpu-memory-utilization 0.9 &
VLLM_PID=$!
echo "vLLM started (PID $VLLM_PID)"

echo "Waiting for vLLM to initialize (this may take a few minutes)..."
while ! curl -s "http://localhost:${VLLM_PORT}/v1/models" > /dev/null; do
    sleep 5
done
echo "vLLM is ready!"
echo ""
echo "vLLM PID: $VLLM_PID"
echo "When done: kill $VLLM_PID"
