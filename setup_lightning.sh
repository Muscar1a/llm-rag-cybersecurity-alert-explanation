#!/bin/bash
set -e

QDRANT_VERSION="v1.13.6"
OLLAMA_MODEL="qwen2.5:7b-instruct-q4_K_M"

echo "=== [1/4] Installing Qdrant ==="
curl -LO "https://github.com/qdrant/qdrant/releases/download/${QDRANT_VERSION}/qdrant-x86_64-unknown-linux-gnu.tar.gz"
tar -xzf qdrant-x86_64-unknown-linux-gnu.tar.gz
rm qdrant-x86_64-unknown-linux-gnu.tar.gz
chmod +x qdrant

./qdrant &
QDRANT_PID=$!
echo "Qdrant started (PID $QDRANT_PID)"
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
echo "  2. Run embedding: python src/data_process/embed_chunks.py --recreate"
echo "  3. Run benchmark: python scripts/run_benchmark.py --samples 20 --version v1"
echo ""
echo "To stop services:"
echo "  kill $QDRANT_PID $OLLAMA_PID"
