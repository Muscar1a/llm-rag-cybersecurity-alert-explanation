import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.rag.service import Retriever

r = Retriever()

queries = [
    ("Apache Log4j RCE", "cve"),
    ("credential dumping", "mitre"),
]

for q, source in queries:
    hits = r.search(query=q, k=3, source=source)
    print(f"\nQuery: {q} | source={source}")
    for i, h in enumerate(hits, 1):
        print(i, h["doc_id"], h["score"])