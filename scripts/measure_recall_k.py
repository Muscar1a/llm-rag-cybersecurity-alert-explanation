import json
import sys
from collections import defaultdict
from pathlib import Path

# Add root to sys.path to import src
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.rag.lc_vectorstore import get_vectorstore

def main():
    gt_file = project_root / "baselines" / "ground_truth.json"
    if not gt_file.exists():
        print(f"Error: Not found {gt_file}")
        return

    gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
    
    # Init qdrant
    vs = get_vectorstore()
    
    K_VALS = [5, 10, 20, 50, 100]
    max_k = max(K_VALS)
    
    # Store results
    hits = {k: 0 for k in K_VALS}
    total = 0
    
    tactic_hits = defaultdict(lambda: {k: 0 for k in K_VALS})
    tactic_totals = defaultdict(int)

    # Filter out entries without label_technique
    samples = [row for row in gt_data if row.get("label_technique")]
    
    print(f"Measuring Recall@K for {len(samples)} samples (ignoring samples without label_technique)...")
    
    for i, row in enumerate(samples):
        alert_text = row["alert_text"]
        label_technique = row.get("label_technique")
        label_tactic = row.get("label_tactic")
            
        total += 1
        tactic_totals[label_tactic] += 1
        
        # Raw similarity search, no threshold, no MMR
        docs = vs.similarity_search(alert_text, k=max_k)
        
        # Check presence at each k
        found_at = -1
        for rank, doc in enumerate(docs):
            doc_id = doc.metadata.get("doc_id", "")
            chunk_id = doc.metadata.get("chunk_id", "")
            
            # Check if this chunk is the correct MITRE technique
            if doc_id.startswith(label_technique) or chunk_id.startswith(label_technique):
                found_at = rank
                break
                
        for k in K_VALS:
            if 0 <= found_at < k:
                hits[k] += 1
                tactic_hits[label_tactic][k] += 1
                
        if (i + 1) % 10 == 0:
            print(f"Processed {i + 1}/{len(samples)}")
            
    print("\n" + "="*40)
    print("OVERALL RECALL@K (Raw Similarity)")
    print("="*40)
    for k in K_VALS:
        recall = hits[k] / total if total > 0 else 0
        print(f"Recall@{k:<3}: {recall:.3f} ({hits[k]}/{total})")
        
    print("\n" + "="*40)
    print("RECALL BY TACTIC")
    print("="*40)
    # Sort tactics alphabetically for clean output
    for tactic in sorted(tactic_totals.keys()):
        count = tactic_totals[tactic]
        print(f"\n{tactic} (n={count}):")
        for k in K_VALS:
            recall = tactic_hits[tactic][k] / count if count > 0 else 0
            print(f"  Recall@{k:<3}: {recall:.3f} ({tactic_hits[tactic][k]}/{count})")

if __name__ == "__main__":
    main()
