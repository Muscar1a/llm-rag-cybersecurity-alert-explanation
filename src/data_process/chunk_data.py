import os
import pandas as pd
from transformers import AutoTokenizer
import json

def chunk_data_pipeline(
    cleaned_parquet_path: str,
    output_parquet_path: str,
    source_name: str,
    id_col: str=None,
    text_cols: list=None,    
    model_name="intfloat/e5-small-v2",
    chunk_size=400, 
    chunk_overlap=100,
):
    print(f"[{source_name.upper()}] Loading tokenizer model '{model_name}'...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, model_max_length=100000)

    stride = chunk_size - chunk_overlap
    
    print(f"[{source_name.upper()}] Reading cleaned data from {cleaned_parquet_path}...")
    try:
        df = pd.read_parquet(cleaned_parquet_path)
    except FileNotFoundError:
        print(f"[{source_name.upper()}] Error: File {cleaned_parquet_path} not found.")
        return 
    
    chunked_results = []
    
    print(f"[{source_name.upper()}] Processing {len(df)} records...")
    for idx, row in df.iterrows():
        if id_col and id_col in df.columns:
            doc_id = str(row[id_col])
        else:
            doc_id = f"{source_name}_{idx}"
            
        if text_cols:
            text_parts = [str(row[c]) for c in text_cols if c in df.columns and str(row[c]).strip().lower() not in ["nan", "none", "<na>", ""]]
            text = "\n".join(text_parts)
        else:
            row_dict = row.to_dict()
            text_parts = [f"{k}: {v}" for k, v in row_dict.items() if pd.notna(v)]
            text = " | ".join(text_parts)
            
        if not text.strip() or text.lower() == "nan":
            continue
        
        used_cols = [id_col] + (text_cols if text_cols else list(df.columns))

        metadata = {str(k): str(v) for k, v in row.to_dict().items() if k not in used_cols and str(v).strip().lower() not in ["nan", "none", "<na>", ""]}

        tokens = tokenizer.encode(text, add_special_tokens=False)
        num_tokens = len(tokens)
        
        if num_tokens <= chunk_size:
            chunked_results .append({
                "chunk_id": f"{doc_id}_c0",
                "doc_id": doc_id,
                "source": source_name,
                "text": text,
                "metadata": json.dumps(metadata)
            })
        else:
            chunk_index = 0
            for i in range(0, num_tokens, stride):
                end_idx = min(i + chunk_size, num_tokens)
                window_tokens = tokens[i:end_idx]
                window_text = tokenizer.decode(window_tokens)
                
                chunked_results.append({
                    "chunk_id": f"{doc_id}_c{chunk_index}",
                    "doc_id": doc_id,
                    "source": source_name,
                    "text": window_text,
                    "metadata": json.dumps(metadata)
                })
                chunk_index += 1
                
                if end_idx == num_tokens:
                    break
                
    chunks_df = pd.DataFrame(chunked_results)
    os.makedirs(os.path.dirname(output_parquet_path), exist_ok=True)
    chunks_df.to_parquet(output_parquet_path, index=False)
    print(f"[{source_name.upper()}] Saved {len(chunks_df)} chunks to {output_parquet_path}")
    

if __name__ == "__main__":
    base_dir = "data/processed"
    
    chunk_data_pipeline(
        cleaned_parquet_path=f"{base_dir}/CVE/cve_cleaned.parquet",
        output_parquet_path=f"{base_dir}/CVE/chunks.parquet",
        source_name="cve",
        text_cols=["cve_id","description"],
        id_col="cve_id"
    )
    
    """
    chunk_data_pipeline(
        cleaned_parquet_path=f"{base_dir}/CICIDS2017/cicids_cleaned.parquet",
        output_parquet_path=f"{base_dir}/CICIDS2017/chunks.parquet",
        source_name="cicids",
        id_col=None, 
        text_cols=None 
    )
    """
    
    chunk_data_pipeline(
        cleaned_parquet_path=f"{base_dir}/MITRE/mitre_cleaned.parquet",
        output_parquet_path=f"{base_dir}/MITRE/chunks.parquet",
        source_name="mitre",
        text_cols=["name", "description", "kill_chain_phases"],
        id_col="mitre_id" 
    )