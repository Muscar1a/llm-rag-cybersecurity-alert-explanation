import json
import os
import re
import pandas as pd
from transformers import AutoTokenizer

TOKENIZER_MODEL = "intfloat/e5-small-v2"
CHUNK_SIZE      = 400
CHUNK_OVERLAP   = 100

SOURCES = [
    {
        "name":       "cve",
        "input":      "data/processed/CVE/cve_cleaned.parquet",
        "output":     "data/processed/CVE/chunks.parquet",
        "id_col":     "cve_id",
        "text_cols":  ["cve_id", "description"],
    },
    {
        "name":       "mitre",
        "input":      "data/processed/MITRE/mitre_cleaned.parquet",
        "output":     "data/processed/MITRE/chunks.parquet",
        "id_col":     "mitre_id",
        "text_cols":  ["name", "description", "tactics"],
    },
    {
        "name":       "sigma",
        "input":      "data/processed/sigma/sigma_cleaned.parquet",
        "output":     "data/processed/sigma/chunks.parquet",
        "id_col":     None,
        "text_cols":  ["title", "description", "level", "tags", "logsource", "falsepositives", "detection"],
    },
]


def _is_junk(text: str) -> bool:
    # kernel function offset notation: +0x12c/0x2a0 (both sides have 0x in real stack traces)
    if len(re.findall(r"\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+", text)) > 1:
        return True
    # kernel log timestamps: [47200.376770]
    if re.search(r"\[\s*\d{5,}\.\d+\]", text):
        return True
    # long memory addresses: 0xffff88816d2c0400
    if len(re.findall(r"0x[0-9a-fA-F]{8,}", text)) > 2:
        return True
    return False


def _chunk_records(
    df: pd.DataFrame,
    source_name: str,
    id_col: str | None,
    text_cols: list[str],
    tokenizer,
) -> list[dict]:
    stride = CHUNK_SIZE - CHUNK_OVERLAP
    results = []

    for idx, row in df.iterrows():
        doc_id = str(row[id_col]) if id_col and id_col in df.columns else f"{source_name}_{idx}"

        text_parts = [
            str(row[c]) for c in text_cols
            if c in df.columns and str(row[c]).strip().lower() not in ("nan", "none", "<na>", "")
        ]
        text = "\n".join(text_parts)
        if not text.strip():
            continue

        used_cols = {id_col} | set(text_cols)
        metadata = {
            str(k): str(v)
            for k, v in row.to_dict().items()
            if k not in used_cols and str(v).strip().lower() not in ("nan", "none", "<na>", "")
        }

        tokens = tokenizer.encode(text, add_special_tokens=False)

        if len(tokens) <= CHUNK_SIZE:
            if not _is_junk(text):
                results.append({
                    "chunk_id": f"{doc_id}_c0",
                    "doc_id":   doc_id,
                    "source":   source_name,
                    "text":     text,
                    "metadata": json.dumps(metadata),
                })
        else:
            for chunk_idx, start in enumerate(range(0, len(tokens), stride)):
                end = min(start + CHUNK_SIZE, len(tokens))
                chunk_text = tokenizer.decode(tokens[start:end])
                if not _is_junk(chunk_text):
                    results.append({
                        "chunk_id": f"{doc_id}_c{chunk_idx}",
                        "doc_id":   doc_id,
                        "source":   source_name,
                        "text":     chunk_text,
                        "metadata": json.dumps(metadata),
                    })
                if end == len(tokens):
                    break

    return results


def chunk_source(source_cfg: dict, tokenizer) -> None:
    name   = source_cfg["name"]
    input_ = source_cfg["input"]
    output = source_cfg["output"]

    if not os.path.isfile(input_):
        print(f"[{name.upper()}] Input not found: {input_} - skipping.")
        return

    print(f"[{name.upper()}] Loading {input_}...")
    df = pd.read_parquet(input_)
    print(f"[{name.upper()}] {len(df)} records -> chunking...")

    records = _chunk_records(
        df,
        source_name=name,
        id_col=source_cfg["id_col"],
        text_cols=source_cfg["text_cols"],
        tokenizer=tokenizer,
    )

    os.makedirs(os.path.dirname(output), exist_ok=True)
    pd.DataFrame(records).to_parquet(output, index=False)
    print(f"[{name.upper()}] Saved {len(records)} chunks -> {output}")


if __name__ == "__main__":
    print(f"Loading tokenizer: {TOKENIZER_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_MODEL, model_max_length=100000)

    for source_cfg in SOURCES:
        chunk_source(source_cfg, tokenizer)
