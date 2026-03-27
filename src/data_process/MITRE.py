import json 
import re
import os
import glob

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[\x00-\x1F\x7f-\x9f]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text
    
def process_mitre():
    input_dir = os.path.join("data", "raw", "MITRE", "enterprise-attack")
    if not os.path.exists(input_dir):
        print(f"Directory not found: {input_dir}")
        return
        
    all_files = glob.glob(os.path.join(input_dir, "*.json"))
    print(f"Found {len(all_files)} files to process.")
    
    techniques_dict = {}

    for file_path in all_files:
        print(f"Processing {os.path.basename(file_path)}...")
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error reading {file_path}, skipping.")
                continue
            
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                
                mitre_id = "Unknown ID"
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        mitre_id = ref.get("external_id", "Unknown ID")
                        break
            
                name = obj.get("name", "Unknown Name")
                desc = clean_text(obj.get("description", ""))
                
                if not desc:
                    continue
                
                phases = []
                for phase in obj.get("kill_chain_phases", []):
                    phases.append(phase.get("phase_name"))
                    
                techniques_dict[mitre_id] = {
                    "mitre_id": mitre_id,
                    "name": name,
                    "description": desc,
                    "kill_chain_phases": phases
                }

    techniques = list(techniques_dict.values())
    
    os.makedirs(os.path.join("data", "processed", "MITRE"), exist_ok=True)
    output_path = os.path.join("data", "processed", "MITRE", "techniques.json")

    print(f"Saved {len(techniques)} unique MITRE techniques to {output_path}")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=4)

    print(f"Cleaned file saved at: {output_path}")


if __name__ == "__main__":
    process_mitre()