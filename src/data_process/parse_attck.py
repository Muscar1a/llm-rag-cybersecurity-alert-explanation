import json
import os


def load_attack_techniques() -> list[dict]:
    stix_file = os.path.join("data", "raw", "MITRE", "enterprise-attack", "enterprise-attack.json")
    
    with open(stix_file) as f:
        bundle = json.load(f)
        
    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False):
            continue
        
        ext_id = ""
        url = ""
        
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                url = ref.get("url", "")
                
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        
        platforms = obj.get("x_mitre_platforms", [])

        detection = obj.get("x_mitre_detection", "")

        techniques.append({
            "id": ext_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "detection": detection,
            "url": url,
            "source": "mitre"
        })
        
    print(f"Loaded {len(techniques)} techniques")
    return techniques

if __name__ == "__main__":
    techniques = load_attack_techniques()
    # Preview
    print(json.dumps(techniques[0], indent=2))
    
    os.makedirs(os.path.join("data", "processed", "MITRE"), exist_ok=True)
    output_path = os.path.join("data", "processed", "MITRE", "techniques.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=4)

    print(f"Cleaned file saved at: {output_path}")