import json, re, sys

# Load data
with open('tests/alerts.json') as f:
    alerts = json.load(f)

with open('baselines/ground_truth.json') as f:
    gt = json.load(f)

def load_jsonl(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

port_kb = load_jsonl('data/kb/port_profile/port_profiles.jsonl')
conn_kb = load_jsonl('data/kb/conn_state/conn_state_profiles.jsonl')
tactic_kb = load_jsonl('data/kb/tactic_profile/tactic_profiles.jsonl')
traffic_kb = load_jsonl('data/kb/traffic_pattern/traffic_pattern_profiles.jsonl')
cat_kb = load_jsonl('data/kb/suricata_category/suricata_category_profiles.jsonl')

port_map = {e['metadata']['port']: e for e in port_kb}
conn_map = {e['metadata']['state_code']: e for e in conn_kb}
tactic_map = {e['metadata']['tactic'].lower(): e for e in tactic_kb}
traffic_map = {e['id']: e for e in traffic_kb}
cat_map = {e['metadata']['category']: e for e in cat_kb}

print(f"Alerts: {len(alerts)}, Ground truth entries: {len(gt)}")

if len(alerts) != len(gt):
    print(f"ERROR: alerts count ({len(alerts)}) != gt count ({len(gt)})")

gt_by_id = {g['id']: g for g in gt}
errors = []

HIGH_RISK = {'exfiltration', 'command and control', 'impact', 'lateral movement'}
MED_RISK = {'credential access', 'discovery', 'initial access', 'execution', 'persistence',
            'privilege escalation', 'defense evasion', 'reconnaissance', 'resource development', 'collection'}
ladder = ['low', 'medium', 'high', 'critical']

action_map = {
    'critical': ('auto_isolate_host', 'Isolate source host from network, page on-call SOC, open P1 incident'),
    'high': ('auto_block_and_ticket', 'Block source IP at perimeter, open P2 ticket, enrich with threat intel'),
    'medium': ('enrich_and_queue', 'Enrich alert with context, queue for analyst review (no auto-block)'),
    'low': ('log_and_suppress', 'Log to SIEM, suppress from analyst queue unless pattern repeats')
}

for alert in alerts:
    aid = alert['id']
    gt_entry = gt_by_id.get(aid)
    if gt_entry is None:
        errors.append(f"ID {aid}: Missing from ground_truth.json")
        continue

    net = alert['network']
    label_tactic = alert['_ground_truth']['label_tactic']
    label_technique = alert['_ground_truth']['label_technique']

    # Label passthrough
    if gt_entry.get('label_tactic') != label_tactic:
        errors.append(f"ID {aid}: label_tactic mismatch: gt={gt_entry.get('label_tactic')} expected={label_tactic}")
    if gt_entry.get('label_technique') != label_technique:
        errors.append(f"ID {aid}: label_technique mismatch: gt={gt_entry.get('label_technique')} expected={label_technique}")

    # 1a. PORT_KB
    dest_port = net['dest_port']
    expected_port_kb = port_map.get(dest_port)
    expected_port_id = expected_port_kb['id'] if expected_port_kb else None
    actual_port_id = gt_entry['evidence'].get('port_kb')
    if actual_port_id != expected_port_id:
        errors.append(f"ID {aid}: port_kb mismatch: gt={actual_port_id} expected={expected_port_id} (port={dest_port})")

    # 1b. CONN_KB
    conn_state = net['conn_state']
    expected_conn_kb = conn_map.get(conn_state)
    expected_conn_id = expected_conn_kb['id'] if expected_conn_kb else None
    actual_conn_id = gt_entry['evidence'].get('conn_state_kb')
    if actual_conn_id != expected_conn_id:
        errors.append(f"ID {aid}: conn_state_kb mismatch: gt={actual_conn_id} expected={expected_conn_id} (state={conn_state})")

    # 1c. TACTIC_KB
    tactic_norm = label_tactic.replace('_', ' ').lower()
    expected_tactic_kb = tactic_map.get(tactic_norm)
    expected_tactic_id = expected_tactic_kb['id'] if expected_tactic_kb else None
    actual_tactic_id = gt_entry['evidence'].get('tactic_kb')
    if actual_tactic_id != expected_tactic_id:
        errors.append(f"ID {aid}: tactic_kb mismatch: gt={actual_tactic_id} expected={expected_tactic_id} (tactic={label_tactic})")

    # 1d. TRAFFIC PATTERN
    o = net['orig_bytes']
    r = net['resp_bytes']
    cs = net['conn_state']
    h = net.get('history', '')
    d = net['duration_s']

    patterns = []
    if cs == 'SF' and o == 0 and r == 0:
        patterns.append(('zero_payload_established', 5))
    if o > 0 and r > 0 and (r / o) >= 5:
        patterns.append(('server_dominant_bulk', 1))
    if o > 0 and r > 0 and (o / r) >= 5:
        patterns.append(('client_dominant_bulk', 1))
    if (o > 0 or r > 0) and cs in ('RSTO', 'RSTR'):
        patterns.append(('reset_after_data', 2))
    t_count = h.count('T') + h.count('t')
    if len(h) > 0 and t_count >= len(h) / 3:
        patterns.append(('retransmission_heavy', 3))
    if d >= 60 and (o + r) <= 1000:
        patterns.append(('long_duration_low_volume', 6))

    patterns.sort(key=lambda x: x[1])
    kept = [p[0] for p in patterns[:2]]
    expected_traffic_ids = [f"traffic_pattern_{p}" for p in kept]
    actual_traffic_ids = gt_entry['evidence'].get('traffic_pattern_kb', [])
    if sorted(actual_traffic_ids) != sorted(expected_traffic_ids):
        errors.append(f"ID {aid}: traffic_pattern_kb mismatch: gt={actual_traffic_ids} expected={expected_traffic_ids} (o={o},r={r},cs={cs},h={h},d={d})")

    # 1e. CATEGORY_KB
    cat_match = re.search(r'severity \d+, ([^)]+)\)', alert['alert_text'])
    expected_cat = cat_match.group(1) if cat_match else None
    expected_cat_kb = cat_map.get(expected_cat) if expected_cat else None
    expected_cat_id = expected_cat_kb['id'] if expected_cat_kb else None
    actual_cat_id = gt_entry['evidence'].get('category_kb')
    if actual_cat_id != expected_cat_id:
        errors.append(f"ID {aid}: category_kb mismatch: gt={actual_cat_id} expected={expected_cat_id} (cat={expected_cat})")

    # SEVERITY
    sev_match = re.search(r'severity (\d+)', alert['alert_text'])
    sev_num = int(sev_match.group(1))
    sev_map_base = {1: 'critical', 2: 'high', 3: 'medium'}
    base_sev = sev_map_base[sev_num]

    if tactic_norm in HIGH_RISK:
        tier = 'HIGH'
    elif tactic_norm in MED_RISK:
        tier = 'MED'
    else:
        tier = 'NONE'

    idx = ladder.index(base_sev)
    if tier == 'HIGH':
        idx = min(idx + 1, 3)
    elif tier == 'NONE':
        idx = max(idx - 1, 0)
    current_sev = ladder[idx]

    behavioral = {'reset_after_data', 'server_dominant_bulk', 'client_dominant_bulk', 'retransmission_heavy'}
    if current_sev in ('high', 'critical') and any(p in behavioral for p in kept):
        cidx = ladder.index(current_sev)
        current_sev = ladder[min(cidx + 1, 3)]

    if label_tactic == 'Benign':
        current_sev = 'low'

    expected_sev = current_sev
    actual_sev = gt_entry.get('severity')
    if actual_sev != expected_sev:
        errors.append(f"ID {aid}: severity mismatch: gt={actual_sev} expected={expected_sev} (base={base_sev}, tier={tier}, patterns={kept})")

    # RECOMMENDED ACTION
    expected_action = action_map[expected_sev]
    actual_action = gt_entry.get('recommended_action', {})
    if actual_action.get('action_id') != expected_action[0]:
        errors.append(f"ID {aid}: action_id mismatch: gt={actual_action.get('action_id')} expected={expected_action[0]}")
    if actual_action.get('description') != expected_action[1]:
        errors.append(f"ID {aid}: action description mismatch: gt='{actual_action.get('description')}'")

    # Reference checks
    ref = gt_entry.get('reference', '')
    if label_tactic != 'Benign':
        tactic_display = label_tactic.replace('_', ' ')
        if tactic_display.lower() in ref.lower():
            # Check it's not just part of KB text
            if f"is {tactic_display}" in ref or f"indicates {tactic_display}" in ref or f"this is {tactic_display}" in ref:
                errors.append(f"ID {aid}: reference directly names label_tactic '{label_tactic}'")
    if label_technique != 'none' and label_technique in ref:
        errors.append(f"ID {aid}: reference contains label_technique '{label_technique}'")

    # Check alert_text passthrough
    if gt_entry.get('alert_text') != alert['alert_text']:
        errors.append(f"ID {aid}: alert_text not passed through correctly")

if errors:
    print(f"\nTOTAL ERRORS: {len(errors)}")
    for e in errors:
        print(f"  {e}")
else:
    print("\nALL CHECKS PASSED!")
