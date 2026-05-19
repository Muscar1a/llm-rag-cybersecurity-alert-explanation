def _get(row: dict, key: str, default=0.0):
    try: 
        v = float(row.get(key, default))
        return v if v == v else default
    except (ValueError, TypeError):
        return default
    
    
def should_suppress(row: dict) -> bool:
    """A function to ignore records that are likely Benign"""
    proto    = int(_get(row, "Protocol"))
    dst_port = int(_get(row, "Dst Port"))
    tot_pkts = int(_get(row, "Tot Fwd Pkts")) + int(_get(row, "Tot Bwd Pkts"))
    dur_ms   = _get(row, "Flow Duration") / 1000          # µs → ms
    fwd_b    = _get(row, "TotLen Fwd Pkts")
    bwd_b    = _get(row, "TotLen Bwd Pkts")
    ratio    = bwd_b / fwd_b if fwd_b > 0 else 0
    rst      = int(_get(row, "RST Flag Cnt"))
    urg      = int(_get(row, "URG Flag Cnt"))
    syn      = int(_get(row, "SYN Flag Cnt"))
    ack      = int(_get(row, "ACK Flag Cnt"))
    fin      = int(_get(row, "FIN Flag Cnt"))
    payload  = fwd_b + bwd_b
    
    TCP, UDP, ICMP = 6, 17, 1
    
    #* 1. Normal HTTPs handshake
    if (dst_port == 443 and tot_pkts <= 30 and dur_ms < 500
            and ratio <= 15 and rst == 0 and urg == 0):
        return True
    
    #* 2. Normal HTTP handshake
    pkt_rate = _get(row, "Flow Pkts/s")
    if (dst_port == 80 and tot_pkts <= 20 and dur_ms < 300
            and ratio <= 10 and rst == 0 and pkt_rate < 500):
        return True
      
    #* 3. TCP 3-way handshake, no data
    if (syn == 1 and ack == 1 and fin == 0 and rst == 0
            and payload < 100 and dur_ms < 5):
        return True
    
    #* 4. Normal DNS query (UDP 53)
    if (proto == UDP and dst_port == 53
            and payload < 512 and tot_pkts <= 2 and dur_ms < 200):
        return True
    
    #* 5. NTP sync (UDP 123)
    if proto == UDP and dst_port == 123 and tot_pkts <= 2 and payload <= 76:
        return True
    
    #* 6.ICMP Echo Request/Reply normaly
    if proto == ICMP:
        fwd_pkts_raw = int(_get(row, "Tot Fwd Pkts"))
        bwd_pkts_raw = int(_get(row, "Tot Bwd Pkts"))
        avg_pkt_size = payload / tot_pkts if tot_pkts > 0 else 0
        pkt_rate = _get(row, "Flow Pkts/s")
        if (pkt_rate < 5
                and avg_pkt_size <= 64
                and fwd_pkts_raw <= 10
                and bwd_pkts_raw <= 10):
            return True
        
    return False