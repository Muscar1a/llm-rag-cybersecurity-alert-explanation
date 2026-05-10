# E2E Report: 5 Alerts Baseline

- Generated at: `2026-05-08 10:53:16`
- Data source: `data/processed/CICIDS2017/cicids_rag_evaluation.csv`
- Retrieval source: `mitre`
- Retrieval k: `5`
- Prompt template in service: `basic`

## Summary

| # | Label | Status |
|---|---|---|
| 1 | SSH-Patator | OK |
| 2 | FTP-Patator | OK |
| 3 | PortScan | OK |
| 4 | DoS Hulk | OK |
| 5 | Bot | OK |

## Alert 1: SSH-Patator

### Raw Packet Row

```json
{
  "destination_port": 22,
  "flow_duration": 14201661,
  "total_fwd_packets": 21,
  "total_backward_packets": 32,
  "total_length_of_fwd_packets": 2008,
  "total_length_of_bwd_packets": 2745,
  "fwd_packet_length_max": 640,
  "fwd_packet_length_min": 0,
  "fwd_packet_length_mean": 95.61904762,
  "fwd_packet_length_std": 140.0451628,
  "bwd_packet_length_max": 976,
  "bwd_packet_length_min": 0,
  "bwd_packet_length_mean": 85.78125,
  "bwd_packet_length_std": 220.240592,
  "flow_bytes_s": 334.6791618,
  "flow_packets_s": 3.731957832,
  "flow_iat_mean": 273108.8654,
  "flow_iat_std": 737057.7048,
  "flow_iat_max": 2501407,
  "flow_iat_min": 40,
  "fwd_iat_total": 11800000,
  "fwd_iat_mean": 592133.6,
  "fwd_iat_std": 1038610.726,
  "fwd_iat_max": 2566372,
  "fwd_iat_min": 849,
  "bwd_iat_total": 14200000,
  "bwd_iat_mean": 458114.0,
  "bwd_iat_std": 914370.1272,
  "bwd_iat_max": 2501407,
  "bwd_iat_min": 48,
  "fwd_psh_flags": 0,
  "bwd_psh_flags": 0,
  "fwd_urg_flags": 0,
  "bwd_urg_flags": 0,
  "fwd_header_length": 680,
  "bwd_header_length": 1032,
  "fwd_packets_s": 1.478700273,
  "bwd_packets_s": 2.253257559,
  "min_packet_length": 0,
  "max_packet_length": 976,
  "packet_length_mean": 88.01851852,
  "packet_length_std": 189.5902723,
  "packet_length_variance": 35944.47135,
  "fin_flag_count": 0,
  "syn_flag_count": 0,
  "rst_flag_count": 0,
  "psh_flag_count": 1,
  "ack_flag_count": 0,
  "urg_flag_count": 0,
  "cwe_flag_count": 0,
  "ece_flag_count": 0,
  "down_up_ratio": 1,
  "average_packet_size": 89.67924528,
  "avg_fwd_segment_size": 95.61904762,
  "avg_bwd_segment_size": 85.78125,
  "fwd_header_length.1": 680,
  "fwd_avg_bytes_bulk": 0,
  "fwd_avg_packets_bulk": 0,
  "fwd_avg_bulk_rate": 0,
  "bwd_avg_bytes_bulk": 0,
  "bwd_avg_packets_bulk": 0,
  "bwd_avg_bulk_rate": 0,
  "subflow_fwd_packets": 21,
  "subflow_fwd_bytes": 2008,
  "subflow_bwd_packets": 32,
  "subflow_bwd_bytes": 2745,
  "init_win_bytes_forward": 29200,
  "init_win_bytes_backward": 247,
  "act_data_pkt_fwd": 16,
  "min_seg_size_forward": 32,
  "active_mean": 0.0,
  "active_std": 0.0,
  "active_max": 0,
  "active_min": 0,
  "idle_mean": 0.0,
  "idle_std": 0.0,
  "idle_max": 0,
  "idle_min": 0,
  "label": "SSH-Patator"
}
```

### Alert Text

```text
[ALERT] UNKNOWN traffic observed targeting destination port 22 (SSH). moderate duration flow (14.20s). relatively balanced bidirectional communication (21 forward vs 32 backward packets). very low packet rate (3.73 packets/s). low throughput (334.68 bytes/s). small average packet sizes. PSH packets observed without normal handshake behavior (PSH=1).
```

### RAG Response

```json
{
  "threat_description": "Unknown traffic observed targeting destination port 22 (SSH).",
  "severity": "Medium",
  "rationale": "The alert describes a moderate duration flow of SSH traffic with relatively balanced bidirectional communication and low packet rate. The use of PSH packets without normal handshake behavior is also noted. While the alert does not provide enough information to determine the specific nature of the traffic, it is possible that this could be indicative of an attempt to establish a secure connection for command-and-control purposes or lateral movement within an environment.",
  "mitigation_steps": [
    "Monitor SSH traffic for any suspicious activity",
    "Implement network segmentation to limit the impact of any potential compromise",
    "Ensure that all SSH sessions are properly secured and monitored"
  ],
  "retrieved_context_ids": [
    "T1043_c0",
    "T1572_c0",
    "T1563.001_c0",
    "T1110.001_c0",
    "T1021_c1"
  ],
  "contexts": [
    {
      "chunk_id": "T1043_c0",
      "doc_id": "T1043",
      "source": "mitre",
      "text": "Commonly Used Port\n**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as* TCP:80 (HTTP)* TCP:443 (HTTPS)* TCP:25 (SMTP)* TCP/UDP:53 (DNS)They may use the protocol associated with the port or a completely different protocol. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are * TCP/UDP:135 (RPC)* TCP/UDP:22 (SSH)* TCP/UDP:3389 (RDP)\n['command-and-control']",
      "metadata": {},
      "score": 0.86782014
    },
    {
      "chunk_id": "T1572_c0",
      "doc_id": "T1572",
      "source": "mitre",
      "text": "protocol tunneling adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection / network filtering and / or enable access to otherwise unreachable systems. tunneling involves explicitly encapsulating a protocol within another. this behavior may conceal malicious traffic by blending in with existing traffic and / or provide an outer layer of encryption ( similar to a vpn ). tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as smb, rdp, or other traffic that would be filtered by network appliances or not routed over the internet. there are various means to encapsulate a protocol within another protocol. for example, adversaries may perform ssh tunneling ( also known as ssh port forwarding ), which involves forwarding arbitrary data over an encrypted ssh tunnel. ( citation : ssh tunneling ) ( citation : sygnia abyss locker 2025 ) [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) may also be abused by adversaries during [ dynamic resolution ] ( https : / / attack. mitre. org / techniques / t1568 ). known as dns over https ( doh ), queries to resolve c2 infrastructure may be encapsulated within encrypted https packets. ( citation : bleepingcomp godlua jul19 ) adversaries may also leverage [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) in conjunction with [ proxy ] ( https : / / attack. mitre. org / techniques / t1090 ) and / or [ protocol or service impersonation ] ( https : / / attack. mitre. org / techniques / t1001 / 003 ) to further conceal c2 communications and infrastructure. ['command - and - control",
      "metadata": {},
      "score": 0.86559564
    },
    {
      "chunk_id": "T1563.001_c0",
      "doc_id": "T1563.001",
      "source": "mitre",
      "text": "SSH Hijacking\nAdversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial.(Citation: Slideshare Abusing SSH)(Citation: SSHjack Blackhat)(Citation: Clockwork SSH Agent Hijacking)(Citation: Breach Post-mortem SSH Hijack)[SSH Hijacking](https://attack.mitre.org/techniques/T1563/001) differs from use of [SSH](https://attack.mitre.org/techniques/T1021/004) because it hijacks an existing SSH session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).\n['lateral-movement']",
      "metadata": {},
      "score": 0.8619523
    },
    {
      "chunk_id": "T1110.001_c0",
      "doc_id": "T1110.001",
      "source": "mitre",
      "text": "password guessing adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. an adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts. guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. ( citation : cylance cleaver ) typically, management services over commonly used ports are used when guessing passwords. commonly targeted services include the following : * ssh ( 22 / tcp ) * telnet ( 23 / tcp ) * ftp ( 21 / tcp ) * netbios / smb / samba ( 139 / tcp & 445 / tcp ) * ldap ( 389 / tcp ) * kerberos ( 88 / tcp ) * rdp / terminal services ( 3389 / tcp ) * http / http management services ( 80 / tcp & 443 / tcp ) * mssql ( 1433 / tcp ) * oracle ( 1521 / tcp ) * mysql ( 3306 / tcp ) * vnc ( 5900 / tcp ) * snmp ( 161 / udp and 162 / tcp / udp ) in addition to management services, adversaries may \" target single sign - on ( sso ) and cloud - based applications utilizing federated authentication protocols, \" as well as externally facing email applications, such as office 365. ( citation : us - cert ta18 - 068a 2018 ). further, advers",
      "metadata": {},
      "score": 0.85575044
    },
    {
      "chunk_id": "T1021_c1",
      "doc_id": "T1021",
      "source": "mitre",
      "text": "##nc ] ( https : / / attack. mitre. org / techniques / t1021 / 005 ) to send the screen and control buffers and [ ssh ] ( https : / / attack. mitre. org / techniques / t1021 / 004 ) for secure file transfer. ( citation : remote management mdm macos ) ( citation : kickstart apple remote desktop commands ) ( citation : apple remote desktop admin guide 3. 3 ) adversaries can abuse applications such as ard to gain remote code execution and perform lateral movement. in versions of macos prior to 10. 14, an adversary can escalate an ssh session to an ard session which enables an adversary to accept tcc ( transparency, consent, and control ) prompts without user interaction and gain access to data. ( citation : fireeye 2019 apple remote desktop ) ( citation : lockboxx ard 2019 ) ( citation : kickstart apple remote desktop commands ) ['lateral - movement']",
      "metadata": {},
      "score": 0.85392255
    }
  ]
}
```

## Alert 2: FTP-Patator

### Raw Packet Row

```json
{
  "destination_port": 21,
  "flow_duration": 8758097,
  "total_fwd_packets": 9,
  "total_backward_packets": 15,
  "total_length_of_fwd_packets": 103,
  "total_length_of_bwd_packets": 188,
  "fwd_packet_length_max": 24,
  "fwd_packet_length_min": 0,
  "fwd_packet_length_mean": 11.44444444,
  "fwd_packet_length_std": 9.153020145,
  "bwd_packet_length_max": 34,
  "bwd_packet_length_min": 0,
  "bwd_packet_length_mean": 12.53333333,
  "bwd_packet_length_std": 14.54975045,
  "flow_bytes_s": 33.2263961,
  "flow_packets_s": 2.740321328,
  "flow_iat_mean": 380786.8261,
  "flow_iat_std": 999399.8942,
  "flow_iat_max": 3371730,
  "flow_iat_min": 3,
  "fwd_iat_total": 6383723,
  "fwd_iat_mean": 797965.375,
  "fwd_iat_std": 1480707.418,
  "fwd_iat_max": 3415392,
  "fwd_iat_min": 3,
  "bwd_iat_total": 8758011,
  "bwd_iat_mean": 625572.2143,
  "bwd_iat_std": 1235063.284,
  "bwd_iat_max": 3371730,
  "bwd_iat_min": 3,
  "fwd_psh_flags": 0,
  "bwd_psh_flags": 0,
  "fwd_urg_flags": 0,
  "bwd_urg_flags": 0,
  "fwd_header_length": 296,
  "bwd_header_length": 488,
  "fwd_packets_s": 1.027620498,
  "bwd_packets_s": 1.71270083,
  "min_packet_length": 0,
  "max_packet_length": 34,
  "packet_length_mean": 11.64,
  "packet_length_std": 12.55282173,
  "packet_length_variance": 157.5733333,
  "fin_flag_count": 0,
  "syn_flag_count": 0,
  "rst_flag_count": 0,
  "psh_flag_count": 1,
  "ack_flag_count": 0,
  "urg_flag_count": 0,
  "cwe_flag_count": 0,
  "ece_flag_count": 0,
  "down_up_ratio": 1,
  "average_packet_size": 12.125,
  "avg_fwd_segment_size": 11.44444444,
  "avg_bwd_segment_size": 12.53333333,
  "fwd_header_length.1": 296,
  "fwd_avg_bytes_bulk": 0,
  "fwd_avg_packets_bulk": 0,
  "fwd_avg_bulk_rate": 0,
  "bwd_avg_bytes_bulk": 0,
  "bwd_avg_packets_bulk": 0,
  "bwd_avg_bulk_rate": 0,
  "subflow_fwd_packets": 9,
  "subflow_fwd_bytes": 103,
  "subflow_bwd_packets": 15,
  "subflow_bwd_bytes": 188,
  "init_win_bytes_forward": 29200,
  "init_win_bytes_backward": 227,
  "act_data_pkt_fwd": 6,
  "min_seg_size_forward": 32,
  "active_mean": 0.0,
  "active_std": 0.0,
  "active_max": 0,
  "active_min": 0,
  "idle_mean": 0.0,
  "idle_std": 0.0,
  "idle_max": 0,
  "idle_min": 0,
  "label": "FTP-Patator"
}
```

### Alert Text

```text
[ALERT] UNKNOWN traffic observed targeting destination port 21 (FTP). moderate duration flow (8.76s). relatively balanced bidirectional communication (9 forward vs 15 backward packets). very low packet rate (2.74 packets/s). low throughput (33.23 bytes/s). very small average packet sizes. PSH packets observed without normal handshake behavior (PSH=1).
```

### RAG Response

```json
{
  "threat_description": "An unknown traffic observed targeting destination port 21 (FTP) with moderate duration flow, relatively balanced bidirectional communication, and low throughput. PSH packets observed without normal handshake behavior.",
  "severity": "Medium",
  "rationale": "The observed traffic is using a commonly used port for file transfer, which may be used by adversaries to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. The use of PSH packets without normal handshake behavior suggests that the communication may be abnormal and potentially malicious.",
  "mitigation_steps": [
    "Monitor FTP traffic for any suspicious activity",
    "Implement network segmentation to isolate FTP traffic from other systems"
  ],
  "retrieved_context_ids": [
    "T1043_c0",
    "T1572_c0",
    "T1071.002_c0",
    "T1048_c0",
    "T1021_c1"
  ],
  "contexts": [
    {
      "chunk_id": "T1043_c0",
      "doc_id": "T1043",
      "source": "mitre",
      "text": "Commonly Used Port\n**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as* TCP:80 (HTTP)* TCP:443 (HTTPS)* TCP:25 (SMTP)* TCP/UDP:53 (DNS)They may use the protocol associated with the port or a completely different protocol. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are * TCP/UDP:135 (RPC)* TCP/UDP:22 (SSH)* TCP/UDP:3389 (RDP)\n['command-and-control']",
      "metadata": {},
      "score": 0.86115015
    },
    {
      "chunk_id": "T1572_c0",
      "doc_id": "T1572",
      "source": "mitre",
      "text": "protocol tunneling adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection / network filtering and / or enable access to otherwise unreachable systems. tunneling involves explicitly encapsulating a protocol within another. this behavior may conceal malicious traffic by blending in with existing traffic and / or provide an outer layer of encryption ( similar to a vpn ). tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as smb, rdp, or other traffic that would be filtered by network appliances or not routed over the internet. there are various means to encapsulate a protocol within another protocol. for example, adversaries may perform ssh tunneling ( also known as ssh port forwarding ), which involves forwarding arbitrary data over an encrypted ssh tunnel. ( citation : ssh tunneling ) ( citation : sygnia abyss locker 2025 ) [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) may also be abused by adversaries during [ dynamic resolution ] ( https : / / attack. mitre. org / techniques / t1568 ). known as dns over https ( doh ), queries to resolve c2 infrastructure may be encapsulated within encrypted https packets. ( citation : bleepingcomp godlua jul19 ) adversaries may also leverage [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) in conjunction with [ proxy ] ( https : / / attack. mitre. org / techniques / t1090 ) and / or [ protocol or service impersonation ] ( https : / / attack. mitre. org / techniques / t1001 / 003 ) to further conceal c2 communications and infrastructure. ['command - and - control",
      "metadata": {},
      "score": 0.8506991
    },
    {
      "chunk_id": "T1071.002_c0",
      "doc_id": "T1071.002",
      "source": "mitre",
      "text": "File Transfer Protocols\nAdversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as SMB(Citation: US-CERT TA18-074A), FTP(Citation: ESET Machete July 2019), FTPS, and TFTP that transfer files may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the transferred files. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.\n['command-and-control']",
      "metadata": {},
      "score": 0.8484998
    },
    {
      "chunk_id": "T1048_c0",
      "doc_id": "T1048",
      "source": "mitre",
      "text": "Exfiltration Over Alternative Protocol\nAdversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) On macOS and Linux curl may be used to invoke protocols such as HTTP/S or FTP/S to exfiltrate data from a system.(Citation: 20 macOS Common Tools and Techniques)Many IaaS and SaaS platforms (such as Microsoft Exchange, Microsoft SharePoint, GitHub, and AWS S3) support the direct download of files, emails, source code, and other sensitive information via the web console or [Cloud API](https://attack.mitre.org/techniques/T1059/009).\n['exfiltration']",
      "metadata": {},
      "score": 0.8438008
    },
    {
      "chunk_id": "T1021_c1",
      "doc_id": "T1021",
      "source": "mitre",
      "text": "##nc ] ( https : / / attack. mitre. org / techniques / t1021 / 005 ) to send the screen and control buffers and [ ssh ] ( https : / / attack. mitre. org / techniques / t1021 / 004 ) for secure file transfer. ( citation : remote management mdm macos ) ( citation : kickstart apple remote desktop commands ) ( citation : apple remote desktop admin guide 3. 3 ) adversaries can abuse applications such as ard to gain remote code execution and perform lateral movement. in versions of macos prior to 10. 14, an adversary can escalate an ssh session to an ard session which enables an adversary to accept tcc ( transparency, consent, and control ) prompts without user interaction and gain access to data. ( citation : fireeye 2019 apple remote desktop ) ( citation : lockboxx ard 2019 ) ( citation : kickstart apple remote desktop commands ) ['lateral - movement']",
      "metadata": {},
      "score": 0.842754
    }
  ]
}
```

## Alert 3: PortScan

### Raw Packet Row

```json
{
  "destination_port": 34573,
  "flow_duration": 47,
  "total_fwd_packets": 1,
  "total_backward_packets": 1,
  "total_length_of_fwd_packets": 2,
  "total_length_of_bwd_packets": 6,
  "fwd_packet_length_max": 2,
  "fwd_packet_length_min": 2,
  "fwd_packet_length_mean": 2.0,
  "fwd_packet_length_std": 0.0,
  "bwd_packet_length_max": 6,
  "bwd_packet_length_min": 6,
  "bwd_packet_length_mean": 6.0,
  "bwd_packet_length_std": 0.0,
  "flow_bytes_s": 170212.766,
  "flow_packets_s": 42553.19149,
  "flow_iat_mean": 47.0,
  "flow_iat_std": 0.0,
  "flow_iat_max": 47,
  "flow_iat_min": 47,
  "fwd_iat_total": 0,
  "fwd_iat_mean": 0.0,
  "fwd_iat_std": 0.0,
  "fwd_iat_max": 0,
  "fwd_iat_min": 0,
  "bwd_iat_total": 0,
  "bwd_iat_mean": 0.0,
  "bwd_iat_std": 0.0,
  "bwd_iat_max": 0,
  "bwd_iat_min": 0,
  "fwd_psh_flags": 0,
  "bwd_psh_flags": 0,
  "fwd_urg_flags": 0,
  "bwd_urg_flags": 0,
  "fwd_header_length": 24,
  "bwd_header_length": 20,
  "fwd_packets_s": 21276.59574,
  "bwd_packets_s": 21276.59574,
  "min_packet_length": 2,
  "max_packet_length": 6,
  "packet_length_mean": 3.333333333,
  "packet_length_std": 2.309401077,
  "packet_length_variance": 5.333333333,
  "fin_flag_count": 0,
  "syn_flag_count": 0,
  "rst_flag_count": 0,
  "psh_flag_count": 1,
  "ack_flag_count": 0,
  "urg_flag_count": 0,
  "cwe_flag_count": 0,
  "ece_flag_count": 0,
  "down_up_ratio": 1,
  "average_packet_size": 5.0,
  "avg_fwd_segment_size": 2.0,
  "avg_bwd_segment_size": 6.0,
  "fwd_header_length.1": 24,
  "fwd_avg_bytes_bulk": 0,
  "fwd_avg_packets_bulk": 0,
  "fwd_avg_bulk_rate": 0,
  "bwd_avg_bytes_bulk": 0,
  "bwd_avg_packets_bulk": 0,
  "bwd_avg_bulk_rate": 0,
  "subflow_fwd_packets": 1,
  "subflow_fwd_bytes": 2,
  "subflow_bwd_packets": 1,
  "subflow_bwd_bytes": 6,
  "init_win_bytes_forward": 1024,
  "init_win_bytes_backward": 0,
  "act_data_pkt_fwd": 0,
  "min_seg_size_forward": 24,
  "active_mean": 0.0,
  "active_std": 0.0,
  "active_max": 0,
  "active_min": 0,
  "idle_mean": 0.0,
  "idle_std": 0.0,
  "idle_max": 0,
  "idle_min": 0,
  "label": "PortScan"
}
```

### Alert Text

```text
[ALERT] UNKNOWN traffic observed targeting destination port 34573. very short-lived flow (0.000s). relatively balanced bidirectional communication (1 forward vs 1 backward packets). high packet rate (42553.19 packets/s). moderate throughput (170212.77 bytes/s). very small average packet sizes. PSH packets observed without normal handshake behavior (PSH=1).
```

### RAG Response

```json
{
  "threat_description": "Unknown traffic observed targeting destination port 34573. Very short-lived flow with balanced bidirectional communication and high packet rate.",
  "severity": "Medium",
  "rationale": "The alert describes a short-lived, bidirectional flow of traffic targeting port 34573 with a high packet rate. The behavior is consistent with protocol tunneling or network sniffing techniques. However, the specific technique used cannot be determined without additional information.",
  "mitigation_steps": [
    "Monitor network traffic for any suspicious activity related to port 34573.",
    "Implement network segmentation to limit the impact of any potential compromise."
  ],
  "retrieved_context_ids": [
    "T1043_c0",
    "T1572_c0",
    "T1040_c0",
    "T1110.001_c0",
    "T1557.003_c0"
  ],
  "contexts": [
    {
      "chunk_id": "T1043_c0",
      "doc_id": "T1043",
      "source": "mitre",
      "text": "Commonly Used Port\n**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as* TCP:80 (HTTP)* TCP:443 (HTTPS)* TCP:25 (SMTP)* TCP/UDP:53 (DNS)They may use the protocol associated with the port or a completely different protocol. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are * TCP/UDP:135 (RPC)* TCP/UDP:22 (SSH)* TCP/UDP:3389 (RDP)\n['command-and-control']",
      "metadata": {},
      "score": 0.8647794
    },
    {
      "chunk_id": "T1572_c0",
      "doc_id": "T1572",
      "source": "mitre",
      "text": "protocol tunneling adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection / network filtering and / or enable access to otherwise unreachable systems. tunneling involves explicitly encapsulating a protocol within another. this behavior may conceal malicious traffic by blending in with existing traffic and / or provide an outer layer of encryption ( similar to a vpn ). tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as smb, rdp, or other traffic that would be filtered by network appliances or not routed over the internet. there are various means to encapsulate a protocol within another protocol. for example, adversaries may perform ssh tunneling ( also known as ssh port forwarding ), which involves forwarding arbitrary data over an encrypted ssh tunnel. ( citation : ssh tunneling ) ( citation : sygnia abyss locker 2025 ) [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) may also be abused by adversaries during [ dynamic resolution ] ( https : / / attack. mitre. org / techniques / t1568 ). known as dns over https ( doh ), queries to resolve c2 infrastructure may be encapsulated within encrypted https packets. ( citation : bleepingcomp godlua jul19 ) adversaries may also leverage [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) in conjunction with [ proxy ] ( https : / / attack. mitre. org / techniques / t1090 ) and / or [ protocol or service impersonation ] ( https : / / attack. mitre. org / techniques / t1001 / 003 ) to further conceal c2 communications and infrastructure. ['command - and - control",
      "metadata": {},
      "score": 0.8560239
    },
    {
      "chunk_id": "T1040_c0",
      "doc_id": "T1040",
      "source": "mitre",
      "text": "network sniffing adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. an adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. techniques for name service resolution poisoning, such as [ llmnr / nbt - ns poisoning and smb relay ] ( https : / / attack. mitre. org / techniques / t1557 / 001 ), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics ( e. g. ip addresses, hostnames, vlan ids ) necessary for subsequent [ lateral movement ] ( https : / / attack. mitre. org / tactics / ta0008 ) and / or [ defense evasion ] ( https : / / attack. mitre. org / tactics / ta0005 ) activities. adversaries may likely also utilize network sniffing during [ adversary - in - the - middle ] ( https : / / attack. mitre. org / techniques / t1557 ) ( aitm ) to passively gain additional knowledge about the environment. in cloud - based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. for example, aws traffic mirroring, gcp packet mirroring, and azure vtap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. ( citation : aws traffic mirroring ) ( citation",
      "metadata": {},
      "score": 0.85126024
    },
    {
      "chunk_id": "T1110.001_c0",
      "doc_id": "T1110.001",
      "source": "mitre",
      "text": "password guessing adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. an adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts. guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. ( citation : cylance cleaver ) typically, management services over commonly used ports are used when guessing passwords. commonly targeted services include the following : * ssh ( 22 / tcp ) * telnet ( 23 / tcp ) * ftp ( 21 / tcp ) * netbios / smb / samba ( 139 / tcp & 445 / tcp ) * ldap ( 389 / tcp ) * kerberos ( 88 / tcp ) * rdp / terminal services ( 3389 / tcp ) * http / http management services ( 80 / tcp & 443 / tcp ) * mssql ( 1433 / tcp ) * oracle ( 1521 / tcp ) * mysql ( 3306 / tcp ) * vnc ( 5900 / tcp ) * snmp ( 161 / udp and 162 / tcp / udp ) in addition to management services, adversaries may \" target single sign - on ( sso ) and cloud - based applications utilizing federated authentication protocols, \" as well as externally facing email applications, such as office 365. ( citation : us - cert ta18 - 068a 2018 ). further, advers",
      "metadata": {},
      "score": 0.84882724
    },
    {
      "chunk_id": "T1557.003_c0",
      "doc_id": "T1557.003",
      "source": "mitre",
      "text": "dhcp spoofing adversaries may redirect network traffic to adversary - owned systems by spoofing dynamic host configuration protocol ( dhcp ) traffic and acting as a malicious dhcp server on the victim network. by achieving the adversary - in - the - middle ( aitm ) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. this may also enable follow - on behaviors such as [ network sniffing ] ( https : / / attack. mitre. org / techniques / t1040 ) or [ transmitted data manipulation ] ( https : / / attack. mitre. org / techniques / t1565 / 002 ). dhcp is based on a client - server model and has two functionalities : a protocol for providing network configuration settings from a dhcp server to a client and a mechanism for allocating network addresses to clients. ( citation : rfc2131 ) the typical server - client interaction is as follows : 1. the client broadcasts a ` discover ` message. 2. the server responds with an ` offer ` message, which includes an available network address. 3. the client broadcasts a ` request ` message, which includes the network address offered. 4. the server acknowledges with an ` ack ` message and the client receives the network configuration parameters. adversaries may spoof as a rogue dhcp server on the victim network, from which legitimate hosts may receive malicious network configurations. for example, malware can act as a dhcp server and provide adversary - owned dns servers to the victimized computers. ( citation : new _ rogue _ dhcp _ serv _ malware ) ( citation : w32. tidserv. g ) through the malicious network configurations, an adversary may achieve the aitm position, route client traffic through adversary - controlled systems, and collect information from the client network. dhcpv6 clients can receive network configuration information without",
      "metadata": {},
      "score": 0.84746563
    }
  ]
}
```

## Alert 4: DoS Hulk

### Raw Packet Row

```json
{
  "destination_port": 80,
  "flow_duration": 55519,
  "total_fwd_packets": 3,
  "total_backward_packets": 6,
  "total_length_of_fwd_packets": 349,
  "total_length_of_bwd_packets": 11595,
  "fwd_packet_length_max": 349,
  "fwd_packet_length_min": 0,
  "fwd_packet_length_mean": 116.3333333,
  "fwd_packet_length_std": 201.4952439,
  "bwd_packet_length_max": 2907,
  "bwd_packet_length_min": 0,
  "bwd_packet_length_mean": 1932.5,
  "bwd_packet_length_std": 1496.914126,
  "flow_bytes_s": 215133.5579,
  "flow_packets_s": 162.1066662,
  "flow_iat_mean": 6939.875,
  "flow_iat_std": 15446.98703,
  "flow_iat_max": 44218,
  "flow_iat_min": 33,
  "fwd_iat_total": 10990,
  "fwd_iat_mean": 5495.0,
  "fwd_iat_std": 6382.345807,
  "fwd_iat_max": 10008,
  "fwd_iat_min": 982,
  "bwd_iat_total": 55477,
  "bwd_iat_mean": 11095.4,
  "bwd_iat_std": 19107.03602,
  "bwd_iat_max": 44218,
  "bwd_iat_min": 37,
  "fwd_psh_flags": 0,
  "bwd_psh_flags": 0,
  "fwd_urg_flags": 0,
  "bwd_urg_flags": 0,
  "fwd_header_length": 104,
  "bwd_header_length": 200,
  "fwd_packets_s": 54.0355554,
  "bwd_packets_s": 108.0711108,
  "min_packet_length": 0,
  "max_packet_length": 2907,
  "packet_length_mean": 1194.4,
  "packet_length_std": 1470.713523,
  "packet_length_variance": 2162998.267,
  "fin_flag_count": 0,
  "syn_flag_count": 0,
  "rst_flag_count": 0,
  "psh_flag_count": 1,
  "ack_flag_count": 0,
  "urg_flag_count": 0,
  "cwe_flag_count": 0,
  "ece_flag_count": 0,
  "down_up_ratio": 2,
  "average_packet_size": 1327.111111,
  "avg_fwd_segment_size": 116.3333333,
  "avg_bwd_segment_size": 1932.5,
  "fwd_header_length.1": 104,
  "fwd_avg_bytes_bulk": 0,
  "fwd_avg_packets_bulk": 0,
  "fwd_avg_bulk_rate": 0,
  "bwd_avg_bytes_bulk": 0,
  "bwd_avg_packets_bulk": 0,
  "bwd_avg_bulk_rate": 0,
  "subflow_fwd_packets": 3,
  "subflow_fwd_bytes": 349,
  "subflow_bwd_packets": 6,
  "subflow_bwd_bytes": 11595,
  "init_win_bytes_forward": 29200,
  "init_win_bytes_backward": 235,
  "act_data_pkt_fwd": 1,
  "min_seg_size_forward": 32,
  "active_mean": 0.0,
  "active_std": 0.0,
  "active_max": 0,
  "active_min": 0,
  "idle_mean": 0.0,
  "idle_std": 0.0,
  "idle_max": 0,
  "idle_min": 0,
  "label": "DoS Hulk"
}
```

### Alert Text

```text
[ALERT] UNKNOWN traffic observed targeting destination port 80 (HTTP). short-lived flow (0.056s). relatively balanced bidirectional communication (3 forward vs 6 backward packets). moderate packet rate (162.11 packets/s). moderate throughput (215133.56 bytes/s). large average packet sizes. PSH packets observed without normal handshake behavior (PSH=1).
```

### RAG Response

```json
{
  "threat_description": "Unknown traffic observed targeting destination port 80 (HTTP). Short-lived flow with relatively balanced bidirectional communication and moderate packet rate and throughput. Large average packet sizes. PSH packets observed without normal handshake behavior.",
  "severity": "Medium",
  "rationale": "The traffic appears to be using HTTP, which is a commonly used port for web communication. The use of PSH packets without normal handshake behavior suggests that the connection may be malicious or exploited. However, the short-lived flow and relatively balanced bidirectional communication suggest that this may be a legitimate connection. Without additional context, it is difficult to determine the severity of this threat.",
  "mitigation_steps": [
    "Monitor network traffic for any suspicious activity",
    "Implement intrusion detection and prevention systems (IDPS) to detect and block malicious traffic"
  ],
  "retrieved_context_ids": [
    "T1043_c0",
    "T1572_c0",
    "T1040_c0",
    "T1557.003_c0",
    "T1040_c1"
  ],
  "contexts": [
    {
      "chunk_id": "T1043_c0",
      "doc_id": "T1043",
      "source": "mitre",
      "text": "Commonly Used Port\n**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as* TCP:80 (HTTP)* TCP:443 (HTTPS)* TCP:25 (SMTP)* TCP/UDP:53 (DNS)They may use the protocol associated with the port or a completely different protocol. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are * TCP/UDP:135 (RPC)* TCP/UDP:22 (SSH)* TCP/UDP:3389 (RDP)\n['command-and-control']",
      "metadata": {},
      "score": 0.8641778
    },
    {
      "chunk_id": "T1572_c0",
      "doc_id": "T1572",
      "source": "mitre",
      "text": "protocol tunneling adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection / network filtering and / or enable access to otherwise unreachable systems. tunneling involves explicitly encapsulating a protocol within another. this behavior may conceal malicious traffic by blending in with existing traffic and / or provide an outer layer of encryption ( similar to a vpn ). tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as smb, rdp, or other traffic that would be filtered by network appliances or not routed over the internet. there are various means to encapsulate a protocol within another protocol. for example, adversaries may perform ssh tunneling ( also known as ssh port forwarding ), which involves forwarding arbitrary data over an encrypted ssh tunnel. ( citation : ssh tunneling ) ( citation : sygnia abyss locker 2025 ) [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) may also be abused by adversaries during [ dynamic resolution ] ( https : / / attack. mitre. org / techniques / t1568 ). known as dns over https ( doh ), queries to resolve c2 infrastructure may be encapsulated within encrypted https packets. ( citation : bleepingcomp godlua jul19 ) adversaries may also leverage [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) in conjunction with [ proxy ] ( https : / / attack. mitre. org / techniques / t1090 ) and / or [ protocol or service impersonation ] ( https : / / attack. mitre. org / techniques / t1001 / 003 ) to further conceal c2 communications and infrastructure. ['command - and - control",
      "metadata": {},
      "score": 0.8489959
    },
    {
      "chunk_id": "T1040_c0",
      "doc_id": "T1040",
      "source": "mitre",
      "text": "network sniffing adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. an adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. techniques for name service resolution poisoning, such as [ llmnr / nbt - ns poisoning and smb relay ] ( https : / / attack. mitre. org / techniques / t1557 / 001 ), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics ( e. g. ip addresses, hostnames, vlan ids ) necessary for subsequent [ lateral movement ] ( https : / / attack. mitre. org / tactics / ta0008 ) and / or [ defense evasion ] ( https : / / attack. mitre. org / tactics / ta0005 ) activities. adversaries may likely also utilize network sniffing during [ adversary - in - the - middle ] ( https : / / attack. mitre. org / techniques / t1557 ) ( aitm ) to passively gain additional knowledge about the environment. in cloud - based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. for example, aws traffic mirroring, gcp packet mirroring, and azure vtap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. ( citation : aws traffic mirroring ) ( citation",
      "metadata": {},
      "score": 0.84722465
    },
    {
      "chunk_id": "T1557.003_c0",
      "doc_id": "T1557.003",
      "source": "mitre",
      "text": "dhcp spoofing adversaries may redirect network traffic to adversary - owned systems by spoofing dynamic host configuration protocol ( dhcp ) traffic and acting as a malicious dhcp server on the victim network. by achieving the adversary - in - the - middle ( aitm ) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. this may also enable follow - on behaviors such as [ network sniffing ] ( https : / / attack. mitre. org / techniques / t1040 ) or [ transmitted data manipulation ] ( https : / / attack. mitre. org / techniques / t1565 / 002 ). dhcp is based on a client - server model and has two functionalities : a protocol for providing network configuration settings from a dhcp server to a client and a mechanism for allocating network addresses to clients. ( citation : rfc2131 ) the typical server - client interaction is as follows : 1. the client broadcasts a ` discover ` message. 2. the server responds with an ` offer ` message, which includes an available network address. 3. the client broadcasts a ` request ` message, which includes the network address offered. 4. the server acknowledges with an ` ack ` message and the client receives the network configuration parameters. adversaries may spoof as a rogue dhcp server on the victim network, from which legitimate hosts may receive malicious network configurations. for example, malware can act as a dhcp server and provide adversary - owned dns servers to the victimized computers. ( citation : new _ rogue _ dhcp _ serv _ malware ) ( citation : w32. tidserv. g ) through the malicious network configurations, an adversary may achieve the aitm position, route client traffic through adversary - controlled systems, and collect information from the client network. dhcpv6 clients can receive network configuration information without",
      "metadata": {},
      "score": 0.84609854
    },
    {
      "chunk_id": "T1040_c1",
      "doc_id": "T1040",
      "source": "mitre",
      "text": "##re. org / techniques / t1557 ) ( aitm ) to passively gain additional knowledge about the environment. in cloud - based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. for example, aws traffic mirroring, gcp packet mirroring, and azure vtap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. ( citation : aws traffic mirroring ) ( citation : gcp packet mirroring ) ( citation : azure virtual network tap ) often, much of this traffic will be in cleartext due to the use of tls termination at the load balancer level to reduce the strain of encrypting and decrypting traffic. ( citation : rhino security labs aws vpc traffic mirroring ) ( citation : specterops aws traffic mirroring ) the adversary can then use exfiltration techniques such as transfer data to cloud account in order to access the sniffed traffic. ( citation : rhino security labs aws vpc traffic mirroring ) on network devices, adversaries may perform network captures using [ network device cli ] ( https : / / attack. mitre. org / techniques / t1059 / 008 ) commands such as ` monitor capture `. ( citation : us - cert - ta18 - 106a ) ( citation : capture _ embedded _ packet _ on _ software ) ['credential - access'' discovery']",
      "metadata": {},
      "score": 0.8412627
    }
  ]
}
```

## Alert 5: Bot

### Raw Packet Row

```json
{
  "destination_port": 8080,
  "flow_duration": 82027,
  "total_fwd_packets": 4,
  "total_backward_packets": 3,
  "total_length_of_fwd_packets": 207,
  "total_length_of_bwd_packets": 134,
  "fwd_packet_length_max": 195,
  "fwd_packet_length_min": 0,
  "fwd_packet_length_mean": 51.75,
  "fwd_packet_length_std": 95.54187564,
  "bwd_packet_length_max": 128,
  "bwd_packet_length_min": 0,
  "bwd_packet_length_mean": 44.66666667,
  "bwd_packet_length_std": 72.23111056,
  "flow_bytes_s": 4157.167762,
  "flow_packets_s": 85.33775464,
  "flow_iat_mean": 13671.16667,
  "flow_iat_std": 32478.91356,
  "flow_iat_max": 79966,
  "flow_iat_min": 33,
  "fwd_iat_total": 82027,
  "fwd_iat_mean": 27342.33333,
  "fwd_iat_std": 46741.9539,
  "fwd_iat_max": 81314,
  "fwd_iat_min": 33,
  "bwd_iat_total": 80761,
  "bwd_iat_mean": 40380.5,
  "bwd_iat_std": 55982.35097,
  "bwd_iat_max": 79966,
  "bwd_iat_min": 795,
  "fwd_psh_flags": 0,
  "bwd_psh_flags": 0,
  "fwd_urg_flags": 0,
  "bwd_urg_flags": 0,
  "fwd_header_length": 92,
  "bwd_header_length": 72,
  "fwd_packets_s": 48.76443122,
  "bwd_packets_s": 36.57332342,
  "min_packet_length": 0,
  "max_packet_length": 195,
  "packet_length_mean": 42.625,
  "packet_length_std": 75.57576615,
  "packet_length_variance": 5711.696429,
  "fin_flag_count": 0,
  "syn_flag_count": 0,
  "rst_flag_count": 0,
  "psh_flag_count": 1,
  "ack_flag_count": 0,
  "urg_flag_count": 0,
  "cwe_flag_count": 0,
  "ece_flag_count": 0,
  "down_up_ratio": 0,
  "average_packet_size": 48.71428571,
  "avg_fwd_segment_size": 51.75,
  "avg_bwd_segment_size": 44.66666667,
  "fwd_header_length.1": 92,
  "fwd_avg_bytes_bulk": 0,
  "fwd_avg_packets_bulk": 0,
  "fwd_avg_bulk_rate": 0,
  "bwd_avg_bytes_bulk": 0,
  "bwd_avg_packets_bulk": 0,
  "bwd_avg_bulk_rate": 0,
  "subflow_fwd_packets": 4,
  "subflow_fwd_bytes": 207,
  "subflow_bwd_packets": 3,
  "subflow_bwd_bytes": 134,
  "init_win_bytes_forward": 8192,
  "init_win_bytes_backward": 237,
  "act_data_pkt_fwd": 3,
  "min_seg_size_forward": 20,
  "active_mean": 0.0,
  "active_std": 0.0,
  "active_max": 0,
  "active_min": 0,
  "idle_mean": 0.0,
  "idle_std": 0.0,
  "idle_max": 0,
  "idle_min": 0,
  "label": "Bot"
}
```

### Alert Text

```text
[ALERT] UNKNOWN traffic observed targeting destination port 8080. short-lived flow (0.082s). relatively balanced bidirectional communication (4 forward vs 3 backward packets). moderate packet rate (85.34 packets/s). moderate throughput (4157.17 bytes/s). very small average packet sizes. PSH packets observed without normal handshake behavior (PSH=1).
```

### RAG Response

```json
{
  "threat_description": "Unknown traffic observed targeting destination port 8080 with short-lived flow and relatively balanced bidirectional communication.",
  "severity": "Medium",
  "rationale": "The alert describes a short-lived flow of traffic targeting port 8080, which is commonly used for HTTP and HTTPS. The traffic appears to be bidirectional with moderate packet rate and throughput. PSH packets were observed without normal handshake behavior, indicating possible use of non-standard protocols or techniques. While the alert does not provide enough information to determine the specific attack technique, it suggests that an adversary may be attempting to bypass firewalls or network detection systems by using a commonly used port. The use of PSH packets without normal handshake behavior also indicates possible use of non-standard protocols or techniques.",
  "mitigation_steps": [
    "Implement network segmentation and access controls to limit the attack surface.",
    "Monitor network traffic for abnormal behavior, such as PSH packets without normal handshake behavior."
  ],
  "retrieved_context_ids": [
    "T1043_c0",
    "T1572_c0",
    "T1040_c0",
    "T1557.003_c0",
    "T1205.002_c0"
  ],
  "contexts": [
    {
      "chunk_id": "T1043_c0",
      "doc_id": "T1043",
      "source": "mitre",
      "text": "Commonly Used Port\n**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as* TCP:80 (HTTP)* TCP:443 (HTTPS)* TCP:25 (SMTP)* TCP/UDP:53 (DNS)They may use the protocol associated with the port or a completely different protocol. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are * TCP/UDP:135 (RPC)* TCP/UDP:22 (SSH)* TCP/UDP:3389 (RDP)\n['command-and-control']",
      "metadata": {},
      "score": 0.8672687
    },
    {
      "chunk_id": "T1572_c0",
      "doc_id": "T1572",
      "source": "mitre",
      "text": "protocol tunneling adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection / network filtering and / or enable access to otherwise unreachable systems. tunneling involves explicitly encapsulating a protocol within another. this behavior may conceal malicious traffic by blending in with existing traffic and / or provide an outer layer of encryption ( similar to a vpn ). tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as smb, rdp, or other traffic that would be filtered by network appliances or not routed over the internet. there are various means to encapsulate a protocol within another protocol. for example, adversaries may perform ssh tunneling ( also known as ssh port forwarding ), which involves forwarding arbitrary data over an encrypted ssh tunnel. ( citation : ssh tunneling ) ( citation : sygnia abyss locker 2025 ) [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) may also be abused by adversaries during [ dynamic resolution ] ( https : / / attack. mitre. org / techniques / t1568 ). known as dns over https ( doh ), queries to resolve c2 infrastructure may be encapsulated within encrypted https packets. ( citation : bleepingcomp godlua jul19 ) adversaries may also leverage [ protocol tunneling ] ( https : / / attack. mitre. org / techniques / t1572 ) in conjunction with [ proxy ] ( https : / / attack. mitre. org / techniques / t1090 ) and / or [ protocol or service impersonation ] ( https : / / attack. mitre. org / techniques / t1001 / 003 ) to further conceal c2 communications and infrastructure. ['command - and - control",
      "metadata": {},
      "score": 0.8576867
    },
    {
      "chunk_id": "T1040_c0",
      "doc_id": "T1040",
      "source": "mitre",
      "text": "network sniffing adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. an adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. techniques for name service resolution poisoning, such as [ llmnr / nbt - ns poisoning and smb relay ] ( https : / / attack. mitre. org / techniques / t1557 / 001 ), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics ( e. g. ip addresses, hostnames, vlan ids ) necessary for subsequent [ lateral movement ] ( https : / / attack. mitre. org / tactics / ta0008 ) and / or [ defense evasion ] ( https : / / attack. mitre. org / tactics / ta0005 ) activities. adversaries may likely also utilize network sniffing during [ adversary - in - the - middle ] ( https : / / attack. mitre. org / techniques / t1557 ) ( aitm ) to passively gain additional knowledge about the environment. in cloud - based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. for example, aws traffic mirroring, gcp packet mirroring, and azure vtap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. ( citation : aws traffic mirroring ) ( citation",
      "metadata": {},
      "score": 0.85172915
    },
    {
      "chunk_id": "T1557.003_c0",
      "doc_id": "T1557.003",
      "source": "mitre",
      "text": "dhcp spoofing adversaries may redirect network traffic to adversary - owned systems by spoofing dynamic host configuration protocol ( dhcp ) traffic and acting as a malicious dhcp server on the victim network. by achieving the adversary - in - the - middle ( aitm ) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. this may also enable follow - on behaviors such as [ network sniffing ] ( https : / / attack. mitre. org / techniques / t1040 ) or [ transmitted data manipulation ] ( https : / / attack. mitre. org / techniques / t1565 / 002 ). dhcp is based on a client - server model and has two functionalities : a protocol for providing network configuration settings from a dhcp server to a client and a mechanism for allocating network addresses to clients. ( citation : rfc2131 ) the typical server - client interaction is as follows : 1. the client broadcasts a ` discover ` message. 2. the server responds with an ` offer ` message, which includes an available network address. 3. the client broadcasts a ` request ` message, which includes the network address offered. 4. the server acknowledges with an ` ack ` message and the client receives the network configuration parameters. adversaries may spoof as a rogue dhcp server on the victim network, from which legitimate hosts may receive malicious network configurations. for example, malware can act as a dhcp server and provide adversary - owned dns servers to the victimized computers. ( citation : new _ rogue _ dhcp _ serv _ malware ) ( citation : w32. tidserv. g ) through the malicious network configurations, an adversary may achieve the aitm position, route client traffic through adversary - controlled systems, and collect information from the client network. dhcpv6 clients can receive network configuration information without",
      "metadata": {},
      "score": 0.85083055
    },
    {
      "chunk_id": "T1205.002_c0",
      "doc_id": "T1205.002",
      "source": "mitre",
      "text": "Socket Filters\nAdversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria.(Citation: haking9 libpcap network sniffing) Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with [Protocol Tunneling](https://attack.mitre.org/techniques/T1572).(Citation: exatrack bpf filters passive backdoors)(Citation: Leonardo Turla Penquin May 2020)Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`. Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.\n['defense-evasion' 'persistence' 'command-and-control']",
      "metadata": {},
      "score": 0.84666383
    }
  ]
}
```
