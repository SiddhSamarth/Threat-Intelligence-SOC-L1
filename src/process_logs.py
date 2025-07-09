
import re
import random

def simulate_virustotal_lookup(ioc_value, ioc_type):
    # Simulate VirusTotal lookup for IPs, domains, and URLs
    malicious_indicators = {
        "ip": ["1.2.3.4", "5.6.7.8", "10.0.0.1"],
        "domain": ["bad-domain.com", "phishing-site.net"],
        "url": ["/malware/payload.exe", "/admin/backdoor.php"]
    }
    if ioc_type in malicious_indicators and ioc_value in malicious_indicators[ioc_type]:
        return {"reputation": "malicious", "source": "VirusTotal", "detections": random.randint(5, 70)}
    elif random.random() < 0.05: # 5% chance of being suspicious/unknown
        return {"reputation": "suspicious", "source": "VirusTotal", "detections": random.randint(1, 4)}
    else:
        return {"reputation": "clean", "source": "VirusTotal", "detections": 0}

def simulate_abuseipdb_lookup(ip_address):
    # Simulate AbuseIPDB lookup for IP addresses
    malicious_ips = ["1.2.3.4", "5.6.7.8", "10.0.0.1"]
    if ip_address in malicious_ips:
        return {"reputation": "malicious", "source": "AbuseIPDB", "reports": random.randint(10, 500), "confidence": random.randint(70, 100)}
    elif random.random() < 0.03: # 3% chance of being reported
        return {"reputation": "reported", "source": "AbuseIPDB", "reports": random.randint(1, 9), "confidence": random.randint(10, 60)}
    else:
        return {"reputation": "clean", "source": "AbuseIPDB", "reports": 0, "confidence": 0}

def extract_iocs(log_entry):
    iocs = {"ips": [], "domains": [], "urls": []}

    # Extract IPs (src= and dst= in firewall logs, or just IPs in other logs)
    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_entry)
    iocs["ips"].extend(ip_matches)

    # Extract domains (from dns logs or URLs)
    domain_matches = re.findall(r'query\[\d+\]\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', log_entry)
    iocs["domains"].extend(domain_matches)

    # Extract URLs (from web access logs)
    url_matches = re.findall(r'"GET\s+(\/[^\s]+)\s+HTTP', log_entry)
    iocs["urls"].extend(url_matches)

    return iocs

def process_security_logs(log_file_path):
    processed_logs = []
    with open(log_file_path, "r") as f:
        for line in f:
            log_entry = line.strip()
            iocs = extract_iocs(log_entry)
            enriched_data = {}

            for ip in set(iocs["ips"]):
                vt_result = simulate_virustotal_lookup(ip, "ip")
                apdb_result = simulate_abuseipdb_lookup(ip)
                enriched_data[ip] = {"virustotal": vt_result, "abuseipdb": apdb_result}

            for domain in set(iocs["domains"]):
                vt_result = simulate_virustotal_lookup(domain, "domain")
                enriched_data[domain] = {"virustotal": vt_result}

            for url in set(iocs["urls"]):
                vt_result = simulate_virustotal_lookup(url, "url")
                enriched_data[url] = {"virustotal": vt_result}

            processed_logs.append({"original_log": log_entry, "iocs": iocs, "enriched_data": enriched_data})
    return processed_logs

if __name__ == "__main__":
    logs = process_security_logs("security_events.log")
    # You can now iterate through 'logs' to see the original log, extracted IOCs, and their simulated enrichment
    # For demonstration, let's print a few examples
    for i, log_entry in enumerate(logs):
        if i < 10 or (i > 200 and i < 210) or (i > 400 and i < 410): # Print first 10, and some in middle and end
            print(f"\n--- Log Entry {i+1} ---")
            print(f"Original: {log_entry['original_log']}")
            print(f"Extracted IOCs: {log_entry['iocs']}")
            print(f"Enriched Data: {log_entry['enriched_data']}")

    # Save processed logs to a file for later analysis
    import json
    with open("processed_security_events.json", "w") as f:
        json.dump(logs, f, indent=4)
    print("\nProcessed logs saved to processed_security_events.json")


