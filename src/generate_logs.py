
import datetime
import random

def generate_firewall_log(timestamp, src_ip, dst_ip, dst_port, action):
    return f"{timestamp} firewall-01 CEF:0|Security|Firewall|1.0|100|Traffic {action}|1|src={src_ip} dst={dst_ip} dpt={dst_port} act={action}"

def generate_web_access_log(timestamp, src_ip, url, status_code, user_agent):
    return f'{timestamp} webserver-01 {src_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {url} HTTP/1.1" {status_code} 1234 "-" "{user_agent}"'

def generate_auth_log(timestamp, username, src_ip, status):
    return f"{timestamp} auth-server-01 sshd[1234]: Invalid user {username} from {src_ip}" if status == "FAILED" \
        else f"{timestamp} auth-server-01 sshd[1234]: Accepted password for {username} from {src_ip} port 12345 ssh2"

def generate_dns_log(timestamp, src_ip, domain):
    return f"{timestamp} dns-server-01 dnsmasq[5678]: query[{random.randint(1, 100)}] {domain} from {src_ip}"

def generate_simulated_logs(num_entries=100):
    log_entries = []
    start_time = datetime.datetime.now() - datetime.timedelta(days=7)

    # Example IOCs (Indicators of Compromise)
    malicious_ips = ["1.2.3.4", "5.6.7.8", "10.0.0.1"]
    malicious_domains = ["bad-domain.com", "phishing-site.net"]
    suspicious_urls = ["/malware/payload.exe", "/admin/backdoor.php"]
    brute_force_users = ["admin", "root", "test"]

    for i in range(num_entries):
        current_time = start_time + datetime.timedelta(minutes=i*10)
        timestamp_str = current_time.strftime("%b %d %H:%M:%S")

        log_type = random.choice(["firewall", "web", "auth", "dns"])

        if log_type == "firewall":
            src_ip = f"192.168.1.{random.randint(100, 200)}"
            dst_ip = random.choice(malicious_ips + [f"203.0.113.{random.randint(1, 254)}"])
            dst_port = random.choice([80, 443, 22, 23, 3389, 8080])
            action = "DENY" if dst_ip in malicious_ips else "ACCEPT"
            log_entries.append(generate_firewall_log(timestamp_str, src_ip, dst_ip, dst_port, action))
        elif log_type == "web":
            src_ip = f"192.168.1.{random.randint(100, 200)}"
            url = random.choice(suspicious_urls + ["/index.html", "/about.html"])
            status_code = 404 if url in suspicious_urls else 200
            user_agent = random.choice(["Mozilla/5.0", "BadBot/1.0"])
            log_entries.append(generate_web_access_log(current_time, src_ip, url, status_code, user_agent))
        elif log_type == "auth":
            src_ip = f"192.168.1.{random.randint(100, 200)}"
            username = random.choice(brute_force_users + ["user1", "user2"])
            status = "FAILED" if username in brute_force_users and random.random() < 0.7 else "SUCCESS"
            log_entries.append(generate_auth_log(timestamp_str, username, src_ip, status))
        elif log_type == "dns":
            src_ip = f"192.168.1.{random.randint(100, 200)}"
            domain = random.choice(malicious_domains + ["google.com", "microsoft.com"])
            log_entries.append(generate_dns_log(timestamp_str, src_ip, domain))

    return log_entries

if __name__ == "__main__":
    logs = generate_simulated_logs(num_entries=500) # Generate 500 log entries
    with open("security_events.log", "w") as f:
        for log in logs:
            f.write(log + "\n")
    print("Generated security_events.log with 500 entries.")


