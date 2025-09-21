import re
import requests

# ===== CONFIG =====
VIRUSTOTAL_API_KEY = "8a7c9988988kk0768ca643f098980ojkjku800tffggfgf789002"
LOG_FILE = "access.log"

# ===== FUNCTIONS =====
def read_logs(file_path):
    """Read and return log lines from a file."""
    with open(file_path, 'r') as file:
        return file.readlines()

def extract_ips(log_lines):
    """Extract IP addresses from log lines using regex."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = set(re.findall(ip_pattern, "\n".join(log_lines)))
    return list(ips)

def vt_ip_lookup(ip):
    """Query VirusTotal for IP reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return malicious_count
    else:
        return None

# ===== MAIN SCRIPT =====
if __name__ == "__main__":
    print("[*] Reading logs...")
    logs = read_logs(LOG_FILE)

    print("[*] Extracting IP addresses...")
    ip_list = extract_ips(logs)
    print(f"[+] Found {len(ip_list)} unique IPs")

    print("[*] Checking IPs on VirusTotal...")
    for ip in ip_list:
        malicious = vt_ip_lookup(ip)
        if malicious is not None:
            print(f"{ip} → Malicious Reports: {malicious}")
        else:
            print(f"{ip} → Lookup failed.")
