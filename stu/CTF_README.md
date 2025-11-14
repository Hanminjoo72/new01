# 🚨 CTF 대회용 취약한 쇼핑몰 웹 애플리케이션

## ⚠️ 경고

**이 애플리케이션은 의도적으로 취약하게 만들어졌습니다!**

- 교육 및 CTF(Capture The Flag) 대회 목적으로만 사용하세요
- 실제 프로덕션 환경에 절대 배포하지 마세요
- 격리된 환경(Docker, VM 등)에서만 실행하세요
- 외부 인터넷에 노출하지 마세요

---

## 📋 프로젝트 개요

이 프로젝트는 Spring MVC + MyBatis 기반의 쇼핑몰 웹 애플리케이션으로,
해킹 대회(CTF)를 위해 다양한 웹 취약점이 의도적으로 포함되어 있습니다.

### 기술 스택
- **Backend**: Spring Framework 4.0.4, Java 1.8
- **Database**: Oracle
- **View**: JSP, Tiles
- **Build**: Maven

---

## 🎯 포함된 취약점

### 1. SQL Injection (SQLi)
- 로그인 기능
- 검색 기능
- 상품 조회 기능

### 2. Command Injection
- 서버 관리 페이지 (ping 기능)
- OS 명령어 실행 가능

### 3. SSRF (Server-Side Request Forgery)
- URL 리다이렉션 기능
- 내부 네트워크 스캔 가능

### 4. XSS (Cross-Site Scripting)
- 게시판 (공지사항, QnA, FAQ)
- 사용자 입력 출력 부분

### 5. IDOR (Insecure Direct Object Reference)
- 주문 상세 조회
- 권한 검증 없음

### 6. Session Fixation
- 소셜 로그인
- 세션 ID 재생성 안함

### 7. File Upload Vulnerability
- 에디터 파일 업로드
- 파일 타입 검증 없음

**상세 내용은 `CTF_VULNERABILITIES.md` 파일을 참조하세요.**

---

## 🚀 설치 및 실행

### 사전 요구사항
- JDK 1.8
- Maven 3.x
- Oracle Database
- Apache Tomcat 7.x 이상

### 데이터베이스 설정

1. Oracle 데이터베이스 생성
2. 테이블 생성 (DDL 스크립트 실행)
3. `src/main/resources/config/spring/context-datasource.xml` 수정

```xml
<property name="url" value="jdbc:oracle:thin:@localhost:1521:XE"/>
<property name="username" value="your_username"/>
<property name="password" value="your_password"/>
```

### 빌드 및 실행

```bash
# 프로젝트 빌드
mvn clean install

# Tomcat에 배포
# target/stu.war 파일을 Tomcat의 webapps 디렉토리에 복사

# 또는 Maven Tomcat 플러그인 사용
mvn tomcat7:run
```

### 접속
```
http://localhost:8080/
```

---

## 🐳 Docker로 실행 (권장)

Docker를 사용하면 격리된 환경에서 안전하게 실행할 수 있습니다.

```bash
# Docker 이미지 빌드
docker build -t ctf-shoppingmall .

# 컨테이너 실행
docker run -d -p 8080:8080 --name ctf-app ctf-shoppingmall

# 네트워크 격리 (외부 인터넷 차단)
docker run -d -p 8080:8080 --network none --name ctf-app ctf-shoppingmall
```

---

## 🎮 CTF 대회 운영 가이드

### 1. 환경 준비

#### 격리된 네트워크 구성
```bash
# Docker 네트워크 생성
docker network create --internal ctf-network

# 컨테이너를 격리된 네트워크에 연결
docker run -d --network ctf-network -p 8080:8080 ctf-shoppingmall
```

#### 방화벽 설정
```bash
# 특정 IP 대역만 허용
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### 2. 플래그 설정

#### SQL Injection 플래그
```sql
-- 숨겨진 테이블 생성
CREATE TABLE SECRET_DATA (
    ID NUMBER PRIMARY KEY,
    FLAG VARCHAR2(100),
    HINT VARCHAR2(200)
);

INSERT INTO SECRET_DATA VALUES (1, 'FLAG{SQL_M4st3r_2024}', 'admin 테이블을 찾아보세요');
```

#### Command Injection 플래그
```bash
# 서버에 플래그 파일 생성
echo "FLAG{C0mm4nd_Pwn3r_2024}" > /tmp/flag_cmd.txt
chmod 644 /tmp/flag_cmd.txt
```

#### IDOR 플래그
```sql
-- 특정 주문에 플래그 포함
INSERT INTO ORDER_LIST (ORDER_NO, MEMBER_NO, ORDER_NAME, ORDER_PHONE) 
VALUES (999, 1, 'FLAG{1D0R_Hunt3r_2024}', '010-0000-0000');
```

### 3. 모니터링

#### 로그 수집
```bash
# 애플리케이션 로그
tail -f /var/log/tomcat/catalina.out

# 접근 로그
tail -f /var/log/tomcat/access.log
```

#### 이상 행위 탐지
- 과도한 요청 (DDoS)
- SQL Injection 시도 패턴
- 파일 업로드 시도

### 4. 자동 리셋

#### Cron으로 주기적 리셋
```bash
# 매 시간 컨테이너 재시작
0 * * * * docker restart ctf-app

# 데이터베이스 초기화 스크립트
0 * * * * /path/to/reset_database.sh
```

### 5. 점수 시스템

각 취약점별 점수 제안:
- SQL Injection: 100점
- Command Injection: 150점
- SSRF: 100점
- XSS: 50점
- IDOR: 80점
- Session Fixation: 70점
- File Upload: 120점

---

## 📝 주요 엔드포인트

### 공개 페이지
- `/main.do` - 메인 페이지
- `/loginForm.do` - 로그인 페이지
- `/joinForm.do` - 회원가입 페이지
- `/shop/openMainSearch.do` - 상품 검색

### 취약한 엔드포인트
- `/loginAction.do` - SQL Injection (로그인)
- `/checkPing.do` - Command Injection
- `/common/redirection.do` - SSRF
- `/my_detail.do` - IDOR
- `/ckeditor/fileupload.do` - File Upload

### 관리자 페이지
- `/admin/` - 관리자 메인
- `/admin/server.jsp` - 서버 관리 (Command Injection)

---

## 🔍 힌트 시스템

참가자들을 위한 힌트:

### Level 1 (쉬움)
- "로그인 페이지에서 특수문자를 입력해보세요"
- "검색 기능에서 SQL 쿼리를 시도해보세요"

### Level 2 (보통)
- "서버 관리 페이지를 찾아보세요"
- "주문 번호를 변경해보세요"

### Level 3 (어려움)
- "내부 네트워크를 스캔할 방법을 찾아보세요"
- "관리자의 쿠키를 탈취해보세요"

---

## 🛡️ 보안 권장사항 (학습용)

이 애플리케이션의 취약점을 수정하려면:

### SQL Injection 방어
```xml
<!-- 안전한 코드 -->
WHERE MEMBER_ID = #{MEMBER_ID}  <!-- PreparedStatement 사용 -->
```

### Command Injection 방어
```java
// 입력값 검증
if (!ping.matches("^[0-9.]+$")) {
    throw new IllegalArgumentException("Invalid IP");
}
```

### XSS 방어
```jsp
<!-- HTML 이스케이프 -->
<c:out value="${map.QNA_TITLE}"/>
```

### IDOR 방어
```java
// 세션 검증
if (!session.getAttribute("MEMBER_NO").equals(orderOwner)) {
    throw new UnauthorizedException();
}
```

---

## 📚 학습 자료

### 추천 도구
- **Burp Suite** - 웹 취약점 스캐닝
- **SQLMap** - SQL Injection 자동화
- **OWASP ZAP** - 웹 애플리케이션 보안 테스트

### 참고 자료
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)

---

## 🤝 기여

이 프로젝트는 교육 목적으로 만들어졌습니다.
새로운 취약점 추가나 개선 사항이 있다면 이슈를 등록해주세요.

---

## 📄 라이선스

이 프로젝트는 교육 목적으로만 사용할 수 있습니다.
상업적 사용이나 실제 서비스 배포는 금지됩니다.

---

## ⚖️ 법적 고지

- 이 애플리케이션은 승인된 CTF 대회 및 교육 환경에서만 사용하세요
- 무단으로 타인의 시스템을 공격하는 것은 불법입니다
- 모든 해킹 활동은 법적 허가를 받은 범위 내에서만 수행하세요

---

## 📞 문의

CTF 대회 운영이나 기술적 문의사항이 있으시면 이슈를 등록해주세요.

**Happy Hacking! 🎯**
