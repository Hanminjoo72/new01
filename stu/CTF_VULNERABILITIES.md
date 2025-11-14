# CTF 대회용 취약점 목록

이 문서는 해킹 대회(CTF)를 위해 의도적으로 추가된 취약점들을 설명합니다.

⚠️ **경고**: 이 애플리케이션은 교육 및 CTF 대회 목적으로만 사용해야 합니다. 
실제 프로덕션 환경에서는 절대 사용하지 마세요!

---

## 1. SQL Injection (SQLi)

### 위치
- **파일**: `src/main/resources/mapper/login/login_SQL.xml`
- **라인**: 59-78

### 취약점 설명
로그인 쿼리에서 파라미터 바인딩(`#{}`) 대신 문자열 치환(`${}`)을 사용하여 SQL Injection 공격이 가능합니다.

```xml
<!-- VULNERABLE CODE -->
SELECT * FROM MEMBER 
WHERE MEMBER_ID = '${MEMBER_ID}'
AND MEMBER_PASSWD = '${MEMBER_PASSWD}'
```

### 공격 예시
```
ID: admin' OR '1'='1' --
PW: anything
```

### 추가 취약점
- **파일**: `src/main/java/stu/member/login/LoginController.java` (라인 42-71)
- 서버측 비밀번호 검증이 제거되어 SQL Injection이 더 쉽게 성공합니다.

### 검색 기능 SQLi
- **파일**: `src/main/resources/mapper/goods/Goods_SQL.xml` (라인 120)
- 검색 키워드에서도 `${keyword}` 사용으로 SQLi 가능

---

## 2. Command Injection (OS Command Injection)

### 위치
- **파일**: `src/main/java/stu/commom/controller/CommonController.java`
- **라인**: 69-106

### 취약점 설명
사용자 입력값을 검증 없이 시스템 명령어로 실행합니다.

```java
// VULNERABLE CODE
String ping = req.getParameter("ping");
if(ping != null && !ping.isEmpty()) {
    check = "ping -c 4 " + ping;
}
String [] cmd = {"/bin/sh","-c",check};
process = Runtime.getRuntime().exec(cmd);
```

### 공격 예시
```
URL: /checkPing.do?ping=127.0.0.1; cat /etc/passwd
URL: /checkPing.do?ping=127.0.0.1 && whoami
URL: /checkPing.do?check=cat /etc/passwd
```

---

## 3. SSRF (Server-Side Request Forgery)

### 위치
- **파일**: `src/main/java/stu/commom/controller/CommonController.java`
- **라인**: 50-70

### 취약점 설명
URL 파라미터를 검증 없이 서버에서 요청하여 내부 네트워크 스캔이 가능합니다.

```java
// VULNERABLE CODE
String req_url = req.getParameter("url");
URL url = new URL(req_url);
HttpURLConnection conn = (HttpURLConnection)url.openConnection();
```

### 공격 예시
```
URL: /common/redirection.do?url=http://localhost:8080/admin
URL: /common/redirection.do?url=http://169.254.169.254/latest/meta-data/
URL: /common/redirection.do?url=file:///etc/passwd
```

---

## 4. XSS (Cross-Site Scripting)

### 위치
- **파일**: `src/main/webapp/WEB-INF/views/board/qnaDetail.jsp`
- **라인**: 67-68, 72-73, 78-80

### 취약점 설명
사용자 입력값을 HTML 이스케이프 없이 출력하여 XSS 공격이 가능합니다.

```jsp
<!-- VULNERABLE CODE -->
<td colspan="3" align="left">${map.QNA_TITLE}</td>
<td colspan="4" align="left">${map.QNA_CONTENT}</td>
<td colspan="4" align="left">${map.QNA_AN}</td>
```

### 공격 예시
```html
제목: <script>alert('XSS')</script>
내용: <img src=x onerror="alert(document.cookie)">
답변: <svg onload="alert('XSS')">
```

### 추가 취약 페이지
- `noticeDetail.jsp` (공지사항)
- `faqDetail.jsp` (FAQ)
- 모든 게시판 상세 페이지

---

## 5. IDOR (Insecure Direct Object Reference)

### 위치
- **파일**: `src/main/java/stu/member/my/MyOrderController.java`
- **라인**: 224-242

### 취약점 설명
세션 검증 없이 order_no만으로 다른 사용자의 주문 정보를 조회할 수 있습니다.

```java
// VULNERABLE CODE
@RequestMapping(value = "/my_detail.do")
public ModelAndView my_detail(CommandMap commandMap, HttpServletRequest request) {
    String order_no = request.getParameter("order_no");
    // 세션 검증 없음!
    List<Map<String, Object>> my_detail = adminMainService.order_detail(commandMap);
}
```

### 공격 예시
```
URL: /my_detail.do?order_no=1
URL: /my_detail.do?order_no=2
URL: /my_detail.do?order_no=3
... (순차적으로 증가시켜 다른 사용자 주문 정보 열람)
```

---

## 6. Session Fixation

### 위치
- **파일**: `src/main/java/stu/member/login/LoginController.java`
- **라인**: 73-95

### 취약점 설명
로그인 시 세션 ID를 재생성하지 않아 세션 고정 공격이 가능합니다.

```java
// VULNERABLE CODE
HttpSession session = request.getSession();
// session.invalidate() 호출 없음!
session.setAttribute("SESSION_ID", map.get("ID"));
```

### 공격 시나리오
1. 공격자가 세션 ID를 얻음
2. 피해자에게 해당 세션 ID로 로그인하도록 유도
3. 피해자가 로그인하면 공격자도 같은 세션으로 접근 가능

---

## 7. File Upload Vulnerability

### 위치
- **파일**: `src/main/java/stu/commom/controller/EditorContorller.java`
- **라인**: 30-96

### 취약점 설명
파일 타입 검증이 주석 처리되어 있어 모든 파일 업로드가 가능합니다.

```java
// VULNERABLE CODE
if(file.getSize() > 0 && StringUtils.isNotBlank(file.getName())){
    //VULNERABLE: 파일 타입 검증이 주석 처리됨
    //if(file.getContentType().toLowerCase().startsWith("image/")){
        String fileName = file.getOriginalFilename();
        // 파일 저장...
}
```

### 공격 예시
- JSP 웹쉘 업로드
- PHP 웹쉘 업로드 (서버 환경에 따라)
- 악성 스크립트 파일 업로드

```
POST /ckeditor/fileupload.do
Content-Type: multipart/form-data

upload=webshell.jsp (내용: JSP 웹쉘 코드)
```

---

## 추가 보안 이슈

### 1. 평문 비밀번호 저장
- 비밀번호가 해시 없이 평문으로 저장됨
- SQL Injection 성공 시 모든 비밀번호 노출

### 2. 에러 메시지 노출
- 상세한 에러 메시지가 사용자에게 노출됨
- 시스템 정보 유출 가능

### 3. 디렉토리 리스팅
- 파일 업로드 디렉토리에 접근 가능할 수 있음

---

## CTF 플래그 숨기기 제안

### 플래그 1 (SQL Injection)
데이터베이스의 숨겨진 테이블이나 컬럼에 플래그 저장
```sql
CREATE TABLE SECRET_FLAGS (FLAG VARCHAR2(100));
INSERT INTO SECRET_FLAGS VALUES ('FLAG{SQL_1nj3ct10n_M4st3r}');
```

### 플래그 2 (Command Injection)
서버의 특정 파일에 플래그 저장
```bash
echo "FLAG{C0mm4nd_1nj3ct10n_Pwn3d}" > /tmp/flag2.txt
```

### 플래그 3 (SSRF)
내부 서비스(예: localhost:8080/admin/flag)에서만 접근 가능한 플래그

### 플래그 4 (XSS)
관리자 쿠키에 플래그 저장 (XSS로 탈취)

### 플래그 5 (IDOR)
특정 주문 번호(예: order_no=999)에 플래그 포함

### 플래그 6 (File Upload)
웹쉘 업로드 후 서버의 특정 위치에서 플래그 읽기

---

## 안전한 운영 가이드

1. **격리된 환경에서만 실행**
   - Docker 컨테이너 사용 권장
   - 네트워크 격리 (외부 인터넷 접근 차단)

2. **방화벽 설정**
   - 대회 참가자만 접근 가능하도록 IP 제한

3. **모니터링**
   - 로그 수집 및 모니터링
   - 비정상적인 활동 감지

4. **자동 리셋**
   - 일정 시간마다 컨테이너 재시작
   - 데이터베이스 초기화

5. **백업**
   - 초기 상태 스냅샷 보관
   - 빠른 복구 가능하도록 준비

---

## 면책 조항

이 애플리케이션의 취약점은 교육 목적으로 의도적으로 만들어졌습니다.
실제 환경에서 이러한 취약점을 악용하는 것은 불법이며, 
오직 승인된 CTF 대회 환경에서만 사용해야 합니다.

작성일: 2024
목적: 해킹 대회(CTF) 교육용
