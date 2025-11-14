package stu.member.login;

import java.util.Map;
import java.util.Random;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import stu.common.common.CommandMap;
import stu.member.join.JoinService;

@Controller
public class LoginController {

	Logger log = Logger.getLogger(this.getClass());

	@Resource(name = "loginService")
	private LoginService loginService;

	@Resource(name = "joinService")
	private JoinService joinService;


	@RequestMapping(value = "/loginForm.do")
	public ModelAndView loginForm(CommandMap commandMap) throws Exception {
		ModelAndView mv = new ModelAndView("login/loginForm");

		return mv;
	}

	// 로그인 이후 메인페이지 이동
	// VULNERABLE: SQL Injection 취약점 - 서버측 비밀번호 검증 제거 (CTF용)
	@RequestMapping(value = "/loginAction.do", method = RequestMethod.POST)
	public ModelAndView loginAction(CommandMap commandMap, HttpServletRequest request) throws Exception {
		ModelAndView mv = new ModelAndView();
		HttpSession session = request.getSession();

		// 디버깅: 입력값 확인
		System.out.println("=== LOGIN DEBUG ===");
		System.out.println("MEMBER_ID: " + commandMap.get("MEMBER_ID"));
		System.out.println("MEMBER_PASSWD: " + commandMap.get("MEMBER_PASSWD"));
		
		Map<String, Object> chk = loginService.loginAction(commandMap.getMap());
		
		// 디버깅: 쿼리 결과 확인
		System.out.println("Query Result: " + chk);
		System.out.println("==================");

		if (chk == null) {
			mv.setViewName("login/loginForm");
			mv.addObject("message", "해당 아이디 혹은 비밀번호가 일치하지 않습니다.");
			return mv;
		} else {
			if (chk.get("MEMBER_DELETE").equals("1")) {
				mv.setViewName("login/loginForm");
				mv.addObject("message", "탈퇴한 회원 입니다.");
			} else {
				// 비밀번호 검증 제거 - SQL에서만 체크
				session.setAttribute("SESSION_ID", chk.get("MEMBER_ID"));
				session.setAttribute("SESSION_NO", chk.get("MEMBER_NO"));
				session.setAttribute("SESSION_NAME", chk.get("MEMBER_NAME"));
				
	            // ✨ 추가 1: MEMBER_GRADE를 세션에 저장합니다.
				session.setAttribute("SESSION_GRADE", chk.get("MEMBER_GRADE")); 

				String memberGrade = (String) chk.get("MEMBER_GRADE");

	            // ✨ 추가 2: 회원 등급에 따라 리다이렉트 경로를 분기합니다.
				if ("ADMIN".equals(memberGrade)) {
					// ADMIN 등급이면 관리자 페이지로 리다이렉트
					mv = new ModelAndView("redirect:/adminEventList.do"); 
				} else {
					// 일반 등급이면 메인 페이지로 리다이렉트
					mv = new ModelAndView("redirect:/main.do");
				}
				
				mv.addObject("MEMBER", chk);

				session.getMaxInactiveInterval();
			}
			return mv;
		}
	}
	// 소셜로그인 이후 메인페이지 이동
	// VULNERABLE: Session Fixation 취약점 - 로그인 시 세션 ID 재생성 안함 (CTF용)
	@RequestMapping(value = "/socialLoginAction.do", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> googleLoginAction(@RequestBody Map<String, Object> map, HttpServletRequest request)
			throws Exception {

		HttpSession session = request.getSession();
		// 취약점: 로그인 시 session.invalidate() 후 새 세션 생성하지 않음

		session.setAttribute("SESSION_ID", map.get("ID"));
		session.setAttribute("SESSION_NO", map.get("ID"));
		session.setAttribute("SESSION_NAME", map.get("Name"));

		session.getMaxInactiveInterval();

		String url = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
				+ request.getContextPath() + "/main.do";
		map.put("URL", url);

		return map;
	}

	// 네이버 로그인 Callback 페이지
	@RequestMapping(value = "/loginCallback.do")
	public ModelAndView loginCallback(CommandMap commandMap) throws Exception {
		ModelAndView mv = new ModelAndView("/loginCallback");

		return mv;
	}

	// 로그아웃
	@RequestMapping(value = "/logout.do", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> logout(HttpServletRequest request, @RequestBody Map<String, Object> map) throws Exception {

		HttpSession session = request.getSession(false);
		if (session != null) session.invalidate();

		String url = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
				+ request.getContextPath() + "/main.do";
		map.put("URL", url);

		return map;
	}

	// 아이디 찾기 폼
	@RequestMapping(value = "/findId.do")
	public ModelAndView findId(CommandMap commandMap) throws Exception {
		ModelAndView mv = new ModelAndView("login/findId");

		return mv;
	}

	// 아이디 찾기
	@RequestMapping(value = "/findIdAction.do", method = RequestMethod.POST)
	public String selectSearchMyId(HttpSession session, CommandMap commandMap, RedirectAttributes ra) throws Exception {
		String email = (String) commandMap.get("MEMBER_EMAIL");
		Map<String, Object> map = loginService.selectFindId(commandMap.getMap());
		if (map == null) {
			ra.addFlashAttribute("resultMsg", "입력된 정보가 일치하지 않습니다.");
			return "redirect:/findId.do";
		}
		String user_name = (String) map.get("MEMBER_NAME");
		String user = (String) map.get("MEMBER_ID");

		String subject = "<JM COLLECTION>" + user_name + "님, 아이디 찾기 결과 입니다.";
		StringBuilder sb = new StringBuilder();
		sb.append("귀하의 아이디는 " + user + " 입니다.");
//		joinService.send(subject, sb.toString(), "1teampjt@gmail.com", email, null);
		ra.addFlashAttribute("resultMsg", "귀하의 아이디는 " + user + " 입니다.");
		ra.addFlashAttribute("isResult", "1");

		return "redirect:/findId.do";
	}

	// 비밀번호 초기화 폼
	@RequestMapping(value = "/findPw.do")
	public ModelAndView findPw(CommandMap commandMap) throws Exception {
		ModelAndView mv = new ModelAndView("login/findPw");

		return mv;
	}

	// 비밀번호 초기화
	@RequestMapping(value = "/findPwAction.do", method = RequestMethod.POST)
	public String sendMailPassword(HttpSession session, CommandMap commandMap, RedirectAttributes ra) throws Exception {
		String email = (String) commandMap.get("MEMBER_EMAIL");
		String user = loginService.selectFindPw(commandMap.getMap());

		if (user == null) {
			ra.addFlashAttribute("resultMsg", "입력된 정보가 일치하지 않습니다.");
			return "redirect:/findPw.do";
		}

		int ran = new Random().nextInt(100000) + 10000;
		String password = String.valueOf(ran);

		commandMap.put("MEMBER_PASSWD", password);
		loginService.updatePw(commandMap.getMap());

		String subject = "<JM COLLECTION>임시 비밀번호입니다.";
		StringBuilder sb = new StringBuilder();
		sb.append("귀하의 임시 비밀번호는 " + password + " 입니다. 로그인 후 패스워드를 변경해 주세요.");
//		joinService.send(subject, sb.toString(), "1teampjt@gmail.com", email, null);
		ra.addFlashAttribute("resultMsg", "귀하의 임시 비밀번호는 " + password + " 입니다.");
		ra.addFlashAttribute("isResult", "1");

		return "redirect:/findPw.do";
	}
}
