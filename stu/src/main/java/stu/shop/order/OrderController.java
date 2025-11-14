package stu.shop.order;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import stu.common.common.CommandMap;
import stu.shop.basket.BasketService;

@Controller
public class OrderController {
	
	Logger log = Logger.getLogger(this.getClass()); //로그
	/*
	 * @Resource(name="orderService") private OrderService orderService;
	 */
	@Resource(name="basketService")
	private BasketService basketService;
	
	@Resource(name="orderService")
	private OrderService orderService;
	
	
	//장바구니 모두구매
	@RequestMapping(value="/order/basketAllOrderWrite.do")
	public ModelAndView basketAllOrderSelect(CommandMap commandMap, HttpServletRequest request) throws Exception {
		
		ModelAndView mv = new ModelAndView("order/orderWrite");
		Object MEMBER_NO = ""; //세션값 가져오기 
		HttpSession session = request.getSession(); 
		MEMBER_NO = (Object)session.getAttribute("SESSION_NO"); 
		commandMap.remove("MEMBER_NO"); // 기존 회원번호 데이터 삭제 
		commandMap.put("MEMBER_NO", MEMBER_NO); // 세션 값으로 적용
		List<Map<String,Object>> list = basketService.basketList(commandMap);
		Map<String,Object> map = orderService.orderMemberInfo(commandMap, request);
		List<Map<String,Object>> list2 = orderService.memberCoupon(commandMap);
		mv.addObject("list", list);
		mv.addObject("list2", list2);
		mv.addObject("map", map);
		System.out.println(list);
		System.out.println(map);
		System.out.println(list2);
		return mv;
	}
	
	//장바구니 선택상품 구매
	@RequestMapping(value="/order/basketSelectOrder.do")
	public ModelAndView basketSelect(CommandMap commandMap, HttpServletRequest request) throws Exception {
		
		ModelAndView mv = new ModelAndView("order/orderWrite");
		Object MEMBER_NO = ""; //세션값 가져오기 
		HttpSession session = request.getSession(); 
		MEMBER_NO = (Object)session.getAttribute("SESSION_NO"); 
		commandMap.remove("MEMBER_NO"); // 기존 회원번호 데이터 삭제 
		commandMap.put("MEMBER_NO", MEMBER_NO); // 세션 값으로 적용
		List<Map<String,Object>> list = basketService.basketSelectList(commandMap, request); //선택한 장바구니번호의 상품 
		Map<String,Object> map = orderService.orderMemberInfo(commandMap, request); //주문자정보
		List<Map<String,Object>> list2 = orderService.memberCoupon(commandMap); //주문자 쿠폰내역
		mv.addObject("list", list);
		mv.addObject("map", map);
		mv.addObject("list2", list2);
		System.out.println(list);
		System.out.println(map);
		System.out.println(list2);
		return mv;
	}
	
	//상품 주문완료(결제)
	@RequestMapping(value="/order/orderPay.do")
	public ModelAndView orderPay(CommandMap commandMap, HttpServletRequest request) throws Exception {
		ModelAndView mv = new ModelAndView("order/orderFinish");
			
		        Object MEMBER_NO = ""; //세션값 가져오기 
        HttpSession session = request.getSession(); 
        MEMBER_NO = (Object)session.getAttribute("SESSION_NO"); 
        commandMap.remove("MEMBER_NO"); // 기존 회원번호 데이터 삭제 
        commandMap.put("MEMBER_NO", MEMBER_NO); // 세션 값으로 적용 
        // 서버단 필수값 보정: 빈 문자열(Oracle에서는 NULL로 처리)일 경우 회원정보로 채움
        Map<String,Object> memberInfo = orderService.orderMemberInfo(commandMap, request);
        if (memberInfo == null) {
            memberInfo = new HashMap<String, Object>();
        }
        Object on = commandMap.get("ORDER_NAME");
        if (on == null || on.toString().trim().isEmpty()) {
            commandMap.put("ORDER_NAME", memberInfo.get("MEMBER_NAME"));
        }
        // 여전히 비어있으면 최소 대체값으로 설정(Oracle '' -> NULL 방지)
        if (commandMap.get("ORDER_NAME") == null || commandMap.get("ORDER_NAME").toString().trim().isEmpty()) {
            commandMap.put("ORDER_NAME", "-");
        }
        Object op = commandMap.get("ORDER_PHONE");
        if (op == null || op.toString().trim().isEmpty()) {
            commandMap.put("ORDER_PHONE", memberInfo.get("MEMBER_PHONE"));
        }
        if (commandMap.get("ORDER_PHONE") == null || commandMap.get("ORDER_PHONE").toString().trim().isEmpty()) {
            commandMap.put("ORDER_PHONE", "0");
        }
        Object oz = commandMap.get("ORDER_ZIPCODE");
        if (oz == null || oz.toString().trim().isEmpty()) {
            commandMap.put("ORDER_ZIPCODE", memberInfo.get("MEMBER_ZIPCODE"));
        }
        if (commandMap.get("ORDER_ZIPCODE") == null || commandMap.get("ORDER_ZIPCODE").toString().trim().isEmpty()) {
            commandMap.put("ORDER_ZIPCODE", "0");
        }
        Object oa1 = commandMap.get("ORDER_ADDR1");
        if (oa1 == null || oa1.toString().trim().isEmpty()) {
            commandMap.put("ORDER_ADDR1", memberInfo.get("MEMBER_ADDR1"));
        }
        if (commandMap.get("ORDER_ADDR1") == null || commandMap.get("ORDER_ADDR1").toString().trim().isEmpty()) {
            commandMap.put("ORDER_ADDR1", "-");
        }
        Object oa2 = commandMap.get("ORDER_ADDR2");
        if (oa2 == null || oa2.toString().trim().isEmpty()) {
            commandMap.put("ORDER_ADDR2", memberInfo.get("MEMBER_ADDR2"));
        }
        if (commandMap.get("ORDER_ADDR2") == null || commandMap.get("ORDER_ADDR2").toString().trim().isEmpty()) {
            commandMap.put("ORDER_ADDR2", "-");
        }
        // 결제자명 비어있으면 주문자명으로 대체
        Object payName = commandMap.get("ORDER_PAY_NAME");
        if (payName == null || payName.toString().trim().isEmpty()) {
            commandMap.put("ORDER_PAY_NAME", commandMap.get("ORDER_NAME"));
        }
        if (commandMap.get("ORDER_PAY_NAME") == null || commandMap.get("ORDER_PAY_NAME").toString().trim().isEmpty()) {
            commandMap.put("ORDER_PAY_NAME", "-");
        }
        // 숫자형 컬럼 기본값 보정: 공백/NULL이면 0으로 설정
        Object opo = commandMap.get("ORDER_PAY_OPTION");
        if (opo == null || opo.toString().trim().isEmpty()) {
            commandMap.put("ORDER_PAY_OPTION", 0);
        }
        Object tot = commandMap.get("ORDER_TOTAL_ORDER_PRICE");
        if (tot == null || tot.toString().trim().isEmpty()) {
            commandMap.put("ORDER_TOTAL_ORDER_PRICE", 0);
        }
        Object tpp = commandMap.get("ORDER_TOTAL_PAY_PRICE");
        if (tpp == null || tpp.toString().trim().isEmpty()) {
            commandMap.put("ORDER_TOTAL_PAY_PRICE", 0);
        }
        Object uPoint = commandMap.get("ORDER_USE_POINT");
        if (uPoint == null || uPoint.toString().trim().isEmpty()) {
            commandMap.put("ORDER_USE_POINT", 0);
        }
        Object sPoint = commandMap.get("ORDER_SAVE_POINT");
        if (sPoint == null || sPoint.toString().trim().isEmpty()) {
            commandMap.put("ORDER_SAVE_POINT", 0);
        }
        Object fee = commandMap.get("ORDER_FEE");
        if (fee == null || fee.toString().trim().isEmpty()) {
            commandMap.put("ORDER_FEE", 0);
        }
        orderService.insertOrder(commandMap, request);
		orderService.updateMember(commandMap, request);
		Map<String,Object> map = orderService.selectOrder(commandMap, request);
		mv.addObject("map", map); 
		return mv;
	}
	
	//주문자 정보변경
	@RequestMapping(value="/order/orderModify.do")
	    public ModelAndView orderModify(CommandMap commandMap, HttpServletRequest request) throws Exception {
        System.out.println(commandMap.get("ORDER_NO"));
        
        ModelAndView mv = new ModelAndView("redirect:/my_detail.do");
        mv.addObject("order_no", commandMap.get("ORDER_NO"));
        //수량수정
        orderService.orderModify(commandMap, request);
        return mv;
    }
}
