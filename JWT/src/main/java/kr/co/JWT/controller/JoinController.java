package kr.co.JWT.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class JoinController {
	
	@GetMapping("/register.do")
	public String register() {
		return "register";
	}
	@GetMapping("/login.do")
	public String login() {
		return "login";
	}
	@GetMapping("/home.do")
    public String home() {
		return "home";
    }
	@GetMapping("/distribution/distribution.do")
	public String distribution() {
		return "distribution_partner";
	}
	@GetMapping("/production/production.do")
	public String productioner() {
		return "production_partner";
	}
	@GetMapping("/sales/sales.do")
	public String sales() {
		return "sales_partner";
	}
}
