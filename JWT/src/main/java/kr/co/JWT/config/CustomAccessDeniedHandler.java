package kr.co.JWT.config;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
	@Override
	 public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
	            throws IOException, ServletException {
	        
	        Authentication auth = (Authentication) request.getUserPrincipal();

	        if (auth != null) {
	            // 로그인이 되어 있지만 권한이 없을 때 처리
	            response.sendRedirect("/login.do?error=accessDenied");
	        } else {
	            // 로그인이 되어 있지 않을 때 처리
	            response.sendRedirect("/login.do");
	        }
	    }
}
