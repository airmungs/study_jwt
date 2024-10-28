package kr.co.JWT.config;
import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 로그인 요청은 필터링하지 않도록 설정
        if ("/login".equals(request.getRequestURI()) || "/login.do".equals(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        // 요청에서 JWT 토큰을 추출합니다.
        String token = this.jwtTokenProvider.resolveToken(request);

        if (token != null) {
            // 토큰이 유효한지 검증합니다.
            if (this.jwtTokenProvider.validateToken(token)) {
                // 유효한 토큰일 경우, 인증 정보를 얻어옵니다.
                Authentication auth = this.jwtTokenProvider.getAuthentication(token);
                // 인증 정보를 SecurityContext에 설정합니다.
                SecurityContextHolder.getContext().setAuthentication(auth);
            } else {
                // 토큰이 유효하지 않은 경우
                SecurityContextHolder.clearContext(); // SecurityContext를 클리어합니다.
            }
        } else {
            // 요청에서 토큰이 없는 경우
            SecurityContextHolder.clearContext(); // SecurityContext를 클리어합니다.
        }

        // 요청을 계속 필터 체인에 전달
        filterChain.doFilter(request, response);
    }
}