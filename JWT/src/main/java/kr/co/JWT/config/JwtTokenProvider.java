package kr.co.JWT.config;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtTokenProvider {

	//private static final Logger logger = Logger.getLogger(JwtTokenProvider.class.getName());
	
    @Value("${jwt.secret}") // application.properties 파일에서 JWT 비밀 키를 주입받습니다.
    private String secretKey;
    
    @Value("${jwt.expiration}") // application.properties 파일에서 JWT 유효 기간을 주입받습니다.
    private long validityInMilliseconds;

    private byte[] secretKeyBytes;
 
    @PostConstruct
    protected void init() {
        this.secretKeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
    }
    
    //엔드포인트에서 토큰 연장을 위한 메소드
    public long getValidityInMilliseconds() {
        return validityInMilliseconds;
    }
    public byte[] getSecretKeyBytes() {
        return secretKeyBytes;
    }
    public String getRole(String token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(this.secretKeyBytes)
                .parseClaimsJws(token)
                .getBody();
            return claims.get("role", String.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract role from JWT token", e);
        }
    }

    public void setJwtCookies(HttpServletResponse response, String token) {
        // JWT 토큰 쿠키 설정
        Cookie tokenCookie = new Cookie("token", token);
        tokenCookie.setHttpOnly(true); // 클라이언트 측 스크립트에서 접근 불가
        tokenCookie.setSecure(true); // HTTPS에서만 전송
        tokenCookie.setPath("/"); // 전체 도메인에 대해 유효
        //tokenCookie.setMaxAge((int) (validityInMilliseconds / 1000)); // 쿠키 유효 시간 (초)
        tokenCookie.setAttribute("SameSite", "Strict"); // CSRF 공격 방지를 위한 SameSite 속성 설정
        response.addCookie(tokenCookie);
    }

    public String createToken(String username,String role) {
        Claims claims = Jwts.claims().setSubject(username); // JWT의 주체로 사용자 이름을 설정합니다.
        claims.put("role", role); // 역할을 클레임에 추가합니다.
        Date now = new Date(); // 현재 시간
        Date validity = new Date(now.getTime() + validityInMilliseconds); // 토큰 만료 시간
        String token = Jwts.builder()
        		.setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setClaims(claims) // 클레임을 설정합니다.
                .setIssuedAt(now) // 토큰 발급 시간을 설정합니다.
                .setExpiration(validity) // 토큰 만료 시간을 설정합니다.
                .signWith(SignatureAlgorithm.HS256, this.secretKeyBytes) // 비밀 키를 사용하여 서명합니다.
                .compact(); // JWT 토큰을 생성합니다.
        Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.INFO, "Generated token: {0}", token);
        return token;
    }

    public String getUsername(String token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(this.secretKeyBytes)
                .parseClaimsJws(token)
                .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            // 예외 처리 로직 (예: JWT가 잘못된 경우)
            throw new RuntimeException("Invalid JWT token", e);
        }
    }
    /**
     * JWT 토큰에서 인증 정보를 추출합니다.
     * @param token - JWT 토큰
     * @return - 인증 정보
     */
    public Authentication getAuthentication(String token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(this.secretKeyBytes)
                .parseClaimsJws(token)
                .getBody();

            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(role));

            return new UsernamePasswordAuthenticationToken(username, "", authorities);
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            throw new RuntimeException("JWT 토큰이 만료되었습니다.", e);
        } catch (io.jsonwebtoken.SignatureException e) {
            throw new RuntimeException("JWT 서명이 잘못되었습니다.", e);
        } catch (Exception e) {
            throw new RuntimeException("유효하지 않은 JWT 토큰입니다.", e);
        }
    }
    

    /**
     * 요청에서 JWT 토큰을 추출합니다.
     * @param req - HTTP 요청
     * @return - 추출된 JWT 토큰
     */
    public String resolveToken(HttpServletRequest req) {
        // HTTP 요청에서 쿠키를 검색하여 JWT 토큰을 추출합니다.
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("token".equals(cookie.getName())) {
                    return cookie.getValue(); // JWT 토큰 반환
                }
            }
        }
        return null; // 토큰이 없는 경우 null을 반환합니다.
    }


    
    /**
     * JWT 토큰의 유효성을 검사합니다.
     * @param token - JWT 토큰
     * @return - 토큰이 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(this.secretKeyBytes).parseClaimsJws(token); // JWT를 파싱하고 유효성을 검사합니다.
            return true; // 유효한 경우 true를 반환합니다.
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.SEVERE, "Expired JWT token: {0}", e.getMessage());
        } catch (io.jsonwebtoken.UnsupportedJwtException e) {
            Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.SEVERE, "Unsupported JWT token: {0}", e.getMessage());
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.SEVERE, "Malformed JWT token: {0}", e.getMessage());
        } catch (io.jsonwebtoken.SignatureException e) {
            Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.SEVERE, "Invalid JWT signature: {0}", e.getMessage());
        } catch (Exception e) {	
            Logger.getLogger(JwtTokenProvider.class.getName()).log(Level.SEVERE, "Invalid JWT token: {0}", e.getMessage());
        }
        return false; // 유효하지 않은 경우 false를 반환합니다.
    }
}