package kr.co.JWT.service;

import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import kr.co.JWT.entity.User;
import kr.co.JWT.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

		public CustomUserDetailsService(UserRepository userRepository) {
			this.userRepository = userRepository;
		}

		@Override
	    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	        User user = userRepository.findByUsername(username)
	                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

	        // 사용자의 역할을 가져옵니다.
	        String role = user.getRole();

	        // 권한을 설정합니다.
	        GrantedAuthority authority = new SimpleGrantedAuthority(role);

	        // UserDetails 객체를 반환합니다.
	        return org.springframework.security.core.userdetails.User
	                .withUsername(user.getUsername())
	                .password(user.getPassword())
	                .authorities(Collections.singletonList(authority)) // 단일 권한을 리스트로 설정합니다.
	                .accountExpired(false)
	                .accountLocked(false)
	                .credentialsExpired(false)
	                .disabled(false)
	                .build();
	    }
}
