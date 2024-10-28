package kr.co.JWT.service;


import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import kr.co.JWT.entity.User;
import kr.co.JWT.repository.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
	    this.userRepository = userRepository;
	    this.passwordEncoder = passwordEncoder;
	}

    public void registerUser(String username, String password, String role) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        userRepository.save(user);
    }
    
    public boolean authenticateUser(String username, String password) {
        // 사용자 정보를 Optional로 가져옵니다
        User user = userRepository.findByUsername(username).orElse(null);

        // 사용자 정보가 존재하고 비밀번호가 일치하는지 확인합니다
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            return true;
        }

        return false;
    }
    
    public String getRole(String username) {
        // User 객체를 Optional로 조회	
        Optional<User> userOpt = userRepository.findByUsername(username);      
        // User 객체가 존재하면 role 필드를 반환
        return userOpt.map(User::getRole).orElse(null); // 사용자 없음에는 null 반환
    }
}
