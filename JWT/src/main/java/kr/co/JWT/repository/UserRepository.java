package kr.co.JWT.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import kr.co.JWT.entity.User;



public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByUsername(String username);
}

