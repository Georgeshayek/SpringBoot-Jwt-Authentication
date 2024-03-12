package com.example.tutorialauth.user;

import org.apache.tomcat.util.buf.UDecoder;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByEmail(String email);

}
