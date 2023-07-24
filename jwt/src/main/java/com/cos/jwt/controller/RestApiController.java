package com.cos.jwt.controller;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.GeneratorType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


/*@CrossOrigin 이렇게 어노테이션으로 걸수도 있는데 이렇게 걸어버리면 인증이 필요한 경우를 해결 할수 없음*/
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public User join(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        System.out.println("fuck!");
        return user;
    }

    @GetMapping("/api/v1/user")
    public String user(){
        return "user";
    }

    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
