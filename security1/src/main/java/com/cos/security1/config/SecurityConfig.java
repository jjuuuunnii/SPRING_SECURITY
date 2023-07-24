package com.cos.security1.config;



//구글 로그인이 완료된 뒤의 후처리가 필요.
// 1. 코드를 받고(인증완료),
// 2. 엑세스토큰을 받음(권한이 생김)
// 3. 사용자 프로필정보를 가져와서
// 4. 그 정보를 토대로 회원가입을 자동으로 진행시키도 함
// 4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> 집주소, 등급,, 등등 더필요해짐
//



import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) //secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
                http.authorizeRequests()
                        .antMatchers("/user/**").authenticated()
                        .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                        .antMatchers("/manager/**").access("hasRole('ROLE_MANAGER')")
                        .anyRequest().permitAll()
                        .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                        .and()
                        .oauth2Login()
                        .loginPage("/loginForm")
                        .userInfoEndpoint()
                        .userService(principalOauth2UserService);
                //구글 로그인 로그인이 완료된 뒤. 1. 코드 x, 엑세스토큰 + 사용자 정보를 바로 받음!!!

        return http.build();
    }
}





