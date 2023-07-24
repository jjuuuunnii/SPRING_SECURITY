package com.cos.jwt.config;

import com.cos.jwt.JwtAuthenticationFilter;

import com.cos.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;


import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;




@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다.
                .and()
                .addFilter(corsFilter)  // @CrossOrigin(인증이 필요없을때), 시큐리티 필터에 등록 인증(0)
                .formLogin().disable()  // 폼로그인 안하겠다
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))//AuthenticationMagager를 던진다.
                // basic은 인증에 필요한 id, password를 들고 직접 요청을 하는것, 이때 Bearer 방식을 쓰면 토큰을 들고 직접 요청을 하게됨
                //토큰은 유효시간이 있음, 물론 토큰을 뺏기면 위험하긴한데, BASIC보다는 안정적이다.
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('USER') or hasRole('MANAGER') or hasRole('ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('USER') or hasRole('MANAGER')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ADMIN')")
                .anyRequest().permitAll();

        return http.build();
    }
}
