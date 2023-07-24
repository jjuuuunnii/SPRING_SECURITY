package com.cos.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.w3c.dom.ls.LSOutput;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;


//스프링 시큐리티에서의 UsernamePasswordAuthenticationFilter 가 있음
// /login요청에서 username, password (post) 요청을 하면
// UsernamePasswordAuthenticationFilter  호출 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    //1번. username, password를 받아서 정상인지 로그인 시도를 해봄

    //2번. 그럼 PrincipalDetailsService 가 호출, loadUserByUsername()이 실행

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중,,,");
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            System.out.println("1================");
            //principaldetails service의 loaduserbyUsername이 실행되는데 그후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다는 뜻
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            System.out.println("==============인증완료===============");
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            //authentication객체가 session영역에 저장됨, 그방법이 return => 로그인이 되었다는 뜻
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    //attmptAuthentication이 실행되고 인증이 정상적으로 완료가 되면 successfulAuthentication함수가 실행됨
    //여기서 이제 jwt 토큰을 만들어서 request요청한 사용자에게 JWT 토큰은 response해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
