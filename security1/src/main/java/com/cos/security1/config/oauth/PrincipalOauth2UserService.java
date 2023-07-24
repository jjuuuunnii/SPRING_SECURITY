
package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;
    //구글로 부터 받은 userRequest데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest :" + userRequest);
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken());
        System.out.println("userRequest.getClientRegistration().getClientId() = " + userRequest.getClientRegistration().getClientId());
        System.out.println("userRequest.getClientRegistration().getClientName() = " + userRequest.getClientRegistration().getClientName()); //이걸로 어떤  OAuoth로 로그인했는지 확인가능

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("getAttributes = " + oAuth2User.getAttributes());


        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String username = provider + "_" + providerId;
        String password = passwordEncoder.encode("겟인데어");
        String role = "ROLE_USER";


        User userEntity = userRepository.findByUsername(username);
        System.out.println(userEntity);
        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}

//구글 로그인 버튼 클링 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAUTH-CLIENT라이브러리) -> ACCESSTOKEN요청
//userRequest 정보 -> 회원프로필을 받아야하는데 이때, loadUser함수 -> 회원 프로필

