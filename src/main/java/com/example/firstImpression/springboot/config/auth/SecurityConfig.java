package com.example.firstImpression.springboot.config.auth;

import com.example.firstImpression.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity //Spring Security 설정 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers().frameOptions().disable() //h2-console화면 사용 위해 해당 옵션 disable
                .and()
                    .authorizeRequests() //URL별 권한 관리를 설정하는 옵션의 시작점, 이게 선언돼야 antMatchers 옵션 사용 가능
                    .antMatchers("/", "/css/**", "/images/**",
                                    "/js/**", "/h2-console/**").permitAll() //권한 관리 대상 지정하는 옵션. URL, HTTP 메소드별 관리 가능
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    .anyRequest().authenticated() //나머지 URL, 인증된 사용자들에게만 허용
                .and()
                    .logout()//로그아웃 기능에 대한 여러 설정의 진입점
                        .logoutSuccessUrl("/") //로그아웃 성공시 /주소로 이동
                .and()
                    .oauth2Login() //OAuth2 로그인 기능에 대한 여러 설정의 진입점
                        .userInfoEndpoint() // OAuth2 로그인 성공 이후 사용자 정보 가져올 때의 설정들을 담당
                            .userService(customOAuth2UserService);
                            //소셜 로그인 성공시 후속 조치 진행할 UserService 인터페이스의 구현체 등록
                            //리소스 서버(소셜 서비스들)에서 사용자 가져온 상태에서 추가로 진행하고픈 기능 명시 가능
    }
}
