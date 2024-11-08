package com.wywin.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration // 설정 클래스로 선언
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true) // 스프링 시큐리티 필터가 스프링 필터체인에 등록
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // filterChain : 특정 HTTP 요청에 대해 웹 기반 보안 구성. 인증/인가 및 로그인,로그아웃 설정
        http
                .formLogin(form -> {
                    form
                            .loginPage("/members/login") // 로그인 페이지 설정
                            .defaultSuccessUrl("/") // 성공시 이동 페이지
                            .usernameParameter("email")
                            .failureUrl("/members/login/error"); // 실패시 이동 페이지
                })
                .logout(logout -> {
                    logout.logoutRequestMatcher(new AntPathRequestMatcher("/members/logout"))
                            .logoutSuccessUrl("/");
                });

        http.authorizeHttpRequests(authorizeHttpRequests -> {
            authorizeHttpRequests
                    .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()
                    .requestMatchers("/", "/members/**", "/item/**", "/images/**").permitAll()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated();
            // requestMatchers : 특정 요청과 일치하는지 url에 대한 엑세스 설정
        });

        http.exceptionHandling(exceptionHandling -> {
            exceptionHandling
                    .authenticationEntryPoint(new CustomAuthenticationEntryPoint());
        });
        return http.build();
    }




    @Bean // 비밀번호 암호화를 위한 빈 등록
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
