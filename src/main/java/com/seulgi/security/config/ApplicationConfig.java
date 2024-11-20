package com.seulgi.security.config;

import com.seulgi.security.user.UserRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.RequiredArgsConstructor;

/*
* 사용자 인증과 관련된 설정을 구성하는 클래스
* */
@Configuration  // 이 클래스는 Spring 컨테이너에 설정 클래스로 등록. 이 클래스에서 정의된 모든 @Bean은 Spring 컨텍스트에서 관리됨
@RequiredArgsConstructor    // Lombok 어노테이션으로, final 필드인 UserRepository에 대한 생성자를 자동으로 생성
public class ApplicationConfig {

    private final UserRepository repository;

    /*
    * 사용자 인증 시 사용자를 조회
    * */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }

    /*
    * 사용자의 인증을 처리
    * */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // DaoAuthenticationProvider : 데이터베이스에서 사용자 정보를 조회하고, 제공된 비밀번호를 암호화된 비밀번호와 비교
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        
        return authProvider;
    }

    /*
    * AuthenticationManager : Spring Security의 핵심 인터페이스로, 인증 요청을 처리
    * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // AuthenticationConfiguration : Spring Security 5.0부터 추가된 클래스로, 인증 관련 설정을 제공
        return config.getAuthenticationManager();
    }

    /*
    * 사용자 비밀번호를 암호화하고, 인증 시 암호화된 비밀번호를 비교
    * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
