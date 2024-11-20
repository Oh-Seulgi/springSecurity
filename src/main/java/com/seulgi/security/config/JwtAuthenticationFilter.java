package com.seulgi.security.config;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component  // Spring 컨텍스트에서 관리되는 Bean으로 등록됨
@RequiredArgsConstructor    // final 필드나 @NonNull 필드에 대해 자동으로 생성자를 생성
public class JwtAuthenticationFilter extends OncePerRequestFilter { // OncePerRequestFilter = 요청당 한 번만 실행되는 필터를 구현

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    // JWT 토큰을 검증하고, 토큰이 유효하면 SecurityContext에 인증 정보를 저장
    // 유효하지 않은 토큰이거나 토큰이 없으면 SecurityContext에 인증 정보를 저장하지 않음
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,    // HttpServletRequest : 클라이언트로부터의 HTTP 요청 정보
            @NonNull HttpServletResponse response,  // HttpServletResponse : 서버에서 클라이언트로 보낼 응답 정보
            @NonNull FilterChain filterChain    // filterChain : 필터 체인을 나타내며, 필터 체인의 다음 필터를 호출하거나 요청 처리를 계속 진행할 때 사용
    ) throws ServletException, IOException {

        final String authHeader  = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // JWT 토큰이 일반적으로 Authorization 헤더의 Bearer <token> 형식으로 포함됨
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {  // 토큰이 없을 경우
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);  // 'Bearer '를 제외한 순수 JWT 값을 추출 (7글자)
        userEmail = jwtService.extractUserName(jwt);    // JWT 검증, 이메일이 반환되지 않으면 인증 실패

        // 인증 정보 확인
        // SecurityContextHolder.getContext().getAuthentication() : 현재 요청에 이미 인증 정보가 있다면 추가 검증을 생략
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail); // 사용자 정보를 DB에서 가져옴

            // JWT가 유효하면 SecurityContext에 인증 정보 저장
            if(jwtService.isTokenValid(jwt, userDetails)) {
                // UsernamePasswordAuthenticationToken : Spring Security에서 제공하는 인증 객체
                // 사용자 정보(userDetails)와 권한(userDetails.getAuthorities())을 담음
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities() // 자격 증명은 저장하지 않음
                );

                // 요청의 세부 정보를 인증 객체에 설정
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Spring Security의 컨텍스트에 인증 정보를 저장하여 이후 보안 컨텍스트에서 인증 상태를 참조할 수 있게 함
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 필터 체인의 다음 필터를 호출하여 요청 처리를 계속 진행
        filterChain.doFilter(request, response);
    }
}
