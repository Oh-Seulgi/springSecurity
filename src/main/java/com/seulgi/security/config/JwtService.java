package com.seulgi.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${jwt.sec-key}")
    private String SECRET_KEY;

    /**
     * JWT에서 사용자 이름을 추출
     */
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /*
    * JWT의 모든 **Claims(정보)**를 추출하고, 지정된 함수를 통해 필요한 값을 반환
    */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /*
    * 사용자 정보를 기반으로 JWT를 생성
    * 기본적으로 추가적인 클레임이 없는 토큰을 생성
    */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /*
    * 사용자 정보 및 추가 클레임을 포함하여 JWT 생성
    * */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims) // 추가 클레임을 설정
                .subject(userDetails.getUsername())  // 토큰의 subject(대상) 설정, 일반적으로 사용자 이름
                .issuedAt(new Date(System.currentTimeMillis()))  // 토큰 생성 시간 설정
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // 토큰 만료 시간 설정. 현재 시간 기준으로 24분 유효
                .signWith(getSignInKey())    // 지정된 키와 알고리즘으로 JWT 서명
                .compact(); // 최종적으로 JWT 문자열 생성
    }

    /*
    * WT가 유효한지 검증
    * */
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        // JWT에서 추출한 사용자 이름이 userDetails의 사용자 이름과 일치하는지 확인
        // JWT가 만료되었는지 확인
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /*
    * JWT의 만료 시간을 확인
    * */
    private boolean isTokenExpired(String token) {
        // 토큰에서 만료 시간 클레임을 추출하여 현재 시간과 비교하여 만료 여부 반환
        return extractExpiration(token).before(new Date());
    }

    /*
    * 토큰에서 만료 시간 클레임을 추출
    * */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /*
    * JWT의 모든 클레임을 추출
    * 서명이 유효하지 않거나 형식이 올바르지 않은 경우 예외가 발생
    * */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)  // 서명 검증을 포함하여 JWT를 파싱
                .getPayload();
    }

    /*
    * 비밀키를 서명용 키 객체로 변환
    * */
    private SecretKey getSignInKey() {
        // Base64로 인코딩된 SECRET_KEY를 디코딩하여 HMAC 알고리즘용 키로 변환
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
