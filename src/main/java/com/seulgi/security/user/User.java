package com.seulgi.security.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data   // Lombok 어노테이션으로, getter/setter, toString, equals, hashCode 메서드를 자동으로 생성
@Builder    // Lombok 어노테이션으로, Builder 패턴을 사용하여 객체를 생성할 수 있도록 지원.
@NoArgsConstructor  // Lombok 어노테이션으로, 매개변수가 없는 기본 생성자를 자동으로 생성.
@AllArgsConstructor // Lombok 어노테이션으로, 모든 필드를 매개변수로 받는 생성자를 자동으로 생성.
@Entity // JPA 어노테이션으로, 이 클래스가 데이터베이스 테이블과 매핑됨을 나타냄.
@Table(name = "_user")  // JPA 어노테이션으로, 이 클래스가 _user라는 이름의 테이블과 매핑됨을 지정.
public class User implements UserDetails {

    @Id // JPA 어노테이션으로, 이 필드가 데이터베이스의 Primary Key 역할을 함을 나타냄.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // JPA 어노테이션으로, 기본 키 값이 자동으로 생성됨을 나타냄.

    private Integer id;

    private String name;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)    // JPA 어노테이션으로, role 필드가 Role 열거형(enum)으로 정의되며, 데이터베이스에는 문자열 형태로 저장됨.
    private Role role;  // 예: Role.ADMIN → "ADMIN"으로 저장.

    // 사용자에게 부여된 권한을 반환하는 메서드 (예: Role.ADMIN → 권한 "ADMIN")
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    // Spring Security에서 사용자를 식별하는 데 사용하는 사용자명을 반환.
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    // 계정이 만료되지 않았는지 여부를 반환하는 메서드
    @Override
    public boolean isAccountNonExpired() {
        return true;    // 항상 true를 반환하여 만료되지 않은 상태로 설정
    }

    // 계정이 잠기지 않았는지 여부를 반환하는 메서드
    @Override
    public boolean isAccountNonLocked() {
        return true;    // 항상 true를 반환하여 잠기지 않은 상태로 설정
    }

    // 자격 증명(비밀번호)이 만료되지 않았는지 여부를 반환하는 메서드
    @Override
    public boolean isCredentialsNonExpired() {
        return true;    // 항상 true를 반환하여 자격 증명이 만료되지 않은 상태로 설정
    }

    // 사용자가 활성화되어 있는지 여부를 반환하는 메서드
    @Override
    public boolean isEnabled() {
        return true;    // 항상 true를 반환하여 사용자가 활성화된 상태로 설정
    }

}
