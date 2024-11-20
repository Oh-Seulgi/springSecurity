package com.seulgi.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/*
* JpaRepository를 상속받아 Spring Data JPA의 기본 CRUD 메서드를 사용할 수 있도록 설정된 리포지토리 인터페이스
* Spring Data JPA는 이 인터페이스에 구현체를 자동으로 생성하여 제공
*
* JpaRepository<User, Integer> : User 엔티티를 다루며, User 엔티티의 기본 키(Primary Key) 타입
* @Id로 지정된 id 필드의 타입이 Integer
* */
public interface UserRepository extends JpaRepository<User, Integer> {

    // Optional<User>: 결과가 있을 수도 있고 없을 수도 있는 상황을 처리.
    // 예를 들어, 이메일로 사용자를 찾지 못하면 Optional.empty()를 반환
    Optional<User> findByEmail(String email);

}
