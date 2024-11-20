package com.seulgi.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Key;
import java.util.Base64;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@SpringBootTest
class SecurityApplicationTests {

	@Test
	void secretKey() {
		Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // 256-bit key
		String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
		System.out.println(base64Key);
	}

}
