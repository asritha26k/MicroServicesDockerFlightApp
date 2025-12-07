package com.example.gateway.security;

import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	@Value("${jwt.secret}")
	private String jwtSecret; // Base64 encoded, SAME as auth-service

	private Key getSigningKey() {
		byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	public Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
	}

	public boolean validate(String token) {
		try {
			extractAllClaims(token);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	// ✅ Extract username (subject)
	public String extractUsername(String token) {
		return extractAllClaims(token).getSubject();
	}

	// ✅ Extract roles list from token
	public List<String> extractRoles(String token) {
		Claims claims = extractAllClaims(token);

		Object rolesObj = claims.get("roles");
		if (rolesObj == null)
			return List.of();

		// Example: "[ROLE_USER, ROLE_ADMIN]"
		String s = rolesObj.toString().replace("[", "").replace("]", "").replace(" ", "");

		if (s.isEmpty())
			return List.of();

		return Arrays.stream(s.split(",")).collect(Collectors.toList());
	}
}
