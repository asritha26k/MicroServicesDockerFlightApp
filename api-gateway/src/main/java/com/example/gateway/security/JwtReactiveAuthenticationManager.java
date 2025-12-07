package com.example.gateway.security;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final JwtUtil jwtUtil;

	public JwtReactiveAuthenticationManager(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		String token = (authentication.getCredentials() == null) ? null : authentication.getCredentials().toString();
		if (token == null || !jwtUtil.validate(token)) {
			return Mono.empty();
		}

		Claims claims = jwtUtil.extractAllClaims(token);
		String username = claims.getSubject();

		Object rolesObj = claims.get("roles");
		List<String> rolesList;
		if (rolesObj == null) {
			rolesList = List.of();
		} else {
			String s = rolesObj.toString().replace("[", "").replace("]", "").replace(" ", "");
			rolesList = Arrays.stream(s.split(",")).filter(r -> !r.isEmpty()).collect(Collectors.toList());
		}

		var authorities = rolesList.stream().map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
				.map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
		return Mono.just(auth);
	}
}
