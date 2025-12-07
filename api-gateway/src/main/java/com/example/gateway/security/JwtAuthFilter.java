package com.example.gateway.security;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements WebFilter {

	private final JwtUtil jwtUtil;

	public JwtAuthFilter(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String path = exchange.getRequest().getURI().getPath();
		if (path.startsWith("/auth-service/api/auth/")) {
			return chain.filter(exchange);
		}
		String token = null;

		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (authHeader != null && authHeader.startsWith("Bearer "))
			token = authHeader.substring(7);

		if (token == null && exchange.getRequest().getCookies().getFirst("bezkoder") != null)
			token = exchange.getRequest().getCookies().getFirst("bezkoder").getValue();

		if (token != null && jwtUtil.validate(token)) {

			String username = jwtUtil.extractUsername(token);
			List<String> roles = jwtUtil.extractRoles(token);

			var authorities = roles.stream().map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
					.map(SimpleGrantedAuthority::new).collect(Collectors.toList());

			Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

			return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
		}

		return chain.filter(exchange);
	}
}
