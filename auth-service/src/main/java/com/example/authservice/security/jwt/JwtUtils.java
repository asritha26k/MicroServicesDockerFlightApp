package com.example.authservice.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.example.authservice.security.services.UserDetailsImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {

	@Value("${bezkoder.app.jwtSecret}")
	private String jwtSecret;

	@Value("${bezkoder.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	@Value("${bezkoder.app.jwtCookieName:bezkoder}")
	private String jwtCookieName;

	private Key key() {
		try {
			byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
			return Keys.hmacShaKeyFor(keyBytes);
		} catch (IllegalArgumentException ex) {
			// fallback to plain bytes if not base64
			return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
		}
	}

	public String generateTokenFromUsername(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(key()).compact();
	}

	public String generateTokenWithRoles(String username, List<String> roles) {
		return Jwts.builder().setSubject(username).claim("roles", roles).setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(key()).compact();
	}

	public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
		List<String> roles = userPrincipal.getAuthorities().stream().map(a -> a.getAuthority()).toList();
		String jwt = generateTokenWithRoles(userPrincipal.getUsername(), roles);
		long maxAgeSec = jwtExpirationMs / 1000L;
		return ResponseCookie.from(jwtCookieName, jwt).path("/").maxAge(maxAgeSec).httpOnly(true).build();
	}

	public ResponseCookie getCleanJwtCookie() {
		return ResponseCookie.from(jwtCookieName, "").path("/").maxAge(0).httpOnly(true).build();
	}

	public String getJwtFromCookies(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookieName);
		if (cookie != null)
			return cookie.getValue();
		String headerAuth = request.getHeader("Authorization");
		if (headerAuth != null && headerAuth.startsWith("Bearer "))
			return headerAuth.substring(7);
		return null;
	}

	public String getUserNameFromJwtToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();
	}

	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody();
	}

	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
			return true;
		} catch (MalformedJwtException e) {
			// log if needed
		} catch (ExpiredJwtException e) {
		} catch (UnsupportedJwtException e) {
		} catch (IllegalArgumentException e) {
		}
		return false;
	}
}
