package com.example.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class GatewaySecurityConfig {

	private final JwtAuthFilter jwtFilter;

	public GatewaySecurityConfig(JwtAuthFilter jwtFilter) {
		this.jwtFilter = jwtFilter;
	}

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

		return http.csrf(ServerHttpSecurity.CsrfSpec::disable).authorizeExchange(ex -> ex

				.pathMatchers("/auth-service/api/auth/**").permitAll()

				.pathMatchers("/flight-service/flight/register").hasRole("ADMIN")
				.pathMatchers("/flight-service/flight/delete/**").hasRole("ADMIN")

				.pathMatchers("/flight-service/flight/getFlightById/**").hasAnyRole("ADMIN", "USER")

				.pathMatchers("/flight-service/flight/**").permitAll()

				.pathMatchers("/passenger-service/passenger/register").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/passenger-service/passenger/getByPassengerId/**").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/passenger-service/passenger/getPassengerIdByEmail/**").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/passenger-service/passenger/delete/**").hasAnyRole("ADMIN", "USER")

				.pathMatchers("/ticket-service/ticket/book").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/ticket-service/ticket/getByPnr/**").hasAnyRole("ADMIN", "USER")
				.pathMatchers("/ticket-service/ticket/getTicketsByEmail/**").hasAnyRole("ADMIN", "USER")

				.anyExchange().authenticated())

				.addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)

				.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
				.formLogin(ServerHttpSecurity.FormLoginSpec::disable).build();
	}

}
