/*
 * Copyright (C) 2024 Sean O'Connor
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package com.aniable.anibl.config;

import com.aniable.anibl.jwt.JwtFilter;
import com.aniable.anibl.oauth2.CustomOAuth2UserService;
import com.aniable.anibl.oauth2.OAuth2SuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

	final OAuth2SuccessHandler oAuth2SuccessHandler;

	final CustomOAuth2UserService customOAuth2UserService;

	final JwtFilter jwtFilter;

	public SecurityConfig(OAuth2SuccessHandler oAuth2SuccessHandler,
						  CustomOAuth2UserService customOAuth2UserService,
						  JwtFilter jwtFilter) {
		this.oAuth2SuccessHandler = oAuth2SuccessHandler;
		this.customOAuth2UserService = customOAuth2UserService;
		this.jwtFilter = jwtFilter;
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.cors(cors -> cors.configurationSource(corsConfigurationSource()))
					.csrf(CsrfConfigurer::disable)
					.formLogin(FormLoginConfigurer::disable)
					.httpBasic(HttpBasicConfigurer::disable)
					.oauth2Login(oauth -> oauth.successHandler(oAuth2SuccessHandler)
											   .userInfoEndpoint(
												   userInfoEndpointConfig -> userInfoEndpointConfig.userService(
													   customOAuth2UserService)))
					.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
					.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
					.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		return httpSecurity.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		var configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(
			List.of("http://localhost:5173")); // TODO 2024-10-18, 17:32 Change to dev front-end or prod hostname
		configuration.setAllowedMethods(Arrays.stream(HttpMethod.values()).map(HttpMethod::name).toList());
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(List.of("Authorization"));
		var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
