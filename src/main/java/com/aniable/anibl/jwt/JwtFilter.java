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

package com.aniable.anibl.jwt;

import com.aniable.anibl.user.User;
import com.aniable.anibl.user.UserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

	final JwtService jwtService;

	final UserRepository userRepository;

	public JwtFilter(JwtService jwtService, UserRepository userRepository) {
		this.jwtService = jwtService;
		this.userRepository = userRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
									@SuppressWarnings("NullableProblems") HttpServletResponse response,
									@SuppressWarnings("NullableProblems") FilterChain filterChain) throws ServletException, IOException {
		var HEADER = "Authorization";
		var SCHEME = "Bearer ";

		var header = request.getHeader(HEADER);
		if (header == null || !header.startsWith(SCHEME)) {
			filterChain.doFilter(request, response);
			return;
		}

		var token = header.substring(SCHEME.length());
		if (token.isBlank()) {
			filterChain.doFilter(request, response);
			return;
		}

		var subject = jwtService.extractSubject(token);
		if (subject == null || subject.isBlank()) throw new JwtException("Subject claim is not present");

		UUID userId;
		try {
			userId = UUID.fromString(subject);
		} catch (Exception e) {
			throw new JwtException("Could not parse subject into user ID");
		}

		var user = userRepository.findById(userId);
		if (user.isEmpty()) throw new JwtException("Could not find matching user for subject");

		authenticate(user.get(), request);
		filterChain.doFilter(request, response);
	}

	private void authenticate(User user, HttpServletRequest request) {
		var authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authenticationToken);
	}
}
